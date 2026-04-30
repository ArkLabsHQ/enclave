package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Type definitions + helpers
// =============================================================================

// envMu protects os.Setenv calls from concurrent access.
var envMu sync.Mutex

// DynamicSecret is the JSON envelope stored in S3 for each dynamic secret.
type DynamicSecret struct {
	Name      string `json:"name"`
	EnvVar    string `json:"env_var,omitempty"`
	Value     string `json:"value"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// DynamicSecretInfo is the metadata-only view returned by list (no value).
type DynamicSecretInfo struct {
	Name      string `json:"name"`
	EnvVar    string `json:"env_var,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

const secretsPrefix = "secrets/"

// validSecretName matches alphanumeric, hyphens, underscores, dots. No slashes, no ..
var validSecretName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// maxSecretValueSize is the maximum size of a dynamic secret value.
// Env vars have OS-level limits (~128KB on Linux), so cap well below that.
const maxSecretValueSize = 64 * 1024 // 64KB

// validateSecretName rejects path traversal, control chars, and invalid names.
func validateSecretName(name string) error {
	if name == "" {
		return fmt.Errorf("secret name is required")
	}
	if strings.Contains(name, "..") || strings.Contains(name, "/") {
		return fmt.Errorf("secret name must not contain '..' or '/'")
	}
	if !validSecretName.MatchString(name) {
		return fmt.Errorf("secret name must be alphanumeric with hyphens, underscores, or dots")
	}
	if len(name) > 256 {
		return fmt.Errorf("secret name must be 256 characters or fewer")
	}
	return nil
}

// safeSetenv wraps os.Setenv with a mutex to prevent concurrent env mutations.
func safeSetenv(key, value string) error {
	envMu.Lock()
	defer envMu.Unlock()
	return os.Setenv(key, value)
}

// =============================================================================
// DynamicSecrets subsystem
// =============================================================================

// DynamicSecrets owns the runtime-managed K/V secret store. Each secret is
// stored as an encrypted JSON envelope in the *Storage S3 bucket and may
// optionally be exported into a child-app env var. Distinct from
// *StaticSecrets, which holds the EIF-baked yaml-declared secrets.
type DynamicSecrets struct {
	count     atomic.Int64
	storage   *Storage
	metrics   *Metrics
	staticRef *StaticSecrets // for env_var collision check
	auth      func(http.ResponseWriter, *http.Request) bool
}

// NewDynamicSecrets constructs the subsystem. storage is required; metrics
// and staticRef may be nil (collision checks become no-ops). Init-state
// gating happens at the Runtime middleware layer applied during
// RegisterRoutes — handlers don't check init themselves.
func NewDynamicSecrets(storage *Storage, metrics *Metrics, staticRef *StaticSecrets, auth func(http.ResponseWriter, *http.Request) bool) *DynamicSecrets {
	return &DynamicSecrets{
		storage:   storage,
		metrics:   metrics,
		staticRef: staticRef,
		auth:      auth,
	}
}

// Count returns the loaded-secrets count for enclave-info.
func (d *DynamicSecrets) Count() int64 { return d.count.Load() }

// Init scans the storage bucket for existing dynamic secrets and injects
// each one's env var (if configured). Returns the count of loaded secrets.
// No-op if storage isn't ready (DEK not loaded).
func (d *DynamicSecrets) Init(ctx context.Context) (int, error) {
	if d.storage == nil || !d.storage.HasDEK() {
		return 0, nil // storage not initialized, skip
	}
	names, err := d.list(ctx)
	if err != nil {
		return 0, err
	}

	seenEnvVars := make(map[string]string) // env_var → secret name
	loaded := 0

	for _, name := range names {
		secret, err := d.load(ctx, name)
		if err != nil {
			slog.Warn("skip dynamic secret", "name", name, "error", err)
			continue
		}
		if secret.EnvVar != "" {
			if prev, dup := seenEnvVars[secret.EnvVar]; dup {
				slog.Warn("duplicate env_var in dynamic secrets", "prev", prev, "current", name, "env_var", secret.EnvVar)
			}
			seenEnvVars[secret.EnvVar] = name
			_ = safeSetenv(secret.EnvVar, secret.Value)
		}
		loaded++
	}
	d.count.Store(int64(loaded))
	return loaded, nil
}

// store encrypts and persists a dynamic secret.
func (d *DynamicSecrets) store(ctx context.Context, name, envVar, value string) error {
	if err := validateSecretName(name); err != nil {
		return err
	}
	if len(value) > maxSecretValueSize {
		return fmt.Errorf("secret value too large (%d bytes, max %d)", len(value), maxSecretValueSize)
	}

	// Validate env_var doesn't collide with static secrets.
	if envVar != "" && d.staticRef != nil {
		for _, s := range d.staticRef.Secrets() {
			if s.EnvVar == envVar {
				return fmt.Errorf("env_var %q conflicts with static secret %q", envVar, s.Name)
			}
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Preserve created_at if updating an existing secret.
	createdAt := now
	if existing, err := d.load(ctx, name); err == nil {
		createdAt = existing.CreatedAt
	}

	secret := DynamicSecret{
		Name:      name,
		EnvVar:    envVar,
		Value:     value,
		CreatedAt: createdAt,
		UpdatedAt: now,
	}
	data, err := json.Marshal(secret)
	if err != nil {
		return fmt.Errorf("marshal secret: %w", err)
	}

	if d.metrics != nil {
		d.metrics.Inc(d.metrics.SecretWrites, "secret_writes_total")
	}
	slog.Info("secret stored", "name", name, "env_var", envVar)
	return d.storage.Store(ctx, secretsPrefix+name, data)
}

// load retrieves and decrypts a dynamic secret.
func (d *DynamicSecrets) load(ctx context.Context, name string) (*DynamicSecret, error) {
	if d.metrics != nil {
		d.metrics.Inc(d.metrics.SecretReads, "secret_reads_total")
	}
	data, err := d.storage.Load(ctx, secretsPrefix+name)
	if err != nil {
		return nil, err
	}
	var secret DynamicSecret
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, fmt.Errorf("unmarshal secret %q: %w", name, err)
	}
	return &secret, nil
}

// del removes a dynamic secret from storage.
func (d *DynamicSecrets) del(ctx context.Context, name string) error {
	if d.metrics != nil {
		d.metrics.Inc(d.metrics.SecretDeletes, "secret_deletes_total")
	}
	slog.Info("secret deleted", "name", name)
	return d.storage.Delete(ctx, secretsPrefix+name)
}

// list returns the names of all dynamic secrets.
func (d *DynamicSecrets) list(ctx context.Context) ([]string, error) {
	keys, err := d.storage.List(ctx, secretsPrefix)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		names = append(names, strings.TrimPrefix(k, secretsPrefix))
	}
	return names, nil
}

// =============================================================================
// HTTP handlers
// =============================================================================

// RegisterRoutes attaches the dynamic-secrets endpoints on mux.
func (d *DynamicSecrets) RegisterRoutes(mux Mux) {
	mux.HandleFunc("PUT /v1/secrets/{name}", d.handlePut)
	mux.HandleFunc("GET /v1/secrets/{name}", d.handleGet)
	mux.HandleFunc("DELETE /v1/secrets/{name}", d.handleDelete)
	mux.HandleFunc("GET /v1/secrets", d.handleList)
}

// handlePut handles PUT /v1/secrets/{name}.
func (d *DynamicSecrets) handlePut(w http.ResponseWriter, r *http.Request) {
	if d.auth != nil && !d.auth(w, r) {
		return
	}

	name := r.PathValue("name")
	if err := validateSecretName(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var req struct {
		EnvVar string `json:"env_var"`
		Value  string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Value == "" {
		http.Error(w, "value is required", http.StatusBadRequest)
		return
	}

	// Check if this is a new secret (vs update) for count tracking.
	_, existsErr := d.load(r.Context(), name)
	isNew := existsErr != nil

	if err := d.store(r.Context(), name, req.EnvVar, req.Value); err != nil {
		if strings.Contains(err.Error(), "too large") {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if isNew {
		d.count.Add(1)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}{Name: name, Status: "stored"})
}

// handleGet handles GET /v1/secrets/{name}.
func (d *DynamicSecrets) handleGet(w http.ResponseWriter, r *http.Request) {
	if d.auth != nil && !d.auth(w, r) {
		return
	}

	name := r.PathValue("name")
	if err := validateSecretName(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	secret, err := d.load(r.Context(), name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "secret not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(secret)
}

// handleDelete handles DELETE /v1/secrets/{name}.
func (d *DynamicSecrets) handleDelete(w http.ResponseWriter, r *http.Request) {
	if d.auth != nil && !d.auth(w, r) {
		return
	}

	name := r.PathValue("name")
	if err := validateSecretName(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verify secret exists before deleting (for accurate count tracking).
	if _, err := d.load(r.Context(), name); err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "secret not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := d.del(r.Context(), name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	d.count.Add(-1)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}{Name: name, Status: "deleted"})
}

// handleList handles GET /v1/secrets.
// Returns metadata for each secret (name, env_var, timestamps) but not the value.
func (d *DynamicSecrets) handleList(w http.ResponseWriter, r *http.Request) {
	if d.auth != nil && !d.auth(w, r) {
		return
	}

	names, err := d.list(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	secrets := make([]DynamicSecretInfo, 0, len(names))
	for _, name := range names {
		secret, err := d.load(r.Context(), name)
		if err != nil {
			slog.Warn("skip secret in list", "name", name, "error", err)
			continue
		}
		secrets = append(secrets, DynamicSecretInfo{
			Name:      secret.Name,
			EnvVar:    secret.EnvVar,
			CreatedAt: secret.CreatedAt,
			UpdatedAt: secret.UpdatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Secrets []DynamicSecretInfo `json:"secrets"`
	}{Secrets: secrets})
}

// =============================================================================
// Auth helper (still on Runtime — used as the auth callback by subsystems)
// =============================================================================

// checkRuntimeToken validates the Authorization: Bearer <token> header.
// Stays on *Runtime because it reads e.runtimeToken; subsystems pass it
// in as the auth callback during their construction.
func (e *Runtime) checkRuntimeToken(w http.ResponseWriter, r *http.Request) bool {
	if e.runtimeToken == "" {
		return true // no token configured, allow (backwards compat)
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, "missing Authorization header", http.StatusUnauthorized)
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		http.Error(w, "invalid Authorization format, expected Bearer token", http.StatusUnauthorized)
		return false
	}
	if strings.TrimPrefix(auth, prefix) != e.runtimeToken {
		http.Error(w, "invalid management token", http.StatusForbidden)
		return false
	}
	return true
}
