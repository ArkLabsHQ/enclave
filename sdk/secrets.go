package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

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

// StoreSecret encrypts and persists a dynamic secret.
func (e *Enclave) StoreSecret(ctx context.Context, name, envVar, value string) error {
	if err := validateSecretName(name); err != nil {
		return err
	}

	// Validate env_var doesn't collide with static secrets.
	if envVar != "" {
		for _, s := range e.secrets {
			if s.EnvVar == envVar {
				return fmt.Errorf("env_var %q conflicts with static secret %q", envVar, s.Name)
			}
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Preserve created_at if updating an existing secret.
	createdAt := now
	if existing, err := e.LoadSecret(ctx, name); err == nil {
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

	log.Printf("secret stored: %s (env_var=%q)", name, envVar)
	return e.Store(ctx, secretsPrefix+name, data)
}

// LoadSecret retrieves and decrypts a dynamic secret.
func (e *Enclave) LoadSecret(ctx context.Context, name string) (*DynamicSecret, error) {
	data, err := e.Load(ctx, secretsPrefix+name)
	if err != nil {
		return nil, err
	}
	var secret DynamicSecret
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, fmt.Errorf("unmarshal secret %q: %w", name, err)
	}
	return &secret, nil
}

// DeleteSecret removes a dynamic secret from storage.
func (e *Enclave) DeleteSecret(ctx context.Context, name string) error {
	log.Printf("secret deleted: %s", name)
	return e.Delete(ctx, secretsPrefix+name)
}

// ListSecrets returns the names of all dynamic secrets.
func (e *Enclave) ListSecrets(ctx context.Context) ([]string, error) {
	keys, err := e.List(ctx, secretsPrefix)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		names = append(names, strings.TrimPrefix(k, secretsPrefix))
	}
	return names, nil
}

// loadDynamicSecrets scans stored secrets and injects their env vars.
// Returns the count of loaded secrets for enclave-info reporting.
func (e *Enclave) loadDynamicSecrets(ctx context.Context) (int, error) {
	if e.dek == nil {
		return 0, nil // storage not initialized, skip
	}
	names, err := e.ListSecrets(ctx)
	if err != nil {
		return 0, err
	}

	seenEnvVars := make(map[string]string) // env_var → secret name
	loaded := 0

	for _, name := range names {
		secret, err := e.LoadSecret(ctx, name)
		if err != nil {
			log.Printf("warning: skip dynamic secret %q: %v", name, err)
			continue
		}
		if secret.EnvVar != "" {
			if prev, dup := seenEnvVars[secret.EnvVar]; dup {
				log.Printf("warning: dynamic secret %q and %q both define env_var %q, last write wins", prev, name, secret.EnvVar)
			}
			seenEnvVars[secret.EnvVar] = name
			os.Setenv(secret.EnvVar, secret.Value)
		}
		loaded++
	}
	return loaded, nil
}

// checkMgmtToken validates the Authorization: Bearer <token> header.
func (e *Enclave) checkMgmtToken(w http.ResponseWriter, r *http.Request) bool {
	if e.mgmtToken == "" {
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
	if strings.TrimPrefix(auth, prefix) != e.mgmtToken {
		http.Error(w, "invalid management token", http.StatusForbidden)
		return false
	}
	return true
}

// handleSecretPut handles PUT /v1/secrets/{name}.
func (e *Enclave) handleSecretPut(w http.ResponseWriter, r *http.Request) {
	if !e.initDone.Load() {
		http.Error(w, "enclave is still initializing", http.StatusServiceUnavailable)
		return
	}
	if !e.checkMgmtToken(w, r) {
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
	_, existsErr := e.LoadSecret(r.Context(), name)
	isNew := existsErr != nil

	if err := e.StoreSecret(r.Context(), name, req.EnvVar, req.Value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if isNew {
		e.dynamicSecretsCount.Add(1)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}{Name: name, Status: "stored"})
}

// handleSecretGet handles GET /v1/secrets/{name}.
func (e *Enclave) handleSecretGet(w http.ResponseWriter, r *http.Request) {
	if !e.initDone.Load() {
		http.Error(w, "enclave is still initializing", http.StatusServiceUnavailable)
		return
	}
	if !e.checkMgmtToken(w, r) {
		return
	}

	name := r.PathValue("name")
	if err := validateSecretName(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	secret, err := e.LoadSecret(r.Context(), name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "secret not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secret)
}

// handleSecretDelete handles DELETE /v1/secrets/{name}.
func (e *Enclave) handleSecretDelete(w http.ResponseWriter, r *http.Request) {
	if !e.initDone.Load() {
		http.Error(w, "enclave is still initializing", http.StatusServiceUnavailable)
		return
	}
	if !e.checkMgmtToken(w, r) {
		return
	}

	name := r.PathValue("name")
	if err := validateSecretName(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verify secret exists before deleting (for accurate count tracking).
	if _, err := e.LoadSecret(r.Context(), name); err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "secret not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := e.DeleteSecret(r.Context(), name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	e.dynamicSecretsCount.Add(-1)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}{Name: name, Status: "deleted"})
}

// handleSecretList handles GET /v1/secrets.
// Returns metadata for each secret (name, env_var, timestamps) but not the value.
func (e *Enclave) handleSecretList(w http.ResponseWriter, r *http.Request) {
	if !e.initDone.Load() {
		http.Error(w, "enclave is still initializing", http.StatusServiceUnavailable)
		return
	}
	if !e.checkMgmtToken(w, r) {
		return
	}

	names, err := e.ListSecrets(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	secrets := make([]DynamicSecretInfo, 0, len(names))
	for _, name := range names {
		secret, err := e.LoadSecret(r.Context(), name)
		if err != nil {
			log.Printf("warning: skip secret %q in list: %v", name, err)
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
	json.NewEncoder(w).Encode(struct {
		Secrets []DynamicSecretInfo `json:"secrets"`
	}{Secrets: secrets})
}
