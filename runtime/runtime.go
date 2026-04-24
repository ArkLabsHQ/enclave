package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// Version is set at build time via ldflags:
//
//	-X github.com/ArkLabsHQ/introspector-enclave/runtime.Version=...
var Version = "dev"

// SecretDef defines a secret managed by KMS inside the enclave runtime.
type SecretDef struct {
	Name   string `json:"name"`
	EnvVar string `json:"env_var"`
}

// AttestationHashRegistrar registers the SHA-256 hash of the enclave
// application's attestation public key with the in-process nitriding instance
// so it's embedded in NSM attestation documents.
//
// Implemented by *nitriding.Enclave (see runtime/nitriding/setters.go).
// Tests inject a fake.
type AttestationHashRegistrar interface {
	SetAttestationKeyHash(hash [32]byte)
}

// Runtime holds the initialized runtime state.
type Runtime struct {
	attestationKey          *btcec.PrivateKey
	attestationRegistrar    AttestationHashRegistrar
	secrets                 []SecretDef
	previousPCR0            string
	previousPCR0Attestation string       // base64-encoded COSE Sign1 attestation doc
	initDone                atomic.Bool  // true after Init completes (happens-before fence)
	initOK                  atomic.Bool  // true only if Init completed successfully
	runtimeToken            string       // bearer token for management endpoints (empty = no auth)
	dynamicSecretsCount     atomic.Int64 // count of loaded dynamic secrets, for enclave-info

	// Encrypted persistent storage (S3-backed, AES-256-GCM with single DEK).
	s3Client   *s3.Client
	bucketName string
	dek        []byte // 32-byte plaintext AES-256 key, in memory only

	// Log buffer for structured log entries from the app.
	logBuffer *LogBuffer
	logShipCh chan LogEntry // buffered channel for CloudWatch shipper (nil when disabled)

	// Span buffer for distributed trace spans.
	spanBuffer *SpanBuffer
	spanShipCh chan SpanEntry // buffered channel for CloudWatch span shipper (nil when disabled)

	// Migration cooldown cache (avoids hammering SSM on every enclave-info call).
	cooldownMu        sync.Mutex
	cooldownPending   bool
	cooldownRemaining int // seconds
	cooldownFetchedAt time.Time
}

// New creates an Enclave that is safe to use immediately for serving
// management endpoints. Call Init() separately to complete initialization.
// A random management token is generated for authenticating internal API calls.
func New() (*Runtime, error) {
	token, err := generateRuntimeToken()
	if err != nil {
		return nil, fmt.Errorf("generate supervisor token: %w", err)
	}
	var logCh chan LogEntry
	var spanCh chan SpanEntry
	if cloudwatchLogsEnabled() {
		logCh = make(chan LogEntry, 1000)
		spanCh = make(chan SpanEntry, 1000)
	}
	return &Runtime{
		previousPCR0: "genesis",
		runtimeToken: token,
		logBuffer:    NewLogBuffer(logBufferSize()),
		logShipCh:    logCh,
		spanBuffer:   NewSpanBuffer(spanBufferSize()),
		spanShipCh:   spanCh,
	}, nil
}

// RuntimeToken returns the management token for authenticating internal API calls.
// Pass this to the consumer app via environment variable.
func (e *Runtime) RuntimeToken() string {
	return e.runtimeToken
}

// generateRuntimeToken creates a 32-byte random hex token.
func generateRuntimeToken() (string, error) {
	b := make([]byte, 32)
	if _, err := secureRandom(b); err != nil {
		return "", fmt.Errorf("secure random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// secureRandom fills the buffer with random bytes from the Nitro NSM hardware
// RNG (/dev/nsm GetRandom). If NSM is unavailable (dev/testing outside an
// enclave), falls back to crypto/rand.
//
// Inside an enclave crypto/rand relies on the kernel entropy pool which is
// severely starved (no disk, no network, no HID — only RDRAND). The NSM
// hardware RNG is a dedicated, independent entropy source provided by AWS
// specifically for this reason. If we successfully open /dev/nsm (meaning
// we ARE in an enclave) but GetRandom fails, we return the error rather
// than silently falling back to the weak pool.
func secureRandom(b []byte) (int, error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		// Not in an enclave (no /dev/nsm) — crypto/rand is fine on normal Linux.
		return rand.Read(b)
	}
	defer func() { _ = session.Close() }()
	// In an enclave — NSM hardware RNG is the only trustworthy source.
	return session.Read(b)
}

// Init initializes the enclave: generates an ephemeral attestation key,
// loads secrets from KMS via attestation, extends PCRs with secret pubkeys,
// and checks migration state.
//
// Init may block (e.g. retrying KMS). The HTTP server should be started
// before calling Init so management endpoints are available during init.
// On completion (success or failure), initDone is set so handlers can
// read all fields safely.
func (e *Runtime) Init(ctx context.Context) error {
	defer e.initDone.Store(true)

	ctx, initSpan := SupervisorSpan(ctx, "init")
	defer initSpan.End()

	secrets, err := loadSecretsConfig()
	if err != nil {
		slog.Error("load secrets config", "error", err)
		return fmt.Errorf("load secrets config: %w", err)
	}
	e.secrets = secrets

	if err := e.generateAttestationKey(); err != nil {
		slog.Error("generate attestation key", "error", err)
		return fmt.Errorf("generate attestation key: %w", err)
	}

	// Verify previous PCR0 BEFORE any irreversible operations.
	// selfApplyKMSPolicy permanently locks the KMS key to the current PCR0,
	// and initStorage may generate a fresh DEK. Both are irreversible —
	// checking first prevents a silent revert to a fresh deployment when
	// previous_pcr0 is wrong.
	expectedPreviousPCR0 := os.Getenv("ENCLAVE_PREVIOUS_PCR0")
	if expectedPreviousPCR0 == "" {
		expectedPreviousPCR0 = "genesis"
	}

	// Classify boot role from declarative SSM flags. Any enclave that boots
	// with MigrationKMSKeyID set but is NOT the target must run the abort path.
	migrationKeyID := ""
	if mkid, err := readMigrationKMSKeyID(ctx); err == nil {
		migrationKeyID = mkid
	}
	migrationTargetPCR0 := ""
	if tgt, err := readMigrationTargetPCR0(ctx); err == nil {
		migrationTargetPCR0 = tgt
	}
	ownPCR0 := getPCR0()
	role := classifyBootRole(migrationKeyID != "", ownPCR0, migrationTargetPCR0)

	if role == BootRoleAbortMigration {
		slog.Warn("aborting in-progress migration — this enclave is not the target",
			"migration_key", migrationKeyID[:min(16, len(migrationKeyID))],
			"target_pcr0", migrationTargetPCR0[:min(16, len(migrationTargetPCR0))],
			"own_pcr0", ownPCR0[:min(16, len(ownPCR0))])
		if err := abortOrphanedMigration(ctx, expectedPreviousPCR0); err != nil {
			return fmt.Errorf("abort orphaned migration: %w", err)
		}
		migrationKeyID = ""
		role = BootRoleNoMigration
	}

	paramPrefix := ""
	if role == BootRoleNewEnclave {
		paramPrefix = "Migration/"
		slog.Info("migration mode active — reading from Migration/* staging", "key", migrationKeyID[:min(16, len(migrationKeyID))])
	}

	// Primary-mode verification: baked ENCLAVE_PREVIOUS_PCR0 must match SSM.
	previousPCR0 := "genesis"
	if pcr0, err := readMigrationPreviousPCR0(ctx); err == nil {
		previousPCR0 = pcr0
	}
	if expectedPreviousPCR0 != previousPCR0 {
		return fmt.Errorf("previous_pcr0 mismatch: expected %q (from enclave config), got %q (from SSM)", expectedPreviousPCR0, previousPCR0)
	}
	e.previousPCR0 = previousPCR0

	slog.Info("applying KMS policy")
	if err := selfApplyKMSPolicy(ctx, migrationKeyID); err != nil {
		slog.Error("apply KMS policy", "error", err)
		return fmt.Errorf("apply KMS policy: %w", err)
	}

	if len(secrets) > 0 {
		slog.Info("waiting for KMS secrets")
		if err := e.waitForSecretsFromKMS(ctx, secrets, migrationKeyID, paramPrefix); err != nil {
			slog.Error("load secrets from KMS", "error", err)
			return fmt.Errorf("load secrets from KMS: %w", err)
		}

		if err := e.extendPCRsWithSecretPubkeys(secrets); err != nil {
			slog.Error("extend PCRs with secret pubkeys", "error", err)
			return fmt.Errorf("extend PCRs with secret pubkeys: %w", err)
		}
	}

	slog.Info("initializing storage")
	if err := e.initStorage(ctx, migrationKeyID, paramPrefix); err != nil {
		slog.Error("init storage", "error", err)
		return fmt.Errorf("init storage: %w", err)
	}

	if count, err := e.loadDynamicSecrets(ctx); err != nil {
		slog.Warn("load dynamic secrets failed", "error", err)
	} else {
		e.dynamicSecretsCount.Store(int64(count))
	}

	// Load migration attestation (after storage is ready).
	if attestDoc, err := readMigrationPreviousPCR0Attestation(ctx); err == nil {
		e.previousPCR0Attestation = attestDoc

		// Verify that the previous enclave committed to handing off to THIS
		// enclave by checking PCR31 in the attestation document. A mismatch
		// means either a rogue new_pcr0 was injected or the old enclave
		// predates the commitment feature (PCR31 all zeros).
		if err := verifyPCR31Commitment(attestDoc, getPCR0()); err != nil {
			slog.Warn("PCR31 migration commitment verification failed", "error", err)
		} else {
			slog.Info("PCR31 migration commitment verified")
		}
	}

	// Atomic commit: if we're in migration mode, promote Migration/* to
	// primary and clear MigrationKMSKeyID in a single ordered sequence. After
	// this, the enclave is in primary mode and the migration is committed.
	if migrationKeyID != "" {
		slog.Info("promoting migration staging to primary")
		if err := promoteMigrationToPrimary(ctx, secrets, migrationKeyID); err != nil {
			slog.Error("promote migration to primary", "error", err)
			return fmt.Errorf("promote migration: %w", err)
		}
		slog.Info("migration committed")
	}

	deleteOldKMSKey(ctx)
	e.initOK.Store(true)
	slog.Info("init completed successfully")
	SpanOK(initSpan)

	// Start CloudWatch shippers if enabled.
	if e.logShipCh != nil {
		go e.runLogShipper(ctx)
	}
	if e.spanShipCh != nil {
		go e.runSpanShipper(ctx)
	}

	return nil
}

// GetLogBuffer returns the log buffer for use by the slog handler.
func (e *Runtime) GetLogBuffer() *LogBuffer {
	return e.logBuffer
}

// GetLogShipCh returns the CloudWatch log shipping channel (may be nil).
func (e *Runtime) GetLogShipCh() chan LogEntry {
	return e.logShipCh
}

// GetSpanBuffer returns the span buffer.
func (e *Runtime) GetSpanBuffer() *SpanBuffer {
	return e.spanBuffer
}

// GetSpanShipCh returns the CloudWatch span shipping channel (may be nil).
func (e *Runtime) GetSpanShipCh() chan SpanEntry {
	return e.spanShipCh
}

// IsReady returns true only if Init has completed successfully. /health
// returns 503 otherwise, distinguishing "failed" from "ready".
func (e *Runtime) IsReady() bool {
	return e.initOK.Load()
}

// AttestationPubkey returns the hex-encoded compressed public key of the
// ephemeral attestation key, or empty string if not initialized.
func (e *Runtime) AttestationPubkey() string {
	if e.attestationKey == nil {
		return ""
	}
	return hex.EncodeToString(e.attestationKey.PubKey().SerializeCompressed())
}

// RegisterRoutes adds enclave management endpoints to the mux:
//
//	GET    /v1/enclave-info
//	POST   /v1/enclave-metrics
//	GET    /v1/enclave-metrics
//	POST   /v1/export-key
//	PUT    /v1/storage/{key...}
//	GET    /v1/storage/{key...}
//	DELETE /v1/storage/{key...}
//	GET    /v1/storage
//	PUT    /v1/secrets/{name}
//	GET    /v1/secrets/{name}
//	DELETE /v1/secrets/{name}
//	GET    /v1/secrets
//	POST   /v1/logs
//	GET    /v1/enclave-logs
//	POST   /v1/enclave-traces
//	GET    /v1/enclave-traces
func (e *Runtime) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/enclave-info", e.handleEnclaveInfo)
	mux.HandleFunc("POST /v1/enclave-metrics", e.handleMetricPost)
	mux.HandleFunc("GET /v1/enclave-metrics", e.handleMetricGet)
	mux.HandleFunc("POST /v1/export-key", e.handleExportKey)
	mux.HandleFunc("PUT /v1/storage/{key...}", e.handleStoragePut)
	mux.HandleFunc("GET /v1/storage/{key...}", e.handleStorageGet)
	mux.HandleFunc("DELETE /v1/storage/{key...}", e.handleStorageDelete)
	mux.HandleFunc("GET /v1/storage", e.handleStorageList)
	mux.HandleFunc("PUT /v1/secrets/{name}", e.handleSecretPut)
	mux.HandleFunc("GET /v1/secrets/{name}", e.handleSecretGet)
	mux.HandleFunc("DELETE /v1/secrets/{name}", e.handleSecretDelete)
	mux.HandleFunc("GET /v1/secrets", e.handleSecretList)
	mux.HandleFunc("POST /v1/logs", e.handleLogPost)
	mux.HandleFunc("GET /v1/enclave-logs", e.handleLogGet)
	mux.HandleFunc("POST /v1/enclave-traces", e.handleSpanPost)
	mux.HandleFunc("GET /v1/enclave-traces", e.handleSpanGet)
}

// Middleware returns an http.Handler that signs all responses with the
// ephemeral attestation key using BIP-340 Schnorr signatures.
// Responses pass through unsigned until Init completes successfully; a
// failed Init leaves the enclave in a half-initialised state where signing
// would be misleading, so we gate on initOK (matches IsReady / /health).
func (e *Runtime) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.initOK.Load() || e.attestationKey == nil {
			next.ServeHTTP(w, r)
			return
		}

		rec := &responseRecorder{
			headers: w.Header(),
			body:    &bytes.Buffer{},
			status:  http.StatusOK,
		}
		next.ServeHTTP(rec, r)

		body := rec.body.Bytes()
		if sig := e.signResponse(body); sig != "" {
			w.Header().Set("X-Attestation-Signature", sig)
			w.Header().Set("X-Attestation-Pubkey",
				hex.EncodeToString(e.attestationKey.PubKey().SerializeCompressed()))
		} else {
			w.Header().Set("X-Attestation-Error", "signing-failed")
		}

		w.WriteHeader(rec.status)
		_, _ = w.Write(body)
	})
}

// loadSecretsConfig parses the ENCLAVE_SECRETS_CONFIG env var (JSON array).
func loadSecretsConfig() ([]SecretDef, error) {
	raw := os.Getenv("ENCLAVE_SECRETS_CONFIG")
	if raw == "" {
		return nil, nil
	}
	var secrets []SecretDef
	if err := json.Unmarshal([]byte(raw), &secrets); err != nil {
		return nil, fmt.Errorf("parse ENCLAVE_SECRETS_CONFIG: %w", err)
	}
	return secrets, nil
}

// SetAttestationRegistrar wires the in-process nitriding enclave as the
// recipient of the attestation key hash. Call this before Init.
func (e *Runtime) SetAttestationRegistrar(r AttestationHashRegistrar) {
	e.attestationRegistrar = r
}

// generateAttestationKey creates an ephemeral secp256k1 keypair and registers
// its public key hash with the in-process nitriding instance.
func (e *Runtime) generateAttestationKey() error {
	keyBytes := make([]byte, 32)
	if _, err := secureRandom(keyBytes); err != nil {
		return fmt.Errorf("generate random bytes: %w", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	if privKey == nil {
		return fmt.Errorf("invalid secp256k1 key from random bytes")
	}
	e.attestationKey = privKey

	if e.attestationRegistrar == nil {
		return fmt.Errorf("no attestation registrar wired; call SetAttestationRegistrar before Init")
	}
	hash := sha256.Sum256(privKey.PubKey().SerializeCompressed())
	e.attestationRegistrar.SetAttestationKeyHash(hash)
	return nil
}

// extendPCRsWithSecretPubkeys derives the secp256k1 compressed public key for
// each secret and extends PCR (16 + index) with SHA256(compressed_pubkey).
func (e *Runtime) extendPCRsWithSecretPubkeys(secrets []SecretDef) error {
	for i, s := range secrets {
		pcrIndex := uint(16) + uint(i)
		if pcrIndex >= migrationPCRIndex {
			return fmt.Errorf("secret %q: PCR index %d would collide with migration PCR (PCR%d)", s.Name, pcrIndex, migrationPCRIndex)
		}

		secretHex := os.Getenv(s.EnvVar)
		if secretHex == "" {
			return fmt.Errorf("secret %q env var %s is empty", s.Name, s.EnvVar)
		}

		secretBytes, err := hex.DecodeString(secretHex)
		if err != nil {
			return fmt.Errorf("decode secret %q hex: %w", s.Name, err)
		}

		privKey, _ := btcec.PrivKeyFromBytes(secretBytes)
		if privKey == nil {
			return fmt.Errorf("secret %q: invalid secp256k1 private key", s.Name)
		}

		pubkeyBytes := privKey.PubKey().SerializeCompressed()
		hash := sha256.Sum256(pubkeyBytes)

		if err := extendPCR(pcrIndex, hash[:]); err != nil {
			return fmt.Errorf("extend PCR%d with secret %q pubkey: %w", pcrIndex, s.Name, err)
		}
		if err := lockPCR(pcrIndex); err != nil {
			return fmt.Errorf("lock PCR%d after secret %q: %w", pcrIndex, s.Name, err)
		}
	}
	return nil
}

// signResponse signs the response body with the attestation key using BIP-340
// Schnorr signatures. Returns hex-encoded signature or empty string on error.
func (e *Runtime) signResponse(body []byte) string {
	if e.attestationKey == nil {
		return ""
	}
	msgHash := sha256.Sum256(body)
	sig, err := schnorr.Sign(e.attestationKey, msgHash[:])
	if err != nil {
		slog.Warn("schnorr sign failed", "error", err)
		return ""
	}
	return hex.EncodeToString(sig.Serialize())
}

// handleEnclaveInfo returns build-time and runtime metadata about this enclave.
// Before init completes, returns 503 with partial state so callers get meaningful
// JSON instead of 502, while curl -sf health checks still fail.
func (e *Runtime) handleEnclaveInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if !e.initDone.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(struct {
			Version      string `json:"version"`
			PreviousPCR0 string `json:"previous_pcr0"`
			Initializing bool   `json:"initializing"`
		}{
			Version:      Version,
			PreviousPCR0: "genesis",
			Initializing: true,
		})
		return
	}

	cooldownSeconds, cooldownRemaining, migrationPending := e.getMigrationCooldownStatus(r.Context())

	_ = json.NewEncoder(w).Encode(struct {
		Version                    string         `json:"version"`
		PreviousPCR0               string         `json:"previous_pcr0"`
		PreviousPCR0Attestation    string         `json:"previous_pcr0_attestation,omitempty"`
		AttestationPubkey          string         `json:"attestation_pubkey,omitempty"`
		DynamicSecrets             int64          `json:"dynamic_secrets"`
		Metrics                    map[string]any `json:"metrics"`
		MigrationCooldownSeconds   int            `json:"migration_cooldown_seconds"`
		MigrationCooldownRemaining int            `json:"migration_cooldown_remaining,omitempty"`
		MigrationPending           bool           `json:"migration_pending"`
	}{
		Version:                    Version,
		PreviousPCR0:               e.previousPCR0,
		PreviousPCR0Attestation:    e.previousPCR0Attestation,
		AttestationPubkey:          e.AttestationPubkey(),
		DynamicSecrets:             e.dynamicSecretsCount.Load(),
		Metrics:                    enclaveMetrics.MetricsSnapshot(),
		MigrationCooldownSeconds:   cooldownSeconds,
		MigrationCooldownRemaining: cooldownRemaining,
		MigrationPending:           migrationPending,
	})
}

// getMigrationCooldownStatus returns the configured cooldown duration, remaining
// seconds, and whether a migration is pending. Results are cached for 5 seconds
// to avoid hammering SSM on frequent enclave-info calls.
func (e *Runtime) getMigrationCooldownStatus(ctx context.Context) (configuredSeconds int, remainingSeconds int, pending bool) {
	cooldownStr := os.Getenv("ENCLAVE_MIGRATION_COOLDOWN")
	if cooldownStr == "" {
		cooldownStr = "0s"
	}
	cooldown, err := time.ParseDuration(cooldownStr)
	if err != nil {
		return 0, 0, false
	}
	configuredSeconds = int(cooldown.Seconds())

	// No cooldown configured — skip SSM check entirely.
	if cooldown == 0 {
		return 0, 0, false
	}

	// Return cached result if fresh.
	e.cooldownMu.Lock()
	if time.Since(e.cooldownFetchedAt) < 5*time.Second {
		remaining := e.cooldownRemaining
		pend := e.cooldownPending
		e.cooldownMu.Unlock()
		return configuredSeconds, remaining, pend
	}
	e.cooldownMu.Unlock()

	// Fetch MigrationRequestedAt from SSM.
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		return configuredSeconds, 0, false
	}
	ssmClient := newSSMClient(awsCfg)
	deployment := getDeployment()
	appName := getAppName()

	requestedAtStr, err := readSSMParam(ctx, ssmClient, fmt.Sprintf("/%s/%s/MigrationRequestedAt", deployment, appName))
	if err != nil || requestedAtStr == "" {
		e.cooldownMu.Lock()
		e.cooldownPending = false
		e.cooldownRemaining = 0
		e.cooldownFetchedAt = time.Now()
		e.cooldownMu.Unlock()
		return configuredSeconds, 0, false
	}

	requestedAt, err := time.Parse(time.RFC3339, requestedAtStr)
	if err != nil {
		return configuredSeconds, 0, false
	}

	deadline := requestedAt.Add(cooldown)
	remaining := time.Until(deadline)
	if remaining < 0 {
		remaining = 0
	}

	e.cooldownMu.Lock()
	e.cooldownPending = true
	e.cooldownRemaining = int(remaining.Seconds())
	e.cooldownFetchedAt = time.Now()
	e.cooldownMu.Unlock()

	return configuredSeconds, int(remaining.Seconds()), true
}

// lockPCR locks a PCR via the NSM, making it read-only.
func lockPCR(index uint) error {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open NSM session: %w", err)
	}
	defer func() { _ = session.Close() }()

	resp, err := session.Send(&request.LockPCR{
		Index: uint16(index),
	})
	if err != nil {
		return fmt.Errorf("LockPCR(%d): %w", index, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("LockPCR(%d): NSM error: %s", index, resp.Error)
	}
	return nil
}

// extendPCR extends a PCR with the given data via the NSM.
func extendPCR(index uint, data []byte) error {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open NSM session: %w", err)
	}
	defer func() { _ = session.Close() }()

	resp, err := session.Send(&request.ExtendPCR{
		Index: uint16(index),
		Data:  data,
	})
	if err != nil {
		return fmt.Errorf("ExtendPCR(%d): %w", index, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("ExtendPCR(%d): NSM error: %s", index, resp.Error)
	}
	return nil
}

// responseRecorder captures HTTP response data for signing.
type responseRecorder struct {
	headers http.Header
	body    *bytes.Buffer
	status  int
}

func (r *responseRecorder) Header() http.Header  { return r.headers }
func (r *responseRecorder) WriteHeader(code int) { r.status = code }
func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

func (r *responseRecorder) ReadFrom(src io.Reader) (int64, error) {
	return io.Copy(r.body, src)
}
