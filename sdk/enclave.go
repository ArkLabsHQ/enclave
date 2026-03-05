package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// Version is set at build time via ldflags:
//
//	-X github.com/ArkLabsHQ/introspector-enclave/sdk.Version=...
var Version = "dev"

// SecretDef defines a secret managed by KMS inside the enclave.
type SecretDef struct {
	Name   string `json:"name"`
	EnvVar string `json:"env_var"`
}

// Enclave holds the initialized enclave state.
type Enclave struct {
	attestationKey          *btcec.PrivateKey
	secrets                 []SecretDef
	previousPCR0            string
	previousPCR0Attestation string // base64-encoded COSE Sign1 attestation doc
	initDone                atomic.Bool  // true after Init completes (happens-before fence)
	initError               atomic.Value // stores string, updated progressively during init

	// Encrypted persistent storage (S3-backed, AES-256-GCM with single DEK).
	s3Client   *s3.Client
	bucketName string
	dek        []byte // 32-byte plaintext AES-256 key, in memory only
}

// New creates an Enclave that is safe to use immediately for serving
// management endpoints. Call Init() separately to complete initialization.
func New() *Enclave {
	return &Enclave{previousPCR0: "genesis"}
}

// Init initializes the enclave: generates an ephemeral attestation key,
// loads secrets from KMS via attestation, extends PCRs with secret pubkeys,
// and checks migration state.
//
// Init may block (e.g. retrying KMS). The HTTP server should be started
// before calling Init so management endpoints are available during init.
// On completion (success or failure), initDone is set so handlers can
// read all fields safely.
func (e *Enclave) Init(ctx context.Context) error {
	defer e.initDone.Store(true)

	secrets, err := loadSecretsConfig()
	if err != nil {
		e.setInitError(fmt.Sprintf("load secrets config: %s", err))
		return fmt.Errorf("load secrets config: %w", err)
	}
	e.secrets = secrets

	if err := e.generateAttestationKey(); err != nil {
		e.setInitError(fmt.Sprintf("generate attestation key: %s", err))
		return fmt.Errorf("generate attestation key: %w", err)
	}

	e.setInitError("applying KMS policy")
	if err := selfApplyKMSPolicy(ctx); err != nil {
		e.setInitError(fmt.Sprintf("apply KMS policy: %s", err))
		return fmt.Errorf("apply KMS policy: %w", err)
	}

	if len(secrets) > 0 {
		e.setInitError("waiting for KMS secrets")
		if err := e.waitForSecretsFromKMS(ctx, secrets); err != nil {
			e.setInitError(fmt.Sprintf("load secrets from KMS: %s", err))
			return fmt.Errorf("load secrets from KMS: %w", err)
		}

		if err := e.extendPCRsWithSecretPubkeys(secrets); err != nil {
			e.setInitError(fmt.Sprintf("extend PCRs with secret pubkeys: %s", err))
			return fmt.Errorf("extend PCRs with secret pubkeys: %w", err)
		}
	}

	e.setInitError("initializing storage")
	if err := e.initStorage(ctx); err != nil {
		e.setInitError(fmt.Sprintf("init storage: %s", err))
		return fmt.Errorf("init storage: %w", err)
	}

	if pcr0, err := readMigrationPreviousPCR0(ctx); err == nil {
		e.previousPCR0 = pcr0
	}
	if attestDoc, err := readMigrationPreviousPCR0Attestation(ctx); err == nil {
		e.previousPCR0Attestation = attestDoc
	}

	deleteOldKMSKey(ctx)
	e.setInitError("") // clear — init succeeded
	return nil
}

// setInitError stores an init error message atomically.
func (e *Enclave) setInitError(msg string) {
	e.initError.Store(msg)
}

// InitError returns the initialization error/status message, or empty string on success.
func (e *Enclave) InitError() string {
	if v := e.initError.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// IsReady returns true after Init has completed (success or failure).
func (e *Enclave) IsReady() bool {
	return e.initDone.Load()
}

// AttestationPubkey returns the hex-encoded compressed public key of the
// ephemeral attestation key, or empty string if not initialized.
func (e *Enclave) AttestationPubkey() string {
	if e.attestationKey == nil {
		return ""
	}
	return hex.EncodeToString(e.attestationKey.PubKey().SerializeCompressed())
}

// RegisterRoutes adds enclave management endpoints to the mux:
//
//	GET  /v1/enclave-info
//	POST /v1/export-key
//	POST /v1/extend-pcr
//	POST /v1/lock-pcr
func (e *Enclave) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/enclave-info", e.handleEnclaveInfo)
	mux.HandleFunc("POST /v1/export-key", e.handleExportKey)
	mux.HandleFunc("POST /v1/extend-pcr", e.handleExtendPCR)
	mux.HandleFunc("POST /v1/lock-pcr", e.handleLockPCR)
}

// Middleware returns an http.Handler that signs all responses with the
// ephemeral attestation key using BIP-340 Schnorr signatures.
// Before init completes, responses pass through unsigned.
func (e *Enclave) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.initDone.Load() || e.attestationKey == nil {
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
		}

		w.WriteHeader(rec.status)
		w.Write(body)
	})
}

// ExtendPCR extends a user-defined PCR (16-31) with the given data.
func (e *Enclave) ExtendPCR(index uint, data []byte) error {
	return extendPCR(index, data)
}

// LockPCR locks a user-defined PCR (16-31) to prevent further extension.
func (e *Enclave) LockPCR(index uint) error {
	return lockPCR(index)
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

// generateAttestationKey creates an ephemeral secp256k1 keypair and registers
// its public key hash with nitriding via POST /enclave/hash.
func (e *Enclave) generateAttestationKey() error {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("generate random bytes: %w", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	if privKey == nil {
		return fmt.Errorf("invalid secp256k1 key from random bytes")
	}
	e.attestationKey = privKey

	pubkeyBytes := privKey.PubKey().SerializeCompressed()
	hash := sha256.Sum256(pubkeyBytes)
	hashB64 := base64.StdEncoding.EncodeToString(hash[:])

	nitridingPort := os.Getenv("ENCLAVE_NITRIDING_INT_PORT")
	if nitridingPort == "" {
		nitridingPort = "8080"
	}
	nitridingURL := fmt.Sprintf("http://127.0.0.1:%s/enclave/hash", nitridingPort)

	resp, err := http.Post(nitridingURL, "text/plain", strings.NewReader(hashB64))
	if err != nil {
		return fmt.Errorf("POST /enclave/hash: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST /enclave/hash status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return nil
}

// extendPCRsWithSecretPubkeys derives the secp256k1 compressed public key for
// each secret and extends PCR (16 + index) with SHA256(compressed_pubkey).
func (e *Enclave) extendPCRsWithSecretPubkeys(secrets []SecretDef) error {
	for i, s := range secrets {
		pcrIndex := uint(16) + uint(i)
		if pcrIndex > 31 {
			return fmt.Errorf("secret %q: PCR index %d exceeds 31", s.Name, pcrIndex)
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
	}
	return nil
}

// signResponse signs the response body with the attestation key using BIP-340
// Schnorr signatures. Returns hex-encoded signature or empty string on error.
func (e *Enclave) signResponse(body []byte) string {
	if e.attestationKey == nil {
		return ""
	}
	msgHash := sha256.Sum256(body)
	sig, err := schnorr.Sign(e.attestationKey, msgHash[:])
	if err != nil {
		return ""
	}
	return hex.EncodeToString(sig.Serialize())
}

// handleEnclaveInfo returns build-time and runtime metadata about this enclave.
// Before init completes, returns 503 with partial state so callers get meaningful
// JSON instead of 502, while curl -sf health checks still fail.
func (e *Enclave) handleEnclaveInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if !e.initDone.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(struct {
			Version      string `json:"version"`
			PreviousPCR0 string `json:"previous_pcr0"`
			Initializing bool   `json:"initializing"`
			Error        string `json:"error,omitempty"`
		}{
			Version:      Version,
			PreviousPCR0: "genesis", // safe: migration PCR0 is only loaded during Init
			Initializing: true,
			Error:        e.InitError(),
		})
		return
	}

	json.NewEncoder(w).Encode(struct {
		Version                 string `json:"version"`
		PreviousPCR0            string `json:"previous_pcr0"`
		PreviousPCR0Attestation string `json:"previous_pcr0_attestation,omitempty"`
		AttestationPubkey       string `json:"attestation_pubkey,omitempty"`
		Error                   string `json:"error,omitempty"`
	}{
		Version:                 Version,
		PreviousPCR0:            e.previousPCR0,
		PreviousPCR0Attestation: e.previousPCR0Attestation,
		AttestationPubkey:       e.AttestationPubkey(),
		Error:                   e.InitError(),
	})
}

// handleExtendPCR extends a user-defined PCR (16-31) with the provided data.
// This allows the user's app to extend PCRs via HTTP without importing the SDK.
func (e *Enclave) handleExtendPCR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PCR  uint   `json:"pcr"`
		Data string `json:"data"` // base64-encoded
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.PCR < 16 || req.PCR > 31 {
		http.Error(w, "pcr must be in range [16, 31]", http.StatusBadRequest)
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		http.Error(w, "invalid base64 data", http.StatusBadRequest)
		return
	}

	if err := extendPCR(req.PCR, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"pcr":%d,"status":"extended"}`, req.PCR)
}

// handleLockPCR locks a user-defined PCR (16-31) to prevent further extension.
func (e *Enclave) handleLockPCR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PCR uint `json:"pcr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.PCR < 16 || req.PCR > 31 {
		http.Error(w, "pcr must be in range [16, 31]", http.StatusBadRequest)
		return
	}

	if err := lockPCR(req.PCR); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"pcr":%d,"status":"locked"}`, req.PCR)
}

// extendPCR extends a PCR with the given data via the NSM.
func extendPCR(index uint, data []byte) error {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open NSM session: %w", err)
	}
	defer session.Close()

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

// lockPCR locks a PCR to prevent further extension.
func lockPCR(index uint) error {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open NSM session: %w", err)
	}
	defer session.Close()

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
