package runtime

// runtime_handlers.go owns every HTTP handler Runtime mounts on its public
// (TLS) and private (loopback) chi muxes:
//
//   - /enclave/* — attestation, peer-keysync state exchange, app-readiness
//   - /v1/enclave-info — runtime status / metrics snapshot
//   - /health — liveness for load balancers
//
// Each handler closes over *Runtime so it can read attestation hashes,
// registered key material, and subsystem state. Pure utility helpers
// (Attest, the limit reader) live in the nitriding subpackage.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ArkLabsHQ/introspector-enclave/runtime/nitriding"
)

const (
	maxKeyMaterialLen = 1024 * 1024
	indexPage         = "This host runs inside an AWS Nitro Enclave.\n"
	nonceNumDigits    = 40 // 20-byte nonce, hex-encoded
)

var (
	errFailedReqBody  = errors.New("failed to read request body")
	errFailedGetState = errors.New("failed to retrieve saved state")
	errHashWrongSize  = errors.New("given hash is of invalid size")

	errBadForm           = "failed to parse POST form data"
	errNoNonce           = "could not find nonce in URL query parameters"
	errBadNonceFormat    = fmt.Sprintf("unexpected nonce format; must be %d-digit hex string", nonceNumDigits)
	errFailedAttestation = "failed to obtain attestation document from hypervisor"
	errProfilingSet      = "attestation disabled because profiling is enabled"
)

func formatIndexPage(appURL *url.URL) string {
	page := indexPage
	if appURL != nil {
		page += fmt.Sprintf("\nIt runs the following code: %s\n", appURL.String())
	}
	return page
}

func rootHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, formatIndexPage(cfg.AppURL))
	}
}

func configHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, cfg)
	}
}

// attestationHandler serves an NSM attestation document whose user_data
// binds the TLS cert fingerprint and the attestation signing key hash.
func attestationHandler(useProfiling bool, hashes *AttestationHashes) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if useProfiling {
			http.Error(w, errProfilingSet, http.StatusServiceUnavailable)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, errBadForm, http.StatusBadRequest)
			return
		}
		nonce := strings.ToLower(r.URL.Query().Get("nonce"))
		if nonce == "" {
			http.Error(w, errNoNonce, http.StatusBadRequest)
			return
		}
		rawNonce, err := hex.DecodeString(nonce)
		if err != nil {
			http.Error(w, errBadNonceFormat, http.StatusBadRequest)
			return
		}
		rawDoc, err := nitriding.Attest(rawNonce, hashes.Serialize(), nil)
		if err != nil {
			http.Error(w, errFailedAttestation, http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintln(w, base64.StdEncoding.EncodeToString(rawDoc))
	}
}

func getStateHandler(e *Runtime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		s, err := e.KeyMaterial()
		if err != nil {
			http.Error(w, errFailedGetState.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(s.([]byte))
	}
}

func putStateHandler(e *Runtime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(nitriding.NewLimitReader(r.Body, maxKeyMaterialLen))
		if err != nil {
			http.Error(w, errFailedReqBody.Error(), http.StatusInternalServerError)
			return
		}
		e.SetKeyMaterial(body)
		w.WriteHeader(http.StatusOK)
	}
}

func hashHandler(e *Runtime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		maxReadLen := base64.StdEncoding.EncodedLen(sha256.Size) + 1
		body, err := io.ReadAll(nitriding.NewLimitReader(r.Body, maxReadLen))
		if errors.Is(err, nitriding.ErrTooMuchToRead) {
			http.Error(w, nitriding.ErrTooMuchToRead.Error(), http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, errFailedReqBody.Error(), http.StatusInternalServerError)
			return
		}
		keyHash, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
		if err != nil {
			http.Error(w, "base64 decode failed", http.StatusBadRequest)
			return
		}
		if len(keyHash) != sha256.Size {
			http.Error(w, errHashWrongSize.Error(), http.StatusBadRequest)
			return
		}
		var h [sha256.Size]byte
		copy(h[:], keyHash)
		e.hashes.SetSigningKeyHash(h)
		w.WriteHeader(http.StatusOK)
	}
}

func readyHandler(e *Runtime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-e.ready:
			// already closed; idempotent
		default:
			close(e.ready)
		}
		w.WriteHeader(http.StatusOK)
	}
}

// RuntimeInfo is the JSON body returned by GET /v1/enclave-info.
type RuntimeInfo struct {
	Version                    string             `json:"version"`
	PreviousPCR0               string             `json:"previous_pcr0"`
	PreviousPCR0Attestation    string             `json:"previous_pcr0_attestation,omitempty"`
	AttestationPubkey          string             `json:"attestation_pubkey,omitempty"`
	DynamicSecrets             int64              `json:"dynamic_secrets"`
	Metrics                    map[string]any     `json:"metrics"`
	MigrationCooldownSeconds   int                `json:"migration_cooldown_seconds"`
	MigrationCooldownRemaining int                `json:"migration_cooldown_remaining,omitempty"`
	MigrationPending           bool               `json:"migration_pending"`
	PCR0Signature              *PCR0SignatureInfo `json:"pcr0_signature,omitempty"`
	UpstreamApp                UpstreamAppInfo    `json:"upstream_app"`
	KMSKeyLocked bool `json:"kms_key_locked"`
}

// UpstreamAppInfo reports whether the user app process has exited and, if
// so, the error from its exit. The runtime stays alive after app exit so
// admin endpoints remain reachable.
type UpstreamAppInfo struct {
	Exited bool   `json:"exited"`
	Error  string `json:"error,omitempty"`
}

// RuntimeInitializing is the JSON body returned by GET /v1/enclave-info before Init completes.
type RuntimeInitializing struct {
	Version      string `json:"version"`
	PreviousPCR0 string `json:"previous_pcr0"`
	Initializing bool   `json:"initializing"`
}

// enclaveInfoHandler serves /v1/enclave-info. Gates on initOK so a
// failed Init doesn't nil-deref subsystems that were never wired.
func enclaveInfoHandler(e *Runtime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if !e.initOK.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(RuntimeInitializing{
				Version:      Version,
				Initializing: true,
			})
			return
		}

		cooldownSeconds, cooldownRemaining, migrationPending := e.migrator.CooldownStatus(r.Context())

		previousPCR0 := "genesis"
		previousPCR0Attestation := ""
		if info, err := e.migrator.GetPreviousPCR0Info(r.Context()); err == nil && info != nil {
			previousPCR0 = info.PCR0
			previousPCR0Attestation = info.Attestation
		}

		upstreamExited, upstreamErr := e.UpstreamExited()

		_ = json.NewEncoder(w).Encode(RuntimeInfo{
			Version:                    Version,
			PreviousPCR0:               previousPCR0,
			PreviousPCR0Attestation:    previousPCR0Attestation,
			AttestationPubkey:          e.AttestationPubkey(),
			DynamicSecrets:             e.dynamic.Count(),
			Metrics:                    enclaveMetrics.MetricsSnapshot(),
			MigrationCooldownSeconds:   cooldownSeconds,
			MigrationCooldownRemaining: cooldownRemaining,
			MigrationPending:           migrationPending,
			PCR0Signature:              e.signature.Snapshot(),
			UpstreamApp:                UpstreamAppInfo{Exited: upstreamExited, Error: upstreamErr},
			KMSKeyLocked:               kmsKeyLocked(),
		})
	}
}

// healthHandler returns 200 once IsReady() is true, 503 otherwise.
func healthHandler(e *Runtime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !e.IsReady() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "initializing"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	}
}
