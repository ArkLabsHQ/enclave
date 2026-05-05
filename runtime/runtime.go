package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// Runtime is the composer that wires every subsystem together. Each
// subsystem is a self-contained struct built in Init() and registered via
// RegisterRoutes(); Runtime itself owns no business logic beyond the boot
// sequencer and a couple of shared helpers.
type Runtime struct {
	aws           *AWSClient
	metrics       *Metrics
	tracing       *Tracing
	logging       *Logging
	attestation   *Attestation
	kms           *KMS
	staticSecrets *StaticSecrets
	dynamic       *DynamicSecrets
	storage       *Storage
	migrator      *Migrator
	environment   *Environment

	mux *http.ServeMux // captured at RegisterRoutes; Init wires gated subsystem routes here

	initDone     atomic.Bool // true after Init completes (happens-before fence)
	initOK       atomic.Bool // true only if Init completed successfully
	runtimeToken string      // bearer token for management endpoints (empty = no auth)
}

// New returns a Runtime safe to use for serving management endpoints
// immediately. Call Init separately to bring up AWS clients and subsystems.
func New() (*Runtime, error) {
	token, err := generateRuntimeToken()
	if err != nil {
		return nil, fmt.Errorf("generate supervisor token: %w", err)
	}
	if enclaveMetrics == nil {
		// cmd/runtime/main.go calls InitMetrics() first, but allow unit tests
		// to skip that step and let New handle it.
		enclaveMetrics = NewMetrics()
	}
	r := &Runtime{
		metrics:      enclaveMetrics,
		attestation:  NewAttestation(),
		runtimeToken: token,
	}
	r.logging = NewLogging(enclaveMetrics, nil, r.checkRuntimeToken)
	r.tracing = NewTracing(enclaveMetrics, nil, r.checkRuntimeToken)
	return r, nil
}

func (e *Runtime) RuntimeToken() string {
	return e.runtimeToken
}

// Init brings up subsystems: AWS clients, KMS policy lock, secrets via
// attestation, PCR extension, storage, migration handshake. May block on
// KMS. The HTTP server should be started before Init so /v1/enclave-info
// and telemetry endpoints stay reachable. initDone is set on return (success
// or failure) so handlers can read fields safely.
func (e *Runtime) Init(ctx context.Context) error {
	defer e.initDone.Store(true)

	ctx, initSpan := e.tracing.Span(ctx, "init")
	defer initSpan.End()

	// AWS clients are built once and shared via e.aws.{KMS,SSM,S3,STS,CWL}.
	aws, err := NewAWSClient(ctx)
	if err != nil {
		slog.Error("init AWS clients", "error", err)
		return fmt.Errorf("init AWS clients: %w", err)
	}
	e.aws = aws

	e.kms = NewKMS(e.aws)

	e.environment = NewEnvironment(e.aws)
	if err := e.environment.Override(ctx); err != nil {
		slog.Error("apply env overrides", "error", err)
		return fmt.Errorf("apply env overrides: %w", err)
	}

	staticSecrets, err := NewStaticSecrets(e.kms)
	if err != nil {
		slog.Error("load static secrets config", "error", err)
		return fmt.Errorf("load static secrets config: %w", err)
	}
	e.staticSecrets = staticSecrets

	e.storage = NewStorage(e.kms, e.metrics, e.checkRuntimeToken)

	if err := e.attestation.Init(); err != nil {
		slog.Error("init attestation", "error", err)
		return fmt.Errorf("init attestation: %w", err)
	}

	// Migrator needs Storage too, but Storage doesn't exist yet. Wired in below;
	// start-migration isn't reachable before initOK, so the late wire-up is safe.
	e.migrator = NewMigrator(e.aws, e.kms, e.staticSecrets, nil, e.checkRuntimeToken)

	// Classify boot role. If MigrationKMSKeyID is set and we're the declared
	// MigrationTargetPCR0, read secrets and DEK from Migration/* staging
	// using the migration key. Otherwise (orphan or normal boot), read from
	// primary. CompleteMigration at the end commits or aborts accordingly,
	// so primary state is only touched after the staged reads validate.
	migrationKMSKeyID, err := e.migrator.GetMigrationKMSKeyID(ctx)
	if err != nil {
		slog.Error("read migration KMS key ID", "error", err)
		return fmt.Errorf("read migration KMS key ID: %w", err)
	}

	var (
		paramPrefix       ParamPrefix
		keyID             string
		isMigrationTarget bool
	)
	if migrationKMSKeyID != "" {
		isMigrationTarget, err = e.migrator.IsTarget(ctx)
		if err != nil {
			return fmt.Errorf("classify boot role: %w", err)
		}
		if isMigrationTarget {
			paramPrefix = MigrationPrefix
			keyID = migrationKMSKeyID
			slog.Info("migration target — reading from Migration/* staging", "key", prefix16(migrationKMSKeyID))
		}
	}
	if !isMigrationTarget {
		keyID, err = e.kms.GetKeyID(ctx)
		if err != nil {
			slog.Error("get KMS key ID", "error", err)
			return fmt.Errorf("get KMS key ID: %w", err)
		}
	}

	// Narrow the KMS policy to current PCR0 before any decrypt.
	if err := e.kms.SelfApplyPolicy(ctx, keyID); err != nil {
		slog.Error("apply KMS policy", "error", err)
		return fmt.Errorf("apply KMS policy: %w", err)
	}

	if err := e.staticSecrets.LoadAll(ctx, keyID, paramPrefix); err != nil {
		slog.Error("load secrets from KMS", "error", err)
		return fmt.Errorf("load secrets from KMS: %w", err)
	}
	if err := e.staticSecrets.ExtendPCRs(); err != nil {
		slog.Error("extend PCRs with secret pubkeys", "error", err)
		return fmt.Errorf("extend PCRs with secret pubkeys: %w", err)
	}

	slog.Info("initializing storage")
	e.migrator.storage = e.storage
	if err := e.storage.Init(ctx, keyID, paramPrefix); err != nil {
		slog.Error("init storage", "error", err)
		return fmt.Errorf("init storage: %w", err)
	}

	e.dynamic = NewDynamicSecrets(e.storage, e.metrics, e.staticSecrets, e.checkRuntimeToken)
	if _, err := e.dynamic.Init(ctx); err != nil {
		slog.Warn("load dynamic secrets failed", "error", err)
	}

	if migrationKMSKeyID != "" {
		if err := e.migrator.CompleteMigration(ctx, migrationKMSKeyID); err != nil {
			slog.Error("complete migration", "error", err)
			return fmt.Errorf("complete migration: %w", err)
		}
	}

	e.registerGatedRoutes()

	e.initOK.Store(true)
	slog.Info("init completed successfully")
	SpanOK(initSpan)

	if e.logging != nil && e.logging.shipCh != nil {
		e.logging.aws = e.aws
		go e.logging.RunShipper(ctx)
	}
	if e.tracing != nil && e.tracing.shipCh != nil {
		e.tracing.aws = e.aws
		go e.tracing.RunShipper(ctx)
	}

	return nil
}

func (e *Runtime) Logging() *Logging { return e.logging }
func (e *Runtime) Tracing() *Tracing { return e.tracing }

// IsReady reports whether Init completed successfully. /health uses this to
// distinguish "failed" from "ready" (returns 503 in either non-ready state).
func (e *Runtime) IsReady() bool {
	return e.initOK.Load()
}

func (e *Runtime) AttestationPubkey() string {
	return e.attestation.Pubkey()
}

// Mux is the minimal http.ServeMux subset subsystems write to. Lets Runtime
// transparently wrap their handlers with init-gating middleware.
type Mux interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

type gatedMux struct {
	inner *http.ServeMux
	gate  func(http.Handler) http.Handler
}

func (g *gatedMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	g.inner.Handle(pattern, g.gate(http.HandlerFunc(handler)))
}

// requireInitDone gates handlers that need Init to have populated their
// dependencies (Storage's DEK, DynamicSecrets' static-secret refs).
func (e *Runtime) requireInitDone(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.initDone.Load() {
			http.Error(w, "enclave is still initializing", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireInitOK is stricter: also rejects when Init completed but failed.
// Used for start-migration — running it on a half-initialised enclave would
// write garbage into the new enclave's SSM.
func (e *Runtime) requireInitOK(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.initDone.Load() {
			http.Error(w, "enclave is still initializing", http.StatusServiceUnavailable)
			return
		}
		if !e.initOK.Load() {
			http.Error(w, "enclave init failed — operation refused to prevent state corruption", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RegisterRoutes adds enclave management endpoints to the mux:
//
//	GET    /v1/enclave-info
//	POST   /v1/enclave-metrics
//	GET    /v1/enclave-metrics
//	POST   /v1/start-migration            (gated: requireInitOK)
//	PUT    /v1/storage/{key...}           (gated: requireInitDone)
//	GET    /v1/storage/{key...}           (gated: requireInitDone)
//	DELETE /v1/storage/{key...}           (gated: requireInitDone)
//	GET    /v1/storage                    (gated: requireInitDone)
//	PUT    /v1/secrets/{name}             (gated: requireInitDone)
//	GET    /v1/secrets/{name}             (gated: requireInitDone)
//	DELETE /v1/secrets/{name}             (gated: requireInitDone)
//	GET    /v1/secrets                    (gated: requireInitDone)
//	POST   /v1/logs
//	GET    /v1/enclave-logs
//	POST   /v1/enclave-traces
//	GET    /v1/enclave-traces
func (e *Runtime) RegisterRoutes(mux *http.ServeMux) {
	e.mux = mux
	mux.HandleFunc("GET /v1/enclave-info", e.handleEnclaveInfo)
	mux.HandleFunc("POST /v1/enclave-metrics", e.handleMetricPost)
	mux.HandleFunc("GET /v1/enclave-metrics", e.handleMetricGet)

	// Telemetry endpoints reachable during Init for diagnostics.
	if e.logging != nil {
		e.logging.RegisterRoutes(mux)
	}
	if e.tracing != nil {
		e.tracing.RegisterRoutes(mux)
	}
}

// registerGatedRoutes wires subsystem handlers behind init-state middleware.
// Runs at the end of Init since the subsystems don't exist at startup time.
func (e *Runtime) registerGatedRoutes() {
	if e.mux == nil {
		return
	}
	gated := &gatedMux{inner: e.mux, gate: e.requireInitDone}
	if e.storage != nil {
		e.storage.RegisterRoutes(gated)
	}
	if e.dynamic != nil {
		e.dynamic.RegisterRoutes(gated)
	}
	strict := &gatedMux{inner: e.mux, gate: e.requireInitOK}
	if e.migrator != nil {
		e.migrator.RegisterRoutes(strict)
	}
}

// Middleware signs every response with the ephemeral attestation key
// (BIP-340 Schnorr). A failed Init leaves the enclave half-initialised
// where signing would mislead callers, so we gate on initOK (matches
// IsReady / /health).
func (e *Runtime) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.initOK.Load() || !e.attestation.Ready() {
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
		if sig := e.attestation.Sign(body); sig != "" {
			w.Header().Set("X-Attestation-Signature", sig)
			w.Header().Set("X-Attestation-Pubkey", e.attestation.Pubkey())
		} else {
			w.Header().Set("X-Attestation-Error", "signing-failed")
		}

		w.WriteHeader(rec.status)
		_, _ = w.Write(body)
	})
}

// SetAttestationRegistrar must be called before Init.
func (e *Runtime) SetAttestationRegistrar(r AttestationHashRegistrar) {
	e.attestation.SetRegistrar(r)
}

// handleEnclaveInfo returns 503 with partial JSON during init (so callers
// get meaningful state instead of 502, while curl -sf still fails).
//
// Guard on initOK rather than initDone: initDone fires on Init return
// regardless of outcome, so a failed Init would otherwise fall through
// to the success path and nil-deref subsystems that were never wired.
func (e *Runtime) handleEnclaveInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if !e.initOK.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		initializing := !e.initDone.Load()
		_ = json.NewEncoder(w).Encode(struct {
			Version      string `json:"version"`
			PreviousPCR0 string `json:"previous_pcr0"`
			Initializing bool   `json:"initializing"`
			InitFailed   bool   `json:"init_failed,omitempty"`
		}{
			Version:      Version,
			PreviousPCR0: "",
			Initializing: initializing,
			InitFailed:   !initializing,
		})
		return
	}

	cooldownSeconds, cooldownRemaining, migrationPending := e.migrator.CooldownStatus(r.Context())

	previousPCR0 := ""
	previousPCR0Attestation := ""

	previousPCR0Info, err := e.migrator.GetPreviousPCR0Info(r.Context(), false)
	if err == nil && previousPCR0Info != nil {
		previousPCR0 = previousPCR0Info.PCR0
		previousPCR0Attestation = previousPCR0Info.Attestation
	}

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
		PreviousPCR0:               previousPCR0,
		PreviousPCR0Attestation:    previousPCR0Attestation,
		AttestationPubkey:          e.AttestationPubkey(),
		DynamicSecrets:             e.dynamic.Count(),
		Metrics:                    enclaveMetrics.MetricsSnapshot(),
		MigrationCooldownSeconds:   cooldownSeconds,
		MigrationCooldownRemaining: cooldownRemaining,
		MigrationPending:           migrationPending,
	})
}

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

// responseRecorder buffers a response body so Middleware can Schnorr-sign it.
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

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		duration := time.Since(start)
		slog.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", duration.Milliseconds(),
		)
		enclaveMetrics.Inc(enclaveMetrics.HTTPRequests, "http_requests_total")
		if sw.status >= 400 {
			enclaveMetrics.Inc(enclaveMetrics.HTTPErrors, "http_errors_total")
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func generateRuntimeToken() (string, error) {
	b := make([]byte, 32)
	if _, err := secureRandom(b); err != nil {
		return "", fmt.Errorf("secure random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// secureRandom uses the NSM hardware RNG when running inside an enclave and
// crypto/rand otherwise. Inside an enclave crypto/rand depends on a starved
// kernel entropy pool (no disk, no network, no HID — only RDRAND), so the
// NSM RNG is the only trustworthy source. If /dev/nsm opens but GetRandom
// fails we surface the error rather than fall back to the weak pool.
func secureRandom(b []byte) (int, error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return rand.Read(b)
	}
	defer func() { _ = session.Close() }()
	return session.Read(b)
}
