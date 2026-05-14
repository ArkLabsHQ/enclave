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
	"strings"
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

	keyID, err := e.kms.EnsureKeyID(ctx)
	if err != nil {
		slog.Error("ensure KMS key ID", "error", err)
		return fmt.Errorf("ensure KMS key ID: %w", err)
	}

	if err := e.kms.VerifyKeyAuthorization(ctx, keyID); err != nil {
		slog.Error("verify KMS key admits us", "error", err)
		return fmt.Errorf("verify KMS key admits us: %w", err)
	}

	if err := e.migrator.VerifyPredecessorCommitment(ctx, getPCR0()); err != nil {
		slog.Error("verify predecessor PCR31 commitment", "error", err)
		return fmt.Errorf("verify predecessor PCR31 commitment: %w", err)
	}

	if err := e.staticSecrets.LoadAll(ctx, keyID); err != nil {
		slog.Error("load secrets from KMS", "error", err)
		return fmt.Errorf("load secrets from KMS: %w", err)
	}
	if err := e.staticSecrets.ExtendPCRs(); err != nil {
		slog.Error("extend PCRs with secret pubkeys", "error", err)
		return fmt.Errorf("extend PCRs with secret pubkeys: %w", err)
	}

	slog.Info("initializing storage")
	e.migrator.storage = e.storage
	if err := e.storage.Init(ctx, keyID); err != nil {
		slog.Error("init storage", "error", err)
		return fmt.Errorf("init storage: %w", err)
	}

	e.dynamic = NewDynamicSecrets(e.storage, e.metrics, e.staticSecrets, e.checkRuntimeToken)
	if _, err := e.dynamic.Init(ctx); err != nil {
		slog.Warn("load dynamic secrets failed", "error", err)
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

// isGRPCRequest reports whether r looks like a native gRPC call.
// Native gRPC (and gRPC-Web over HTTP/2) carries an application/grpc*
// Content-Type and uses HTTP/2. Buffering such requests breaks
// server-streaming RPCs and drops the grpc-status / grpc-message trailers.
func isGRPCRequest(r *http.Request) bool {
	if r.ProtoMajor != 2 {
		return false
	}
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
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

		// gRPC streams cannot be buffered — clients verify enclave
		// authenticity via the TLS cert fingerprint embedded in the NSM
		// attestation document, not via X-Attestation-Signature headers.
		if isGRPCRequest(r) {
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

type EnclaveInfo struct {
	Version                    string         `json:"version"`
	PreviousPCR0               string         `json:"previous_pcr0"`
	PreviousPCR0Attestation    string         `json:"previous_pcr0_attestation,omitempty"`
	AttestationPubkey          string         `json:"attestation_pubkey,omitempty"`
	DynamicSecrets             int64          `json:"dynamic_secrets"`
	Metrics                    map[string]any `json:"metrics"`
	MigrationCooldownSeconds   int            `json:"migration_cooldown_seconds"`
	MigrationCooldownRemaining int            `json:"migration_cooldown_remaining,omitempty"`
	MigrationPending           bool           `json:"migration_pending"`
}

type enclaveInitializing struct {
	Version      string `json:"version"`
	PreviousPCR0 string `json:"previous_pcr0"`
	Initializing bool   `json:"initializing"`
}

// handleEnclaveInfo gates on initOK rather than initDone so a failed Init
// does not fall through to the success path and nil-deref subsystems that
// were never wired.
func (e *Runtime) handleEnclaveInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if !e.initOK.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(enclaveInitializing{
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

	_ = json.NewEncoder(w).Encode(EnclaveInfo{
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

func describePCR(index uint) (data []byte, locked bool, err error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, false, fmt.Errorf("open NSM session: %w", err)
	}
	defer func() { _ = session.Close() }()

	resp, err := session.Send(&request.DescribePCR{Index: uint16(index)})
	if err != nil {
		return nil, false, fmt.Errorf("DescribePCR(%d): %w", index, err)
	}
	if resp.Error != "" {
		return nil, false, fmt.Errorf("DescribePCR(%d): NSM error: %s", index, resp.Error)
	}
	if resp.DescribePCR == nil {
		return nil, false, fmt.Errorf("DescribePCR(%d): empty response", index)
	}
	return resp.DescribePCR.Data, resp.DescribePCR.Lock, nil
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

// Flush delegates to the underlying writer's http.Flusher so HTTP/2
// streaming (gRPC server-streaming responses) is not buffered when this
// middleware sits in the chain. Without an explicit Flush method,
// downstream code that does an `(w).(http.Flusher)` type assertion
// would miss the underlying Flusher and never flush mid-stream.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
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
