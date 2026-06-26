// Package runtime is the in-process supervisor that boots inside an AWS
// Nitro Enclave. A single *Runtime owns the TLS edge on :ExtPort, the
// internal loopback listener on :IntPort, the catch-all reverse proxy to
// the user app, and every supporting subsystem (KMS, storage, secrets,
// tracing, logging, migration).
//
// cmd/runtime/main.go constructs a Runtime via New(cfg), wraps it with
// the response-signing and logging middleware, calls Start to bind the
// listeners, then Init to bring up AWS-backed subsystems.
package runtime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"

	"github.com/ArkLabsHQ/introspector-enclave/runtime/nitriding"
)

const (
	acmeCertCacheDir = "cert-cache"
	// acmeStagingDirectoryURL is Let's Encrypt's staging ACME endpoint — an
	// untrusted root with high rate limits, used for testing.
	acmeStagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	certificateOrg          = "AWS Nitro enclave application"
	certificateValidity     = time.Hour * 24 * 356

	// Routes served on the public TLS mux (pubSrv) and the internal HTTP
	// mux (privSrv). Paths are scoped under /enclave so they don't collide
	// with the user app's surface area, which is forwarded via the catch-all
	// reverse proxy at pathProxy.
	pathRoot        = "/enclave"
	pathAttestation = "/enclave/attestation"
	pathState       = "/enclave/state"
	pathHash        = "/enclave/hash"
	pathReady       = "/enclave/ready"
	pathProfiling   = "/enclave/debug"
	pathConfig      = "/enclave/config"
	pathProxy       = "/*"

	hashPrefix    = "sha256:"
	hashSeparator = ";"
)

var (
	errNoKeyMaterial  = errors.New("no key material registered")
	errCfgMissingFQDN = errors.New("config is missing FQDN")
	errCfgMissingPort = errors.New("config is missing port")
)

// Mux is the minimal http.ServeMux subset the subsystems write to.
// Runtime wraps their handlers with init-gating middleware transparently.
type Mux interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// Runtime is the singleton supervisor that owns every long-lived piece of
// state inside the enclave: the HTTP servers, the reverse proxy, the
// attestation key, the KMS / storage / secrets / migration subsystems, and
// the OTEL metrics + logging + tracing exporters.
type Runtime struct {
	sync.RWMutex // guards keyMaterial

	// Configuration and auth.
	cfg          *Config
	runtimeToken string // bearer token for /v1/* admin endpoints; "" disables auth

	// HTTP server state.
	pubSrv   *http.Server           // external TLS listener on :ExtPort
	privSrv  *http.Server           // internal loopback HTTP listener on :IntPort
	revProxy *httputil.ReverseProxy // catch-all forwarder to the user app
	mux      *http.ServeMux         // admin mux captured at RegisterRoutes; gated routes wire here

	// tlsGetCert is the resolved TLS cert source — installed by configureTLS
	// during Init, read by the pubSrv GetCertificate callback once tlsReady closes.
	tlsGetCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// Lifecycle channels.
	ready        chan bool     // closed when the user app POSTs /enclave/ready
	stop         chan bool     // closed by Stop() to unwind goroutines
	listenErr    chan error    // first listener bind/serve error; consumed by main
	storageReady chan struct{} // closed by Init once Storage initialization has settled
	tlsReady     chan struct{} // closed once configureTLS installs the cert source

	// Init state — set by Init, read by gating middleware and handlers.
	initDone atomic.Bool // happens-before fence: Init returned (success or failure)
	initOK   atomic.Bool // Init returned without error

	// rollbackHalt is set by the freshness anchor's per-read version-floor check
	// when it detects a rollback of the K/V store; flips /health to 503 and
	// refuses RESP ops.
	rollbackHalt atomic.Bool

	// Upstream app state — set by MarkUpstreamExited (called from
	// cmd/runtime/main.go when the user app exits).
	upstreamExited atomic.Bool
	upstreamErr    atomic.Value // string; "" when no error or not exited

	// Attestation state.
	hashes      *AttestationHashes // embedded in every NSM attestation doc
	keyMaterial any                // arbitrary peer-syncable state

	// Subsystems — built in Init, registered via RegisterRoutes.
	aws           *AWSClient
	metrics       *Metrics
	tracing       *Tracing
	logging       *Logging
	attestation   *Attestation
	kms           *KMS
	staticSecrets *StaticSecrets
	stateOrigin   *StateOrigin
	storage       *Storage
	kvStore       *KVStore
	respSrv       *RESPServer
	lineage       *PCR0Lineage
	genesis       *GenesisInfo // cached deployment descriptor for /v1/enclave-info
	migrator      *Migrator
	environment   *Environment
	signature     *Signature
}

// New returns a Runtime safe to use for serving management endpoints.
// cfg may be nil in unit tests that don't bring up the HTTP listeners;
// otherwise New eagerly builds the chi muxes, mounts the /enclave/* and
// /v1/* routes, and wires the catch-all revProxy to the user app.
//
// Call Init separately to bring up the AWS-backed subsystems, and Start
// to bind the listeners.
func New(cfg *Config) (*Runtime, error) {
	token, err := generateRuntimeToken()
	if err != nil {
		return nil, fmt.Errorf("generate supervisor token: %w", err)
	}
	if enclaveMetrics == nil {
		// cmd/runtime/main.go calls InitMetrics() first; tests skip that.
		enclaveMetrics = NewMetrics()
	}
	r := &Runtime{
		cfg:          cfg,
		metrics:      enclaveMetrics,
		attestation:  NewAttestation(),
		signature:    NewSignature(),
		runtimeToken: token,
		storageReady: make(chan struct{}),
		tlsReady:     make(chan struct{}),
	}
	r.logging = NewLogging(enclaveMetrics, nil, r.checkRuntimeToken)
	r.tracing = NewTracing(enclaveMetrics, nil, r.checkRuntimeToken)
	if cfg != nil {
		if err := r.configureHTTPServers(); err != nil {
			return nil, fmt.Errorf("configure HTTP servers: %w", err)
		}
	}
	return r, nil
}

// Init brings up the AWS-backed subsystems: AWS clients, KMS key
// authorization, the attestation key, secrets, the K/V store,
// and the migration handshake. May block on KMS. Idempotent on the
// initDone fence — handlers can safely read subsystem fields once it
// returns, regardless of success.
//
// Start must run before Init so /v1/enclave-info and the telemetry
// endpoints remain reachable while subsystems come up.
func (e *Runtime) Init(ctx context.Context) error {
	defer e.initDone.Store(true)
	// storageReady unblocks the ACME cert cache (wired by configureTLS) once
	// Storage initialization has settled — whether it succeeded or not.
	defer close(e.storageReady)

	ctx, initSpan := e.tracing.Span(ctx, "init")
	defer initSpan.End()

	aws, err := NewAWSClient(ctx)
	if err != nil {
		slog.Error("init AWS clients", "error", err)
		return fmt.Errorf("init AWS clients: %w", err)
	}
	e.aws = aws

	// Install the TLS cert source now that the AWS client is up: this reads
	// the deploy-time TLS config from SSM and unblocks the pubSrv listener.
	if err := e.configureTLS(ctx); err != nil {
		slog.Error("configure TLS", "error", err)
		return fmt.Errorf("configure TLS: %w", err)
	}

	// Pull the PCR0 signature Tofu wrote to SSM during apply. Non-fatal:
	// if signing isn't provisioned for this deployment, /enclave/signature
	// stays at 503 but everything else still boots.
	e.signature.Load(ctx, e.aws.SSM)

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

	e.storage = NewStorage(e.kms)
	e.kvStore = NewKVStore(e.kms, nil)
	e.kvStore.anchor = &FreshnessAnchor{kv: e.kvStore, s3: e.kms.aws.S3, window: anchorWindow, halt: &e.rollbackHalt}
	e.respSrv = NewRESPServer(e.kvStore, e.runtimeToken)
	e.respSrv.halt = &e.rollbackHalt
	e.lineage = &PCR0Lineage{s3: e.kms.aws.S3, ssm: e.aws.SSM, window: anchorWindow}

	if err := e.attestation.Init(); err != nil {
		slog.Error("init attestation", "error", err)
		return fmt.Errorf("init attestation: %w", err)
	}

	// State-origin provenance (issue #131), shared with the Migrator.
	e.stateOrigin = NewStateOrigin(e.aws.SSM, e.staticSecrets.Secrets())
	if err := e.lineage.Init(ctx); err != nil {
		slog.Error("init PCR0 lineage", "error", err)
		return fmt.Errorf("init PCR0 lineage: %w", err)
	}
	e.stateOrigin.lineage = e.lineage

	// Migrator needs Storage too, but Storage isn't fully initialized yet.
	// Wire it in after Storage.Init below; /v1/start-migration is gated on
	// initOK so the late wire-up is safe.
	e.migrator = NewMigrator(e.aws, e.kms, e.staticSecrets, nil, e.checkRuntimeToken)
	e.migrator.stateOrigin = e.stateOrigin

	// Establish the startup-state protocol (issue #131): classify → ensureKey →
	// verify → load → write receipt. PeekKeyID reads the key without minting one.
	ownPCR0 := getPCR0()
	if ownPCR0 == "" {
		slog.Error("read PCR0 from NSM")
		return fmt.Errorf("could not read PCR0 from NSM")
	}
	rawKeyID, err := e.kms.PeekKeyID(ctx)
	if err != nil {
		slog.Error("peek KMS key ID", "error", err)
		return fmt.Errorf("peek KMS key ID: %w", err)
	}
	if err := e.stateOrigin.Establish(ctx, rawKeyID, ownPCR0,
		func() (string, error) { return e.ensureActiveKey(ctx, ownPCR0) },
		func(keyID string) error { return e.loadState(ctx, keyID) },
	); err != nil {
		slog.Error("establish startup state", "error", err)
		return err
	}
	e.genesis = loadGenesisInfo(ctx, e.aws.SSM)

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

// ensureActiveKey returns the active KMS key ID — minting a PCR0-locked one on
// genesis — after verifying its policy and any predecessor handoff.
func (e *Runtime) ensureActiveKey(ctx context.Context, ownPCR0 string) (string, error) {
	keyID, err := e.kms.EnsureKeyID(ctx)
	if err != nil {
		return "", fmt.Errorf("ensure KMS key ID: %w", err)
	}
	if err := e.kms.VerifyKeyAuthorization(ctx, keyID); err != nil {
		return "", fmt.Errorf("verify KMS key admits us: %w", err)
	}
	if err := e.migrator.VerifyPredecessorCommitment(ctx, ownPCR0); err != nil {
		return "", fmt.Errorf("verify predecessor PCR31 commitment: %w", err)
	}
	return keyID, nil
}

// loadState decrypts the runtime-owned secrets and storage DEK under keyID,
// extends the secret PCRs, and brings up Storage.
func (e *Runtime) loadState(ctx context.Context, keyID string) error {
	if err := e.staticSecrets.LoadAll(ctx, keyID); err != nil {
		return fmt.Errorf("load secrets from KMS: %w", err)
	}
	if err := e.staticSecrets.ExtendPCRs(); err != nil {
		return fmt.Errorf("extend PCRs with secret pubkeys: %w", err)
	}
	slog.Info("initializing storage")
	e.migrator.storage = e.storage
	if err := e.storage.Init(ctx, keyID); err != nil {
		return fmt.Errorf("init storage: %w", err)
	}
	if err := e.kvStore.Init(ctx, keyID); err != nil {
		return fmt.Errorf("init kv store: %w", err)
	}
	if e.kvStore.Enabled() {
		if err := e.kvStore.anchor.Init(ctx); err != nil {
			return fmt.Errorf("init freshness anchor: %w", err)
		}
		e.stateOrigin.anchorBucket = e.kvStore.anchor.bucket // for the genesis descriptor
		// Boot gate: fail closed if the live store is already rolled back.
		if err := e.kvStore.anchor.Establish(ctx); err != nil {
			return fmt.Errorf("freshness anchor establish: %w", err)
		}
	}
	return nil
}

// Start binds the public TLS listener, the private HTTP listener, and the
// TAP networking to the EC2 host. Returns once the listeners are spawned;
// errors during ListenAndServe surface via slog.Error from the listener
// goroutines.
func (e *Runtime) Start() error {
	const errPrefix = "failed to start enclave HTTP server"

	if nitriding.InEnclave() {
		if err := nitriding.SetFdLimit(e.cfg.FdCur, e.cfg.FdMax); err != nil {
			slog.Warn("set fd limit", "error", err)
		}
		if err := nitriding.ConfigureLoIface(); err != nil {
			return fmt.Errorf("%s: %w", errPrefix, err)
		}
	}
	go nitriding.RunNetworking(e.cfg.HostProxyPort, e.stop)

	// The TLS cert source is installed later by configureTLS (during Init,
	// after the deploy-time TLS config is read from SSM). Start only binds
	// the listener; pubSrv.TLSConfig already carries the getCertificate callback.
	return e.runListeners()
}

// Stop closes the lifecycle channel and shuts down both HTTP servers.
func (e *Runtime) Stop() error {
	if e.stop != nil {
		close(e.stop)
		e.stop = nil
	}
	if e.privSrv != nil {
		if err := e.privSrv.Shutdown(context.Background()); err != nil {
			return err
		}
	}
	if e.pubSrv != nil {
		if err := e.pubSrv.Shutdown(context.Background()); err != nil {
			return err
		}
	}
	return nil
}

// RegisterRoutes mounts Runtime's admin endpoints on mux. POST routes
// follow the OTLP/HTTP spec (/v1/{metrics,traces,logs}) so standard OTEL
// SDK exporters work without URL overrides. GET routes carry the
// `enclave-` prefix to distinguish introspection from OTLP ingest.
//
//	GET    /v1/enclave-info
//	POST   /v1/metrics                    (OTLP ingest)
//	GET    /v1/enclave-metrics            (JSON snapshot)
//	POST   /v1/start-migration            (gated: requireInitOK)
//	POST   /v1/logs                       (OTLP ingest)
//	GET    /v1/enclave-logs               (JSON history)
//	POST   /v1/traces                     (OTLP ingest)
//	GET    /v1/enclave-traces             (JSON history)
//
// Subsystem-owned routes are added later by registerGatedRoutes once Init
// has built those subsystems.
func (e *Runtime) RegisterRoutes(mux *http.ServeMux) {
	e.mux = mux
	mux.Handle("GET /v1/enclave-info", enclaveInfoHandler(e))
	mux.HandleFunc("POST /v1/metrics", e.handleMetricPost)
	mux.HandleFunc("GET /v1/enclave-metrics", e.handleMetricGet)

	// Telemetry endpoints stay reachable while Init runs, for diagnostics.
	if e.logging != nil {
		e.logging.RegisterRoutes(mux)
	}
	if e.tracing != nil {
		e.tracing.RegisterRoutes(mux)
	}
}

// PubMux returns the public chi router so consumers can mount additional
// routes on the external TLS listener.
func (e *Runtime) PubMux() *chi.Mux { return e.pubSrv.Handler.(*chi.Mux) }

// UseMiddleware wraps both pubSrv (external TLS) and privSrv (internal
// loopback) handlers with the given http.Handler middleware. Applied
// after configureHTTPServers so the wrap covers every route on both
// listeners.
func (e *Runtime) UseMiddleware(mw func(http.Handler) http.Handler) {
	e.pubSrv.Handler = mw(e.pubSrv.Handler)
	e.privSrv.Handler = mw(e.privSrv.Handler)
}

// Middleware buffers each response and signs it with the ephemeral
// attestation key (BIP-340 Schnorr), attaching the signature and public
// key as response headers. Skipped when Init has not completed
// successfully (so callers see no signature rather than a misleading
// one) and when the request is gRPC (signing requires buffering the
// entire body, which would break streaming RPCs and drop trailers).
func (e *Runtime) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.initOK.Load() || !e.attestation.Ready() {
			next.ServeHTTP(w, r)
			return
		}
		// gRPC clients verify the enclave via the TLS cert fingerprint
		// embedded in the NSM attestation document — not via these
		// per-response signature headers — so the bypass is safe.
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

func (e *Runtime) RuntimeToken() string { return e.runtimeToken }

// checkRuntimeToken validates the Authorization: Bearer <token> header against
// the runtime token; subsystems pass it as their auth callback.
func (e *Runtime) checkRuntimeToken(w http.ResponseWriter, r *http.Request) bool {
	if e.runtimeToken == "" {
		return true
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

func (e *Runtime) Logging() *Logging         { return e.logging }
func (e *Runtime) Tracing() *Tracing         { return e.tracing }
func (e *Runtime) AttestationPubkey() string { return e.attestation.Pubkey() }

// IsReady reports whether Init completed successfully. /health uses this
// to distinguish "ready" from "initializing" / "failed".
func (e *Runtime) IsReady() bool { return e.initOK.Load() && !e.rollbackHalt.Load() }

// MarkUpstreamExited records that the user app has exited. The runtime
// keeps running so /v1/start-migration and other admin endpoints stay
// reachable — without this latch, cmd/runtime/main.go used to call stop()
// and tear the whole runtime down (issue #122). Pass nil for a clean exit,
// a non-nil error otherwise.
func (e *Runtime) MarkUpstreamExited(err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	e.upstreamErr.Store(msg)
	e.upstreamExited.Store(true)
}

// UpstreamExited returns whether the user app has exited and the error
// string from its exit. The error is empty when the app exited cleanly or
// has not exited at all (check the bool first).
func (e *Runtime) UpstreamExited() (bool, string) {
	if !e.upstreamExited.Load() {
		return false, ""
	}
	if v := e.upstreamErr.Load(); v != nil {
		if s, ok := v.(string); ok {
			return true, s
		}
	}
	return true, ""
}

// SetAttestationRegistrar must be called before Init.
func (e *Runtime) SetAttestationRegistrar(r AttestationHashRegistrar) {
	e.attestation.SetRegistrar(r)
}

// SetAttestationKeyHash registers the SHA-256 hash of the user app's
// attestation key for inclusion in NSM attestation documents.
func (e *Runtime) SetAttestationKeyHash(hash [32]byte) {
	copy(e.hashes.appKeyHash[:], hash[:])
}

// SetKeyMaterial registers the enclave's key material so an identical
// peer enclave can sync state. Guarded by Runtime.RWMutex.
func (e *Runtime) SetKeyMaterial(km any) {
	e.Lock()
	defer e.Unlock()
	e.keyMaterial = km
}

// KeyMaterial returns the registered key material or errNoKeyMaterial.
func (e *Runtime) KeyMaterial() (any, error) {
	e.RLock()
	defer e.RUnlock()
	if e.keyMaterial == nil {
		return nil, errNoKeyMaterial
	}
	return e.keyMaterial, nil
}

// configureHTTPServers does the shared setup (cfg validation, lifecycle
// channels, the shared admin handler) and dispatches to the per-listener
// configurators. The admin handler is mounted unwrapped; signing and
// logging are applied once by UseMiddleware after New returns.
func (e *Runtime) configureHTTPServers() error {
	if err := e.cfg.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	e.hashes = new(AttestationHashes)
	e.stop = make(chan bool)
	e.ready = make(chan bool)
	e.listenErr = make(chan error, 2) // pubSrv + privSrv

	// Boost the default idle-connection pool — see brave/nitriding-daemon#2.
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 500
	http.DefaultTransport.(*http.Transport).MaxIdleConns = 500

	adminMux := http.NewServeMux()
	e.RegisterRoutes(adminMux)
	adminMux.Handle("GET /health", healthHandler(e))

	e.configureExternalHttpServer(adminMux)
	e.configureInternalHttpServer(adminMux)
	return nil
}

// protocolSwitchTransport forwards each proxied request to the user app over
// the same HTTP version the client used — h2c for HTTP/2 inbound, HTTP/1.1 for
// HTTP/1.1 — via the inbound ProtoMajor that ReverseProxy preserves on RoundTrip.
type protocolSwitchTransport struct {
	h1  http.RoundTripper
	h2c http.RoundTripper
}

func (t *protocolSwitchTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.ProtoMajor == 1 {
		return t.h1.RoundTrip(r)
	}
	return t.h2c.RoundTrip(r)
}

// upstreamTransport builds the reverse-proxy transport for the runtime->app
// hop, selected by ENCLAVE_NITRIDING_UPSTREAM: "h2c" or "h1" pin a single
// protocol; "auto" (the default) matches the inbound protocol per request.
// h2c is required for gRPC; h1 suits a plain HTTP/1.1 app.
func upstreamTransport(mode string) http.RoundTripper {
	h1 := &http.Transport{}
	h2c := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	switch mode {
	case "h2c":
		return h2c
	case "h1":
		return h1
	default:
		return &protocolSwitchTransport{h1: h1, h2c: h2c}
	}
}

// corsWildcard wraps an http.Handler to send permissive CORS headers on every
// response and short-circuit OPTIONS preflight with 204. Used on the runtime's
// /v1/* admin endpoints so a browser SPA can call them cross-origin (e.g.,
// GET /v1/enclave-info for attestation). The catch-all upstream proxy is not
// wrapped — the user app sets its own CORS on its own responses.
func corsWildcard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "*")
		h.Set("Access-Control-Allow-Headers", "*")
		h.Set("Access-Control-Expose-Headers", "*")
		h.Set("Access-Control-Max-Age", "600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// configureExternalHttpServer builds pubSrv: the external TLS listener
// on :ExtPort that fronts the public attestation API, the admin routes,
// and the catch-all reverse proxy to the user app.
func (e *Runtime) configureExternalHttpServer(admin http.Handler) {
	e.pubSrv = &http.Server{Handler: chi.NewRouter()}
	pm := e.pubSrv.Handler.(*chi.Mux)

	if e.cfg.UseProfiling {
		pm.Mount(pathProfiling, chimw.Profiler())
	}
	if e.cfg.DisableKeepAlives {
		e.pubSrv.SetKeepAlivesEnabled(false)
	}

	pm.Get(pathAttestation, attestationHandler(e.cfg.UseProfiling, e.hashes))
	pm.Get(pathRoot, rootHandler(e.cfg))
	pm.Get(pathConfig, configHandler(e.cfg))

	pm.Handle("/v1/*", corsWildcard(admin))
	pm.Handle("/health", admin)

	// The upstream transport is selected by ENCLAVE_NITRIDING_UPSTREAM (see
	// upstreamTransport). FlushInterval=-1 keeps server-streaming unbuffered.
	if e.cfg.AppWebSrv != nil {
		e.revProxy = httputil.NewSingleHostReverseProxy(e.cfg.AppWebSrv)
		e.revProxy.BufferPool = nitriding.NewBufPool()
		e.revProxy.Transport = upstreamTransport(e.cfg.UpstreamProtocol)
		e.revProxy.FlushInterval = -1
		e.revProxy.ModifyResponse = func(*http.Response) error {
			enclaveMetrics.Inc(enclaveMetrics.AppProxiedRequests, "enclave_app_proxied_requests_total")
			return nil
		}
		e.revProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			enclaveMetrics.Inc(enclaveMetrics.AppProxiedErrors, "enclave_app_proxied_errors_total")
			w.WriteHeader(http.StatusBadGateway)
		}
		pm.Handle(pathProxy, e.revProxy)
	}

	// The TLS cert is resolved per-handshake by getCertificate, which blocks
	// until configureTLS (run during Init, after the SSM read) installs the
	// cert source. acme-tls/1 is advertised so ACME TLS-ALPN-01 challenges work.
	e.pubSrv.TLSConfig = &tls.Config{
		GetCertificate: e.getCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1", "acme-tls/1"},
	}
}

// configureInternalHttpServer builds privSrv: the loopback HTTP listener
// on 127.0.0.1:IntPort. Serves the peer-keysync and readiness endpoints
// plus the same admin routes as pubSrv so the user app can call back
// over plain HTTP from the same enclave process.
func (e *Runtime) configureInternalHttpServer(admin http.Handler) {
	e.privSrv = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", e.cfg.IntPort),
		Handler: chi.NewRouter(),
	}
	im := e.privSrv.Handler.(*chi.Mux)

	im.Get(pathReady, readyHandler(e))
	im.Get(pathState, getStateHandler(e))
	im.Put(pathState, putStateHandler(e))
	im.Post(pathHash, hashHandler(e))

	// Admin routes (shared handler from configureHTTPServers).
	im.Handle("/v1/*", admin)
	im.Handle("/health", admin)
}

// runListeners spawns the goroutines that bind the private and public HTTP
// servers. Bind / serve failures are pushed onto e.listenErr so cmd/runtime
// can exit non-zero — silently leaking a listener-less process would let
// Init complete and the user app start with no external reachability.
func (e *Runtime) runListeners() error {
	slog.Info("starting private listener", "addr", e.privSrv.Addr)
	go func() {
		if err := e.privSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case e.listenErr <- fmt.Errorf("private listener: %w", err):
			default:
			}
		}
	}()

	go func() {
		if e.cfg.WaitForApp {
			<-e.ready
			slog.Info("application signalled ready, starting public listener")
		}
		lis, err := e.externalListener()
		if err != nil {
			select {
			case e.listenErr <- fmt.Errorf("listen on external port: %w", err):
			default:
			}
			return
		}
		if err := e.pubSrv.ServeTLS(lis, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case e.listenErr <- fmt.Errorf("public listener: %w", err):
			default:
			}
		}
	}()

	go e.serveRESP()
	return nil
}

// serveRESP brings up the RESP listener (reusing the public server's
// attestation-bound TLS) once init settles, if a port and K/V table are
// configured. A bind/serve failure is logged but non-fatal to the runtime.
func (e *Runtime) serveRESP() {
	<-e.storageReady
	port := respPort()
	if port == 0 || !e.kvStore.Enabled() {
		slog.Info("RESP listener disabled", "port", port, "kv_enabled", e.kvStore.Enabled())
		return
	}
	addr := fmt.Sprintf(":%d", port)
	raw, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("RESP listener bind failed", "addr", addr, "error", err)
		return
	}
	lis := tls.NewListener(raw, e.pubSrv.TLSConfig)
	slog.Info("starting RESP listener", "addr", addr)
	if err := e.respSrv.Serve(lis); err != nil {
		slog.Error("RESP listener exited", "error", err)
	}
}

// ListenErr returns a channel that fires once if either listener fails to
// bind or serves an unexpected error. cmd/runtime selects on it alongside
// the child-process and signal channels and exits non-zero on receive.
func (e *Runtime) ListenErr() <-chan error { return e.listenErr }

// externalListener returns the listener for the external TLS port, either
// AF_VSOCK or AF_INET depending on Config.UseVsockForExtPort.
func (e *Runtime) externalListener() (net.Listener, error) {
	if e.cfg.UseVsockForExtPort {
		return vsock.Listen(uint32(e.cfg.ExtPort), nil)
	}
	return net.Listen("tcp", fmt.Sprintf(":%d", e.cfg.ExtPort))
}

// getCertificate is the pubSrv TLS GetCertificate callback. It blocks until
// configureTLS (run during Init) installs the cert source, then delegates.
// The first real handshake happens after Init, so the wait is normally a
// no-op; a handshake racing Init waits rather than failing.
func (e *Runtime) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	select {
	case <-e.tlsReady:
	case <-hello.Context().Done():
		return nil, hello.Context().Err()
	}
	return e.certForHello(hello)
}

// certForHello resolves the TLS certificate for a ClientHello. A client
// reaching the enclave by IP — the supervisor's watchdog, observability, and
// migration probes all hit it on loopback — sends no SNI, and in ACME mode
// autocert rejects a nameless ClientHello. The enclave serves exactly one
// FQDN, so a nameless handshake resolves to it instead of failing.
func (e *Runtime) certForHello(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == "" && e.cfg.FQDN != "" {
		h := *hello
		h.ServerName = e.cfg.FQDN
		return e.tlsGetCert(&h)
	}
	return e.tlsGetCert(hello)
}

// configureTLS reads the deploy-time TLS settings from SSM (published by tofu
// from enclave.yaml's tls: block) and installs the cert source — self-signed
// or ACME — then unblocks getCertificate. It runs during Init because the SSM
// read needs the AWS client; Start only binds the listener.
func (e *Runtime) configureTLS(ctx context.Context) error {
	t, err := loadDeployTLSConfig(ctx, e.aws.SSM)
	if err != nil {
		return err
	}
	e.cfg.FQDN = t.FQDN
	e.cfg.UseACME = t.UseACME
	e.cfg.ACMEDirectory = t.Directory
	e.cfg.ACMEEmail = t.Email
	e.cfg.ACMECA = t.CA

	if e.cfg.UseACME {
		slog.Info("TLS: ACME enabled", "fqdn", e.cfg.FQDN, "directory", e.cfg.ACMEDirectory)
		err = e.configureACME()
	} else {
		slog.Info("TLS: self-signed certificate", "fqdn", e.cfg.FQDN)
		err = e.genSelfSignedCert()
	}
	if err != nil {
		return err
	}
	close(e.tlsReady)
	return nil
}

// genSelfSignedCert generates an ECDSA-P256 leaf cert, records its
// fingerprint in the attestation hashes (so clients can pin it against
// the NSM document), and installs it as the tlsGetCert source.
func (e *Runtime) genSelfSignedCert() error {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate cert key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate cert serial: %w", err)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{certificateOrg}},
		DNSNames:              []string{e.cfg.FQDN},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		return errors.New("encode certificate to PEM")
	}
	if err := e.setCertFingerprint(pemCert); err != nil {
		return err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		return errors.New("encode private key to PEM")
	}
	cert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		return fmt.Errorf("load X509 key pair: %w", err)
	}
	e.tlsGetCert = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &cert, nil
	}
	return nil
}

// acmeClientForDirectory returns the acme.Client autocert should use for the
// given directory selector, or nil to let autocert default to Let's Encrypt
// production. A value beginning with "https://" is a literal ACME directory URL
// (a private or test ACME server such as Pebble); "letsencrypt-staging" maps to
// the Let's Encrypt staging directory; anything else returns (nil, nil).
//
// When caPEM is non-empty it is installed as the sole root for the client's
// HTTPS transport, so the enclave can verify a private ACME server's own
// (non-public) API certificate. caPEM is irrelevant for the public Let's
// Encrypt endpoints, which chain to the system roots baked into the EIF.
func acmeClientForDirectory(directory, caPEM string) (*acme.Client, error) {
	var dirURL string
	switch {
	case strings.HasPrefix(directory, "https://"):
		dirURL = directory
	case directory == "letsencrypt-staging":
		dirURL = acmeStagingDirectoryURL
	default:
		return nil, nil
	}
	client := &acme.Client{DirectoryURL: dirURL}
	if caPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("ENCLAVE_NITRIDING_ACME_CA: no certificates parsed")
		}
		client.HTTPClient = &http.Client{
			Timeout: 90 * time.Second,
			Transport: newACMERoundTripper(&http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			}),
		}
	}
	return client, nil
}

// acmeRoundTripper is the ACME client's HTTP transport. It works around Pebble
// omitting the Location header on its finalize-order response, which leaves
// x/crypto/acme unable to poll the order: the order URL, remembered from an
// earlier Location header, is re-attached to any response missing one. A no-op
// against a directory that sets Location, such as real Let's Encrypt.
type acmeRoundTripper struct {
	base http.RoundTripper
	mu   sync.Mutex
	urls map[string]string // resource ID (trailing path segment) -> resource URL
}

func newACMERoundTripper(base http.RoundTripper) *acmeRoundTripper {
	return &acmeRoundTripper{base: base, urls: make(map[string]string)}
}

func lastPathSegment(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func (rt *acmeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		slog.Warn("ACME http", "method", req.Method, "url", req.URL.String(), "error", err)
		return resp, err
	}

	loc := resp.Header.Get("Location")
	rt.mu.Lock()
	if loc != "" {
		rt.urls[lastPathSegment(loc)] = loc
	} else if known := rt.urls[lastPathSegment(req.URL.Path)]; known != "" {
		resp.Header.Set("Location", known)
		loc = known
	}
	rt.mu.Unlock()

	slog.Info("ACME http",
		"method", req.Method, "url", req.URL.String(), "status", resp.StatusCode, "location", loc)
	return resp, err
}

// configureACME wires Let's Encrypt as the TLS cert source via autocert.
// Inside an enclave the cert is persisted in the encrypted Storage subsystem
// (acmeStorageCache) so reboots and migrations reuse it instead of re-issuing;
// outside an enclave a local DirCache is used. The pubSrv TLS config already
// advertises acme-tls/1, so TLS-ALPN-01 challenges work.
func (e *Runtime) configureACME() error {
	var cache autocert.Cache = &acmeStorageCache{
		ready:   e.storageReady,
		storage: func() *Storage { return e.storage },
	}
	if !nitriding.InEnclave() {
		cache = autocert.DirCache(acmeCertCacheDir)
	}
	mgr := autocert.Manager{
		Cache:      cache,
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(e.cfg.FQDN),
		Email:      e.cfg.ACMEEmail,
	}
	client, err := acmeClientForDirectory(e.cfg.ACMEDirectory, e.cfg.ACMECA)
	if err != nil {
		return err
	}
	if client != nil {
		mgr.Client = client
	}
	e.tlsGetCert = mgr.GetCertificate

	// Block on the cert appearing in the cache before computing its
	// fingerprint. autocert populates the cache asynchronously after the
	// first TLS handshake.
	go func() {
		var raw []byte
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			got, err := cache.Get(ctx, e.cfg.FQDN)
			cancel()
			if err == nil {
				raw = got
				break
			}
			time.Sleep(5 * time.Second)
		}
		if err := e.setCertFingerprint(raw); err != nil {
			slog.Error("set cert fingerprint", "error", err)
		}
	}()
	return nil
}

// setCertFingerprint extracts the SHA-256 fingerprint of the first
// non-CA certificate in raw and stores it in e.hashes.tlsKeyHash so
// it appears in NSM attestation documents.
func (e *Runtime) setCertFingerprint(raw []byte) error {
	if e.cfg.MockCertFp != "" {
		hash, err := hex.DecodeString(e.cfg.MockCertFp)
		if err != nil {
			return errors.New("decode mock cert fingerprint")
		}
		copy(e.hashes.tlsKeyHash[:], hash)
		return nil
	}
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			return errors.New("pem.Decode found no PEM data")
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("parse certificate: %w", err)
			}
			if !cert.IsCA {
				e.hashes.tlsKeyHash = sha256.Sum256(cert.Raw)
				return nil
			}
		}
		if len(rest) == 0 {
			return nil
		}
		raw = rest
	}
}

// LoggingMiddleware emits a structured slog entry for each request and
// increments the request / error counters. Wraps the response writer in
// a statusWriter to capture the final status code without buffering.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		slog.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		enclaveMetrics.Inc(enclaveMetrics.HTTPRequests, "http_requests_total")
		if sw.status >= 400 {
			enclaveMetrics.Inc(enclaveMetrics.HTTPErrors, "http_errors_total")
		}
	})
}

// responseRecorder buffers a response body and status so Middleware can
// sign the body before forwarding to the real ResponseWriter.
type responseRecorder struct {
	headers http.Header
	body    *bytes.Buffer
	status  int
}

func (r *responseRecorder) Header() http.Header         { return r.headers }
func (r *responseRecorder) WriteHeader(code int)        { r.status = code }
func (r *responseRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *responseRecorder) ReadFrom(s io.Reader) (int64, error) {
	return io.Copy(r.body, s)
}

// statusWriter wraps http.ResponseWriter to expose the final status code
// for LoggingMiddleware. Delegates Flush so HTTP/2 streaming (gRPC
// server-streaming responses) is not buffered when this middleware sits
// in the chain.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// isGRPCRequest reports whether r is a native gRPC or gRPC-Web call.
// Native gRPC (application/grpc*) requires HTTP/2; gRPC-Web
// (application/grpc-web*) rides either HTTP/1.1 or HTTP/2. Buffering
// either breaks server-streaming — native gRPC also loses its
// grpc-status / grpc-message trailers — so the response-signing
// middleware needs to short-circuit for both.
func isGRPCRequest(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/grpc-web") {
		return true
	}
	if r.ProtoMajor != 2 {
		return false
	}
	return strings.HasPrefix(ct, "application/grpc")
}

// gatedMux wraps an http.ServeMux so every HandleFunc call is rewrapped
// in a gating middleware (e.g. requireInitDone or requireInitOK).
type gatedMux struct {
	inner *http.ServeMux
	gate  func(http.Handler) http.Handler
}

func (g *gatedMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	g.inner.Handle(pattern, g.gate(http.HandlerFunc(handler)))
}

// requireInitDone rejects requests until Init returns (success or
// failure). Used for handlers that nil-deref subsystems built in Init.
func (e *Runtime) requireInitDone(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.initDone.Load() {
			http.Error(w, "enclave is still initializing", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireInitOK is stricter than requireInitDone: also rejects when Init
// completed but failed. Used for /v1/start-migration — running it on a
// half-initialized enclave would write garbage into the new enclave's SSM.
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

// registerGatedRoutes wires the subsystems' routes behind init-state
// middleware. Called at the end of Init when those subsystems exist.
func (e *Runtime) registerGatedRoutes() {
	if e.mux == nil {
		return
	}
	strict := &gatedMux{inner: e.mux, gate: e.requireInitOK}
	if e.migrator != nil {
		e.migrator.RegisterRoutes(strict)
	}
}

// lockPCR pins a PCR so further ExtendPCR calls are rejected by the NSM.
func lockPCR(index uint) error {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open NSM session: %w", err)
	}
	defer func() { _ = session.Close() }()

	resp, err := session.Send(&request.LockPCR{Index: uint16(index)})
	if err != nil {
		return fmt.Errorf("LockPCR(%d): %w", index, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("LockPCR(%d): NSM error: %s", index, resp.Error)
	}
	return nil
}

// extendPCR appends data to PCR[index]'s rolling hash.
func extendPCR(index uint, data []byte) error {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open NSM session: %w", err)
	}
	defer func() { _ = session.Close() }()

	resp, err := session.Send(&request.ExtendPCR{Index: uint16(index), Data: data})
	if err != nil {
		return fmt.Errorf("ExtendPCR(%d): %w", index, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("ExtendPCR(%d): NSM error: %s", index, resp.Error)
	}
	return nil
}

// describePCR returns PCR[index]'s current value and its lock state.
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
