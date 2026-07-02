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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/acme/autocert"

	"github.com/ArkLabsHQ/introspector-enclave/runtime/nitriding"
)

const (
	acmeCertCacheDir = "cert-cache"
	// acmeStagingDirectoryURL is Let's Encrypt's staging ACME endpoint — an
	// untrusted root with high rate limits, used for testing.
	acmeStagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	certificateOrg          = "AWS Nitro enclave application"
	certificateValidity     = time.Hour * 24 * 356

	migrationPCRIndex            = 31
	keyDeletionPendingDays int32 = 7

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

type PreviousPCR0Info struct {
	PCR0        string
	Attestation string
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
	nsm           *Nsm
	staticSecrets *StaticSecrets
	stateOrigin   *StateOrigin
	storage       *Storage
	kvStore       *KVStore
	respSrv       *RESPServer
	environment   *Environment
	signature     *Signature

	cooldownMu        sync.Mutex
	cooldownPending   bool
	cooldownRemaining int
	cooldownFetchedAt time.Time

	auth func(http.ResponseWriter, *http.Request) bool
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
	e.kvStore.anchor = &FreshnessAnchor{kv: e.kvStore, s3: e.kms.aws.S3, window: anchorWindow(), halt: &e.rollbackHalt}
	e.respSrv = NewRESPServer(e.kvStore, e.runtimeToken)
	e.respSrv.halt = &e.rollbackHalt

	if err := e.attestation.Init(); err != nil {
		slog.Error("init attestation", "error", err)
		return fmt.Errorf("init attestation: %w", err)
	}

	// State-origin provenance.
	e.stateOrigin = NewStateOrigin(e.aws.SSM, e.staticSecrets.Secrets())
	e.nsm, err = NewNsm()
	if err != nil {
		slog.Error("open NSM session", "error", err)
	}

	ownPCR0, err := e.nsm.getPCR0()
	if err != nil {
		slog.Error("read PCR0 from NSM", "error", err)
		return fmt.Errorf("read PCR0 from NSM: %w", err)
	}

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
	keyID, err := e.kms.EnsureKeyID(ctx, ownPCR0)
	if err != nil {
		return "", fmt.Errorf("ensure KMS key ID: %w", err)
	}
	if err := e.kms.VerifyKeyAuthorization(ctx, keyID, ownPCR0); err != nil {
		return "", fmt.Errorf("verify KMS key admits us: %w", err)
	}
	if err := e.VerifyPredecessorCommitment(ctx, ownPCR0); err != nil {
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
// and tear the whole runtime down. Pass nil for a clean exit,
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

// SetSigningKeyHash registers the SHA-256 hash of the enclave's
// attestation signing key for inclusion in NSM attestation documents.
func (e *Runtime) SetSigningKeyHash(hash [32]byte) {
	e.hashes.SetSigningKeyHash(hash)
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

	leafFingerprint := func(raw []byte) ([sha256.Size]byte, error) {
		for len(raw) > 0 {
			var block *pem.Block
			block, raw = pem.Decode(raw)
			if block == nil {
				return [sha256.Size]byte{}, errors.New("pem.Decode found no PEM data")
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return [sha256.Size]byte{}, fmt.Errorf("parse certificate: %w", err)
			}
			if !cert.IsCA {
				return sha256.Sum256(cert.Raw), nil
			}
		}
		return [sha256.Size]byte{}, errors.New("no non-CA leaf certificate found in TLS chain")
	}

	setCertFingerprint := func(raw []byte) error {
		h, err := leafFingerprint(raw)
		if err != nil {
			return err
		}
		e.hashes.SetTLSKeyHash(h)
		return nil
	}

	if err := setCertFingerprint(pemCert); err != nil {
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

	bindLeafFingerprint := func(leafDER []byte) {
		h := sha256.Sum256(leafDER)
		if e.hashes.SetTLSKeyHashIfChanged(h) {
			slog.Info("TLS: bound attestation to ACME cert", "sha256", hex.EncodeToString(h[:]))
		}
	}

	// autocert serves (and caches) the leaf from GetCertificate and rotates it on
	// renewal. Wrap it so the attested fingerprint tracks the live leaf, re-binding
	// on rotation — no separate polling loop needed.
	e.tlsGetCert = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := mgr.GetCertificate(hello)
		if err == nil && cert != nil && len(cert.Certificate) > 0 {
			bindLeafFingerprint(cert.Certificate[0])
		}
		return cert, err
	}
	return nil
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
	strict.HandleFunc("POST /v1/start-migration", e.handleStartMigration)
}

// handleStartMigration mints the migration key PCR0-locked at birth, re-encrypts
// secrets + DEK into its key-scoped SSM paths, verifies them, then flips
// KMSKeyID (one atomic write) and schedules the old key for deletion.
func (e *Runtime) handleStartMigration(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewPCR0 string `json:"new_pcr0"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NewPCR0 == "" {
		http.Error(w, "new_pcr0 is required in request body", http.StatusBadRequest)
		return
	}
	if len(req.NewPCR0) != 96 {
		http.Error(w, "new_pcr0 must be 96 hex characters (SHA-384)", http.StatusBadRequest)
		return
	}
	if _, err := hex.DecodeString(req.NewPCR0); err != nil {
		http.Error(w, "new_pcr0 must be valid hex", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	deployment := getDeployment()
	appName := getAppName()

	ownPCR0, err := e.nsm.getPCR0()
	if err != nil {
		http.Error(w, fmt.Sprintf("could not read own PCR0 from NSM: %v", err), http.StatusInternalServerError)
		return
	}

	if ownPCR0 == "" {
		http.Error(w, "could not read own PCR0 from NSM", http.StatusInternalServerError)
		return
	}

	newPCR0Bytes, _ := hex.DecodeString(req.NewPCR0)
	if err := e.nsm.commitPCR(req.NewPCR0, newPCR0Bytes, migrationPCRIndex); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Mint the migration key with the final PCR0-locked policy in one call.
	// No external principal ever holds authority over the key.
	migrationKeyID, err := e.kms.CreateMigrationKey(ctx, ownPCR0, req.NewPCR0)
	if err != nil {
		http.Error(w, fmt.Sprintf("create migration key: %v", err), http.StatusInternalServerError)
		return
	}
	slog.Info("created migration KMS key", "key_id", migrationKeyID, "own_pcr0", prefix16(ownPCR0), "new_pcr0", prefix16(req.NewPCR0))

	committed := false
	defer func() {
		if committed {
			return
		}
		pendingDays := keyDeletionPendingDays
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, derr := e.aws.KMS.ScheduleKeyDeletion(cleanupCtx, &kms.ScheduleKeyDeletionInput{
			KeyId:               aws.String(migrationKeyID),
			PendingWindowInDays: &pendingDays,
		}); derr != nil {
			slog.Warn("schedule unused migration key for deletion failed", "key_id", migrationKeyID, "error", derr)
		} else {
			slog.Info("scheduled unused migration key for deletion (handleStartMigration failed before commit)", "key_id", migrationKeyID)
		}
	}()

	type encryptedSecret struct {
		name          string
		keyBytes      []byte
		ciphertextB64 string
	}
	var encryptedSecrets []encryptedSecret
	for _, secret := range e.staticSecrets.Secrets() {
		secretValue := os.Getenv(secret.EnvVar)
		if secretValue == "" {
			continue
		}
		keyBytes, err := hex.DecodeString(secretValue)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid key format for %s", secret.Name), http.StatusInternalServerError)
			return
		}
		ciphertextB64, err := e.kms.Encrypt(ctx, migrationKeyID, keyBytes)
		if err != nil {
			http.Error(w, fmt.Sprintf("KMS encrypt failed for %s", secret.Name), http.StatusInternalServerError)
			return
		}
		ciphertextParam := secretCiphertextParam(secret.Name, migrationKeyID)
		if err := e.kms.StoreCiphertext(ctx, ciphertextParam, ciphertextB64); err != nil {
			http.Error(w, fmt.Sprintf("SSM store failed for %s", secret.Name), http.StatusInternalServerError)
			return
		}
		encryptedSecrets = append(encryptedSecrets, encryptedSecret{
			name:          secret.Name,
			keyBytes:      keyBytes,
			ciphertextB64: ciphertextB64,
		})
	}

	if err := e.storage.ExportDEK(ctx, migrationKeyID); err != nil {
		http.Error(w, fmt.Sprintf("storage DEK export failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Verify before commit: ownPCR0 is in the policy, so we can decrypt our own writes.
	for _, es := range encryptedSecrets {
		decrypted, err := decryptDEK(ctx, e.kms.aws.KMS, migrationKeyID, es.ciphertextB64)
		if err != nil {
			http.Error(w, fmt.Sprintf("verify: decrypt failed for %s: %v", es.name, err), http.StatusInternalServerError)
			return
		}
		if !bytes.Equal(decrypted, es.keyBytes) {
			http.Error(w, fmt.Sprintf("verify: ciphertext mismatch for %s", es.name), http.StatusInternalServerError)
			return
		}
	}

	// Record this enclave as the next one's predecessor (with attestation)
	// before flipping KMSKeyID, so a failure here leaves nothing committed.
	pcr0, _, err := e.storePCR0WithAttestation(ctx, deployment, appName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Emit the migration-transition receipt over the successor's state_root,
	// before the KMSKeyID flip, so the successor can verify the handoff on first
	// boot. PCR31 already committed to new_pcr0 above.
	if err := e.stateOrigin.writeTransitionReceipt(ctx, migrationKeyID); err != nil {
		http.Error(w, fmt.Sprintf("write migration-transition receipt: %v", err), http.StatusInternalServerError)
		return
	}

	oldKeyID, _ := e.kms.GetKeyID(ctx) // for deletion below

	// Atomic commit: from here, all boots use the migration key.
	if _, err := e.aws.SSM.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(fmt.Sprintf("/%s/%s/KMSKeyID", deployment, appName)),
		Value:     aws.String(migrationKeyID),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	}); err != nil {
		http.Error(w, fmt.Sprintf("update KMSKeyID: %v", err), http.StatusInternalServerError)
		return
	}
	committed = true
	slog.Info("KMSKeyID updated to migration key", "key_id", migrationKeyID)

	// Schedule old key for deletion (best-effort — failure is non-fatal).
	if oldKeyID != "" && oldKeyID != migrationKeyID {
		pendingDays := keyDeletionPendingDays
		if _, err := e.aws.KMS.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
			KeyId:               aws.String(oldKeyID),
			PendingWindowInDays: &pendingDays,
		}); err != nil {
			slog.Warn("schedule old key deletion failed", "key_id", oldKeyID, "error", err)
		} else {
			slog.Info("scheduled old KMS key for deletion", "key_id", oldKeyID, "pending_days", keyDeletionPendingDays)
		}
	}

	var exportedNames []string
	for _, es := range encryptedSecrets {
		exportedNames = append(exportedNames, es.name)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		PCR0     string   `json:"pcr0"`
		Exported []string `json:"exported"`
	}{
		PCR0:     pcr0,
		Exported: exportedNames,
	})
}

// storePCR0WithAttestation writes the old enclave's PCR0 and attestation doc
// directly to MigrationPreviousPCR0 / MigrationPreviousPCR0Attestation.
func (e *Runtime) storePCR0WithAttestation(ctx context.Context, deployment, appName string) (string, string, error) {
	pcr0, err := e.nsm.getPCR0()
	if err != nil {
		return "", "", fmt.Errorf("could not read PCR0 from NSM: %w", err)
	}

	if pcr0 == "" {
		return "", "", fmt.Errorf("could not read PCR0 from NSM")
	}

	attestDocB64, err := getAttestationDocumentB64()
	if err != nil {
		return "", "", fmt.Errorf("generate attestation document: %w", err)
	}

	// Write the attestation first; PCR0 is the commit point. VerifyPredecessor-
	// Commitment treats a recorded PCR0 as proof the attestation exists, so a
	// partial write can never leave a predecessor without its attestation.
	attestParam := fmt.Sprintf("/%s/%s/MigrationPreviousPCR0Attestation", deployment, appName)
	if _, err := e.aws.SSM.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(attestParam),
		Value:     aws.String(attestDocB64),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
		Tier:      ssmtypes.ParameterTierAdvanced,
	}); err != nil {
		return "", "", fmt.Errorf("store PCR0 attestation in SSM: %w", err)
	}

	pcr0Param := fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", deployment, appName)
	if _, err := e.aws.SSM.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(pcr0Param),
		Value:     aws.String(pcr0),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	}); err != nil {
		return "", "", fmt.Errorf("store PCR0 in SSM: %w", err)
	}

	return pcr0, attestDocB64, nil
}

func (e *Runtime) CooldownStatus(ctx context.Context) (configuredSeconds, remaining int, pending bool) {
	cooldown := getMigrationCooldown()
	configuredSeconds = int(cooldown.Seconds())

	e.cooldownMu.Lock()
	if time.Since(e.cooldownFetchedAt) < 5*time.Second {
		rem := e.cooldownRemaining
		pend := e.cooldownPending
		e.cooldownMu.Unlock()
		return configuredSeconds, rem, pend
	}
	e.cooldownMu.Unlock()

	if e.aws == nil {
		return configuredSeconds, 0, false
	}
	deployment := getDeployment()
	appName := getAppName()

	requestedAtStr, err := readSSMParam(ctx, e.aws.SSM, fmt.Sprintf("/%s/%s/MigrationRequestedAt", deployment, appName))
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
	rem := time.Until(deadline)
	if rem < 0 {
		rem = 0
	}

	e.cooldownMu.Lock()
	e.cooldownPending = true
	e.cooldownRemaining = int(rem.Seconds())
	e.cooldownFetchedAt = time.Now()
	e.cooldownMu.Unlock()

	return configuredSeconds, int(rem.Seconds()), true
}

// VerifyPredecessorCommitment checks that the previous enclave's stored
// attestation document committed (via PCR31) to handing off to ownPCR0.
// No-op when there's no predecessor (genesis), or when the chain entry
// points at our own PCR0 — that's the rolled-back-onto-self case: this
// enclave wrote the attestation before a failed migration, and its PCR31
// commits to the failed target rather than to itself.
func (e *Runtime) VerifyPredecessorCommitment(ctx context.Context, ownPCR0 string) error {
	deployment := getDeployment()
	appName := getAppName()
	prevPCR0, err := readSSMParamOptional(ctx, e.aws.SSM, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", deployment, appName))
	if err != nil {
		return fmt.Errorf("read previous PCR0: %w", err)
	}
	if prevPCR0 == "" || strings.EqualFold(prevPCR0, ownPCR0) {
		return nil
	}
	attestB64, err := readSSMParamOptional(ctx, e.aws.SSM, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0Attestation", deployment, appName))
	if err != nil {
		return fmt.Errorf("read previous attestation: %w", err)
	}
	// Fail closed: a predecessor is recorded but its attestation is missing or
	// UNSET. storePCR0WithAttestation writes the attestation before PCR0, so a
	// recorded PCR0 always has one — a blank here is a tampered or corrupt
	// handoff, not a state to trust.
	if attestB64 == "" {
		return fmt.Errorf("predecessor PCR0 %s recorded but its attestation is missing", prefix16(prevPCR0))
	}
	return verifyPCR31Commitment(attestB64, ownPCR0, prevPCR0)
}

func (e *Runtime) GetPreviousPCR0Info(ctx context.Context) (*PreviousPCR0Info, error) {
	pcr0, err := readSSMParam(ctx, e.aws.SSM, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", getDeployment(), getAppName()))
	if err != nil {
		return nil, err
	}
	attest, err := readSSMParam(ctx, e.aws.SSM, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0Attestation", getDeployment(), getAppName()))
	if err != nil {
		return nil, err
	}
	return &PreviousPCR0Info{PCR0: pcr0, Attestation: attest}, nil
}

// readSSMParam returns an error if the parameter is missing or set to "UNSET".
func readSSMParam(ctx context.Context, ssmClient SSMAPI, paramName string) (string, error) {
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", fmt.Errorf("parameter %s has no value", paramName)
	}
	value := strings.TrimSpace(*out.Parameter.Value)
	if value == "" || value == "UNSET" {
		return "", fmt.Errorf("parameter %s is unset", paramName)
	}
	return value, nil
}

// readSSMParamOptional is like readSSMParam but returns ("", nil) when the
// param is missing or holds the tofu placeholder "UNSET". Real SSM errors
// (network, IAM) still propagate.
func readSSMParamOptional(ctx context.Context, ssmClient SSMAPI, paramName string) (string, error) {
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		var pnf *ssmtypes.ParameterNotFound
		if errors.As(err, &pnf) {
			return "", nil
		}
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", nil
	}
	v := strings.TrimSpace(*out.Parameter.Value)
	if v == "" || v == "UNSET" {
		return "", nil
	}
	return v, nil
}
