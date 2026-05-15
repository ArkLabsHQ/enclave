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
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"

	"github.com/ArkLabsHQ/introspector-enclave/runtime/nitriding"
)

const (
	acmeCertCacheDir    = "cert-cache"
	certificateOrg      = "AWS Nitro enclave application"
	certificateValidity = time.Hour * 24 * 356

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

	// Lifecycle channels.
	ready     chan bool  // closed when the user app POSTs /enclave/ready
	stop      chan bool  // closed by Stop() to unwind goroutines
	listenErr chan error // first listener bind/serve error; consumed by main

	// Init state — set by Init, read by gating middleware and handlers.
	initDone atomic.Bool // happens-before fence: Init returned (success or failure)
	initOK   atomic.Bool // Init returned without error

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
	dynamic       *DynamicSecrets
	storage       *Storage
	migrator      *Migrator
	environment   *Environment
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
		runtimeToken: token,
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
// authorization, the attestation key, static and dynamic secrets, storage,
// and the migration handshake. May block on KMS. Idempotent on the
// initDone fence — handlers can safely read subsystem fields once it
// returns, regardless of success.
//
// Start must run before Init so /v1/enclave-info and the telemetry
// endpoints remain reachable while subsystems come up.
func (e *Runtime) Init(ctx context.Context) error {
	defer e.initDone.Store(true)

	ctx, initSpan := e.tracing.Span(ctx, "init")
	defer initSpan.End()

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

	// Migrator needs Storage too, but Storage isn't fully initialized yet.
	// Wire it in after Storage.Init below; /v1/start-migration is gated on
	// initOK so the late wire-up is safe.
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

	var err error
	if e.cfg.UseACME {
		err = e.configureACME()
	} else {
		err = e.genSelfSignedCert()
	}
	if err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}
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

// RegisterRoutes mounts Runtime's admin endpoints on mux:
//
//	GET    /v1/enclave-info
//	POST   /v1/enclave-metrics
//	GET    /v1/enclave-metrics
//	POST   /v1/start-migration            (gated: requireInitOK)
//	{PUT,GET,DELETE} /v1/storage/{key...} (gated: requireInitDone)
//	GET    /v1/storage                    (gated: requireInitDone)
//	{PUT,GET,DELETE} /v1/secrets/{name}   (gated: requireInitDone)
//	GET    /v1/secrets                    (gated: requireInitDone)
//	POST   /v1/logs
//	GET    /v1/enclave-logs
//	POST   /v1/enclave-traces
//	GET    /v1/enclave-traces
//
// Subsystem-owned routes are added later by registerGatedRoutes once Init
// has built those subsystems.
func (e *Runtime) RegisterRoutes(mux *http.ServeMux) {
	e.mux = mux
	mux.Handle("GET /v1/enclave-info", enclaveInfoHandler(e))
	mux.HandleFunc("POST /v1/enclave-metrics", e.handleMetricPost)
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

func (e *Runtime) RuntimeToken() string      { return e.runtimeToken }
func (e *Runtime) Logging() *Logging         { return e.logging }
func (e *Runtime) Tracing() *Tracing         { return e.tracing }
func (e *Runtime) AttestationPubkey() string { return e.attestation.Pubkey() }

// IsReady reports whether Init completed successfully. /health uses this
// to distinguish "ready" from "initializing" / "failed".
func (e *Runtime) IsReady() bool { return e.initOK.Load() }

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

	pm.Handle("/v1/*", admin)
	pm.Handle("/health", admin)

	// h2c upstream so gRPC trailers and long-lived streams survive the
	// proxy hop; FlushInterval=-1 so server-streaming responses aren't buffered.
	if e.cfg.AppWebSrv != nil {
		e.revProxy = httputil.NewSingleHostReverseProxy(e.cfg.AppWebSrv)
		e.revProxy.BufferPool = nitriding.NewBufPool()
		e.revProxy.Transport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}
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
	return nil
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

// genSelfSignedCert generates an ECDSA-P256 leaf cert, records its
// fingerprint in the attestation hashes (so clients can pin it against
// the NSM document), and installs it on pubSrv with ALPN advertising h2.
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
	e.pubSrv.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	return nil
}

// configureACME wires Let's Encrypt as the TLS cert source via autocert.
// The cert is cached in memory only (inside an enclave) so a restart
// requests a fresh cert; outside an enclave a local DirCache is used.
// ALPN includes acme-tls/1 so TLS-ALPN-01 challenges continue to work.
func (e *Runtime) configureACME() error {
	var cache autocert.Cache = nitriding.NewCertCache()
	if !nitriding.InEnclave() {
		cache = autocert.DirCache(acmeCertCacheDir)
	}
	mgr := autocert.Manager{
		Cache:      cache,
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist([]string{e.cfg.FQDN}...),
	}
	e.pubSrv.TLSConfig = mgr.TLSConfig()
	e.pubSrv.TLSConfig.NextProtos = []string{"h2", "http/1.1", "acme-tls/1"}
	e.pubSrv.TLSConfig.MinVersion = tls.VersionTLS12

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
