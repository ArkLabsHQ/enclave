package runtime

// servers.go wires public/private muxes, admin handlers, reverse proxy, and listeners.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/ArkLabsHQ/enclave/runtime/nitriding"
	"github.com/mdlayher/vsock"
	"golang.org/x/net/http2"
)

const (
	nonceNumDigits            = 40 // 20-byte nonce, hex-encoded
	migrationControlPort      = 8003
	migrationRequestPath      = "/request-migration"
	migrationFinalisationPath = "/finalise-migration"
	enclavePrefix             = "/enclave/"
	externalRuntimeV1Prefix   = enclavePrefix + "v1/"
)

var (
	errBadForm        = "failed to parse POST form data"
	errNoNonce        = "could not find nonce in URL query parameters"
	errBadNonceFormat = fmt.Sprintf(
		"unexpected nonce format; must be %d-digit hex string",
		nonceNumDigits,
	)
	errFailedAttestation = "failed to obtain attestation document from hypervisor"
)

type Servers interface {
	Start(ctx context.Context, cfg Config) error
	ConfigureEnclaveInfoHandler(ctx context.Context, migrator Migrator, ancestry Ancestry) error
	StartMigrationControlServer(ctx context.Context, migrator Migrator) error
}

type servers struct {
	cfg     *Config
	ext     *http.Server
	int     *http.Server
	sm      *http.ServeMux
	rm      *http.ServeMux
	im      *http.ServeMux
	em      *http.ServeMux
	rt      RuntimeState
	metrics *Metrics
}

func SetupHttpServers(
	rt RuntimeState,
	cfg Config,
	nsm NSM,
	telemetry *Telemetry,
	hashes *AttestationHashes,
	authToken string,
) Servers {
	metrics := telemetry.Metrics
	metricsMW := metricsMiddleware(metrics)

	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 500
	http.DefaultTransport.(*http.Transport).MaxIdleConns = 500

	revProxy := httputil.NewSingleHostReverseProxy(cfg.AppWebSrv)
	revProxy.BufferPool = nitriding.NewBufPool()
	revProxy.Transport = upstreamTransport(cfg.UpstreamProtocol)
	revProxy.FlushInterval = -1
	revProxy.ModifyResponse = func(*http.Response) error {
		metrics.Inc(metricAppProxiedRequests)
		return nil
	}
	revProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		metrics.Inc(metricAppProxiedErrors)
		w.WriteHeader(http.StatusBadGateway)
	}

	sm := http.NewServeMux()
	registerRuntimeV1Handlers(sm, "/v1/", telemetry, authToken)
	sm.Handle("GET /health", healthHandler(rt))

	rm := http.NewServeMux()
	registerRuntimeV1Handlers(rm, externalRuntimeV1Prefix, telemetry, authToken)
	rm.HandleFunc("GET /enclave/attestation", attestationHandler(nsm, hashes))

	em := http.NewServeMux()
	em.Handle(enclavePrefix, corsWildcard(rm))

	em.Handle("/health", sm)
	em.Handle("/", revProxy)

	im := http.NewServeMux()
	im.Handle("/v1/", sm)
	im.Handle("/health", sm)

	ext := &http.Server{
		Handler: metricsMW(em),
		TLSConfig: &tls.Config{
			GetCertificate: certCallback(rt),
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
		},
	}

	int := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", cfg.IntPort),
		Handler: metricsMW(im),
	}

	return &servers{
		cfg:     &cfg,
		ext:     ext,
		int:     int,
		sm:      sm,
		rm:      rm,
		em:      em,
		im:      im,
		rt:      rt,
		metrics: metrics,
	}
}

// registerRuntimeV1Handlers mounts the OTLP ingest endpoints under prefix. Ingest
// only: the runtime ships telemetry to CloudWatch and never reads it back, so a
// compromised enclave has no history to serve.
func registerRuntimeV1Handlers(
	mux *http.ServeMux,
	prefix string,
	telemetry *Telemetry,
	authToken string,
) {
	mux.HandleFunc(
		"POST "+prefix+"metrics",
		withTokenAuth(authToken, HandleMetricPost(telemetry.Metrics)),
	)
	mux.HandleFunc(
		"POST "+prefix+"logs",
		withTokenAuth(authToken, HandleLogsPost(telemetry.Logging)),
	)
	mux.HandleFunc(
		"POST "+prefix+"traces",
		withTokenAuth(authToken, HandleTracingPost(telemetry.Tracing)),
	)
}

func (s *servers) Start(ctx context.Context, cfg Config) error {
	private, err := net.Listen("tcp", s.int.Addr)
	if err != nil {
		return fmt.Errorf("private listener: %w", err)
	}

	public, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.ExtPort))
	if err != nil {
		_ = private.Close()
		return fmt.Errorf("public listener: %w", err)
	}

	go func() {
		if err := s.int.Serve(private); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.rt.NotifyListenerError(fmt.Errorf("private listener: %w", err))
		}
	}()

	go func() {
		if err := s.ext.ServeTLS(
			public,
			"",
			"",
		); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			s.rt.NotifyListenerError(fmt.Errorf("public listener: %w", err))
		}
	}()

	go func() {
		<-ctx.Done()
		_ = s.int.Close()
		_ = s.ext.Close()
	}()

	return nil
}

// RuntimeInfo is the JSON body returned by GET /enclave/v1/info.
type RuntimeInfo struct {
	Version                  string           `json:"version"`
	PreviousPCR0             string           `json:"previous_pcr0"`
	PreviousPCR0Attestation  string           `json:"previous_pcr0_attestation,omitempty"`
	MigrationCooldownSeconds int              `json:"migration_cooldown_seconds"`
	Migration                *MigrationStatus `json:"migration"`
	UpstreamApp              UpstreamAppInfo  `json:"upstream_app"`
	KMSKeyLocked             bool             `json:"kms_key_locked"`
	Ancestry                 *AncestryInfo    `json:"ancestry,omitempty"`
}

func (s *servers) ConfigureEnclaveInfoHandler(
	ctx context.Context,
	migrator Migrator,
	ancestry Ancestry,
) error {
	if ancestry != nil {
		ancestry.Start(ctx)
	}
	s.rm.HandleFunc("GET /enclave/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		migrationStatus, err := migrator.MigrationStatus(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get migration status: %v", err),
				migrationHTTPStatus(err))
			return
		}

		prevInfo, err := migrator.PreviousPCR0Info(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get previous PCR0 info: %v", err),
				http.StatusInternalServerError)
			return
		}
		// Reading the audit cannot block or fail, so it is safe this late in the
		// handler and cannot make the endpoint slow or unavailable.
		var ancestryInfo *AncestryInfo
		if ancestry != nil {
			ancestryInfo = ancestry.Snapshot()
		}

		_ = json.NewEncoder(w).Encode(RuntimeInfo{
			Version:                  Version,
			PreviousPCR0:             prevInfo.PCR0,
			PreviousPCR0Attestation:  prevInfo.Attestation,
			MigrationCooldownSeconds: int(s.cfg.MigrationCooldown.Seconds()),
			Migration:                migrationStatus,
			UpstreamApp:              s.rt.UpstreamAppInfo(),
			KMSKeyLocked:             s.cfg.KMSLocked,
			Ancestry:                 ancestryInfo,
		})
	})

	return nil
}

func (s *servers) StartMigrationControlServer(ctx context.Context, migrator Migrator) error {
	lis, err := vsock.Listen(migrationControlPort, nil)
	if err != nil {
		return fmt.Errorf(
			"listen on migration control vsock port %d: %w",
			migrationControlPort,
			err,
		)
	}

	slog.Info("starting migration control listener", "vsock_port", migrationControlPort)
	s.serveMigrationControl(ctx, migrator, lis)
	return nil
}

func (s *servers) serveMigrationControl(
	ctx context.Context,
	migrator Migrator,
	lis net.Listener,
) {
	server := &http.Server{Handler: migrationControlHandler(migrator)}

	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()

	go func() {
		if err := server.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.rt.NotifyListenerError(fmt.Errorf("migration control listener: %w", err))
		}
	}()
}

func migrationControlHandler(migrator Migrator) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+migrationRequestPath, func(w http.ResponseWriter, r *http.Request) {
		var req MigrationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
			return
		}

		if err := req.Validate(); err != nil {
			http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}

		status, err := migrator.HandleMigrationRequest(r.Context(), req.Action, req.TargetPCR0)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("failed to handle migration request: %v", err),
				migrationHTTPStatus(err),
			)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	})

	mux.HandleFunc("POST "+migrationFinalisationPath, func(w http.ResponseWriter, r *http.Request) {
		res, err := migrator.CompleteMigration(r.Context())
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("failed to finalise migration: %v", err),
				migrationHTTPStatus(err),
			)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	})

	return mux
}

func migrationHTTPStatus(err error) int {
	switch {
	case errors.Is(err, errMigrationCooldownActive):
		return http.StatusTooEarly
	case errors.Is(err, errMigrationIntentAbsent),
		errors.Is(err, errMigrationIntentAborted),
		errors.Is(err, errMigrationIntentAlreadyRequested),
		errors.Is(err, errMigrationAlreadyFinalised):
		return http.StatusConflict
	case errors.Is(err, errMigrationIntentSelfTarget):
		return http.StatusBadRequest
	case errors.Is(err, errMigrationIntentStoreUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func metricsMiddleware(metrics *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			slog.Info(
				"http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
			metrics.Inc(metricHTTPRequests)
			if sw.status >= 400 {
				metrics.Inc(metricHTTPErrors)
			}
		})
	}
}

func withTokenAuth(token string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			handler(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			http.Error(
				w,
				"invalid Authorization format, expected Bearer token",
				http.StatusUnauthorized,
			)
			return
		}
		if strings.TrimPrefix(auth, prefix) != token {
			http.Error(w, "invalid management token", http.StatusForbidden)
			return
		}

		handler(w, r)
	}
}

// certCallback blocks each handshake until the runtime's TLS cert source is
// configured. SNI defaulting lives in withDefaultSNI, applied where the
// post-SSM-override FQDN is final.
func certCallback(rt RuntimeState) TLSCertCallback {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		getCert, err := rt.GetTLSCertCallback(hello.Context())
		if err != nil {
			return nil, nil
		}
		return getCert(hello)
	}
}

// attestationHandler serves NSM attestation bound to the currently served TLS leaf.
func attestationHandler(nsm NSM, hashes *AttestationHashes) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		doc, _, err := nsm.BuildAttestationDocument(
			WithNonce(rawNonce),
			WithUserData(hashes.Serialize()),
		)
		if err != nil {
			http.Error(w, errFailedAttestation, http.StatusInternalServerError)
			return
		}

		_, _ = fmt.Fprintln(w, base64.StdEncoding.EncodeToString(doc))
	}
}

// UpstreamAppInfo reports whether the user app process has exited and, if
// so, the error from its exit. The runtime stays alive after app exit so
// admin endpoints remain reachable.
type UpstreamAppInfo struct {
	Exited bool   `json:"exited"`
	Error  string `json:"error,omitempty"`
}

// healthHandler returns 200 once Ready() is true, 503 otherwise.
func healthHandler(rt RuntimeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !rt.Ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "initializing"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	}
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

// corsWildcard adds permissive CORS to external runtime API endpoints.
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

// statusWriter captures status and forwards Flush for streaming responses.
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
