package runtime

// servers.go wires public/private muxes, admin handlers, reverse proxy, and listeners.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ArkLabsHQ/enclave/internal/signing"
	"github.com/ArkLabsHQ/enclave/runtime/nitriding"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http2"
)

const (
	nonceNumDigits = 40 // 20-byte nonce, hex-encoded
	enclavePrefix  = "/enclave/"

	signNonceHeader = "X-Enclave-Sign-Nonce"
	signatureHeader = "X-Enclave-Signature"

	maxSignedRequestBytes  = 1 << 20 // 1 MiB
	maxSignedResponseBytes = 4 << 20 // 4 MiB

	maxLoggedNonce = 128
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

// RuntimeInfo is the JSON body returned by GET /enclave/v1/info.
type RuntimeInfo struct {
	Version                  string           `json:"version"`
	Status                   string           `json:"status"`
	Candidate                *CandidateInfo   `json:"candidate,omitempty"`
	PreviousPCR0             string           `json:"previous_pcr0"`
	PreviousPCR0Attestation  string           `json:"previous_pcr0_attestation,omitempty"`
	MigrationCooldownSeconds int              `json:"migration_cooldown_seconds"`
	MigrationIntentBucket    string           `json:"migration_intent_bucket"`
	Migration                *MigrationStatus `json:"migration"`
	UpstreamApp              UpstreamAppInfo  `json:"upstream_app"`
	KMSKeyLocked             bool             `json:"kms_key_locked"`
	Ancestry                 *AncestryInfo    `json:"ancestry,omitempty"`
	// Error says why boot stopped, when Status is failed.
	Error string `json:"error,omitempty"`
}

type Servers interface {
	Start(ctx context.Context, cfg Config) error
	ConfigureEnclaveInfoHandler(migrator Migrator) error
	ReportBootFailure(err error)
	SetAncestry(ctx context.Context, ancestry Ancestry)
}

type servers struct {
	cfg *Config
	ext *http.Server
	int *http.Server
	rm  *http.ServeMux
	em  *http.ServeMux
	rt  RuntimeState

	attData  *AttestationData
	ancestry atomic.Value // Ancestry, set once state is established
}

func SetupHttpServers(
	rt RuntimeState,
	cfg Config,
	nsm NSM,
	telemetry *Telemetry,
	attData *AttestationData,
	authToken string,
) Servers {
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 500
	http.DefaultTransport.(*http.Transport).MaxIdleConns = 500

	revProxy := httputil.NewSingleHostReverseProxy(cfg.AppWebSrv)
	revProxy.BufferPool = nitriding.NewBufPool()
	revProxy.Transport = upstreamTransport(cfg.UpstreamProtocol)
	if cfg.ExportTraces {
		revProxy.Transport = tracedTransport{next: revProxy.Transport}
	}
	revProxy.FlushInterval = -1
	revProxy.ModifyResponse = func(*http.Response) error {
		telemetry.Inc(metricAppProxiedRequests)
		return nil
	}
	revProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		telemetry.Inc(metricAppProxiedErrors)
		w.WriteHeader(http.StatusBadGateway)
	}

	sm := http.NewServeMux()
	registerRuntimeV1Handlers(sm, "/v1/", telemetry, authToken)
	sm.Handle("GET /health", healthHandler(rt))

	// OTLP forwarding stays on loopback because requests use instance credentials.
	rm := http.NewServeMux()
	rm.Handle("GET /enclave/attestation", routeSpan(
		cfg.ExportTraces, "enclave-attestation", whenReady(rt, attestationHandler(nsm, attData)),
	))

	em := http.NewServeMux()
	em.Handle(enclavePrefix, corsWildcard(rm))

	em.Handle("/health", sm)

	em.Handle("/", routeSpan(
		cfg.ExportTraces, "proxy", whenReady(rt, signResponses(attData, revProxy)),
	))

	im := http.NewServeMux()
	im.Handle("/v1/", sm)
	im.Handle("/health", sm)

	ext := &http.Server{
		Handler: metricsMiddleware(telemetry, true)(em),
		TLSConfig: &tls.Config{
			GetCertificate: certCallback(rt),
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
		},
	}

	int := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", cfg.IntPort),
		Handler: metricsMiddleware(telemetry, false)(im),
	}

	return &servers{
		cfg:     &cfg,
		ext:     ext,
		int:     int,
		rm:      rm,
		em:      em,
		rt:      rt,
		attData: attData,
	}
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

func registerRuntimeV1Handlers(
	mux *http.ServeMux,
	prefix string,
	telemetry *Telemetry,
	authToken string,
) {
	mux.HandleFunc(
		"POST "+prefix+"metrics",
		withTokenAuth(authToken, telemetry.forwardHandler(otlpMetrics)),
	)
	mux.HandleFunc(
		"POST "+prefix+"logs",
		withTokenAuth(authToken, telemetry.forwardHandler(otlpLogs)),
	)
	mux.HandleFunc(
		"POST "+prefix+"traces",
		withTokenAuth(authToken, telemetry.forwardHandler(otlpTraces)),
	)
}

// SetAncestry starts the audit after boot establishes lineage.
func (s *servers) SetAncestry(ctx context.Context, ancestry Ancestry) {
	ancestry.Start(ctx)
	s.ancestry.Store(ancestry)
}

func (s *servers) ConfigureEnclaveInfoHandler(migrator Migrator) error {
	info := func(w http.ResponseWriter, r *http.Request) {
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
		// Snapshot is local and cannot fail.
		var ancestryInfo *AncestryInfo
		if ancestry, ok := s.ancestry.Load().(Ancestry); ok {
			ancestryInfo = ancestry.Snapshot()
		}

		status := s.rt.Status()
		var candidate *CandidateInfo
		if status == runtimeStatusCandidate {
			// Candidate details are best-effort.
			if candidate, err = migrator.CandidateInfo(r.Context()); err != nil {
				slog.Warn("could not read inbound migration intent", "error", err)
				candidate = nil
			}
		}

		_ = json.NewEncoder(w).Encode(RuntimeInfo{
			Version:                  Version,
			Status:                   status,
			Candidate:                candidate,
			PreviousPCR0:             prevInfo.PCR0,
			PreviousPCR0Attestation:  prevInfo.Attestation,
			MigrationCooldownSeconds: int(s.cfg.MigrationCooldown.Seconds()),
			MigrationIntentBucket:    migrator.MigrationIntentBucket(),
			Migration:                migrationStatus,
			UpstreamApp:              s.rt.UpstreamAppInfo(),
			KMSKeyLocked:             s.cfg.KMSLocked,
			Ancestry:                 ancestryInfo,
		})
	}
	// Signed on request like application responses, once the signing key exists.
	s.rm.Handle("GET /enclave/v1/info", routeSpan(
		s.cfg.ExportTraces, "enclave-info", signResponses(s.attData, http.HandlerFunc(info)),
	))

	return nil
}

// ReportBootFailure exposes startup errors before telemetry is available.
func (s *servers) ReportBootFailure(err error) {
	s.rm.HandleFunc("GET /enclave/v1/info", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(RuntimeInfo{
			Version:                  Version,
			Status:                   runtimeStatusFailed,
			MigrationCooldownSeconds: int(s.cfg.MigrationCooldown.Seconds()),
			KMSKeyLocked:             s.cfg.KMSLocked,
			Error:                    err.Error(),
		})
	})
}

// migrationHTTPStatus maps the errors /enclave/v1/info can surface. Migration
// itself has no HTTP surface; only reading its status does.
func migrationHTTPStatus(err error) int {
	switch {
	case errors.Is(err, errMigrationIntentStoreUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// metricsMiddleware counts and logs each request. On the public listener, a 404
// is almost always a scanner probing for a path, so it is counted but not logged;
// other 4xx, and every 4xx on the internal listener, are real client errors and
// stay logged.
func metricsMiddleware(telemetry *Telemetry, public bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			level := slog.LevelInfo
			switch {
			case sw.status >= 500:
				level = slog.LevelWarn
				telemetry.Inc(metricHTTPServerErrors)
			case sw.status >= 400:
				if public && sw.status == http.StatusNotFound {
					level = slog.LevelDebug
				}
				telemetry.Inc(metricHTTPClientErrors)
			}
			slog.Log(
				r.Context(),
				level,
				"http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
			telemetry.Inc(metricHTTPRequests)
		})
	}
}

// routeSpan records a server span named for its route. It exports no path, query
// or client header, because the operator can read X-Ray but not this TLS traffic.
// Trace context from the internet is untrusted: it only becomes a link on a new
// root, so a caller cannot join an existing trace or force sampling.
func routeSpan(traced bool, route string, next http.Handler) http.Handler {
	if !traced {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		opts := []trace.SpanStartOption{
			trace.WithNewRoot(),
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(spanMethod(r.Method)),
		}
		incoming := propagation.TraceContext{}.Extract(
			r.Context(), propagation.HeaderCarrier(r.Header),
		)
		if sc := trace.SpanContextFromContext(incoming); sc.IsValid() {
			opts = append(opts, trace.WithLinks(trace.Link{
				SpanContext: sc.WithTraceState(trace.TraceState{}),
			}))
		}
		ctx, span := otel.Tracer(runtimeService).Start(r.Context(), route, opts...)
		defer span.End()

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if p := recover(); p != nil {
				// ReverseProxy panics with http.ErrAbortHandler when the app's response
				// breaks off; re-panic so net/http still cuts the connection.
				setSpanStatus(span, sw.status)
				span.SetStatus(codes.Error, "response aborted")
				panic(p)
			}
		}()
		next.ServeHTTP(sw, r.WithContext(ctx))
		setSpanStatus(span, sw.status)
	})
}

// spanMethod bounds a client-chosen method to the standard ones.
func spanMethod(method string) attribute.KeyValue {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
	default:
		method = "_OTHER"
	}
	return attribute.String("http.request.method", method)
}

func setSpanStatus(span trace.Span, status int) {
	span.SetAttributes(attribute.Int("http.response.status_code", status))
	if status >= http.StatusInternalServerError {
		span.SetStatus(codes.Error, http.StatusText(status))
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

// whenReady serves next after the application starts.
func whenReady(rt RuntimeState, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rt.Ready() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "initializing"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// attestationHandler serves NSM attestation bound to the currently served TLS leaf.
func attestationHandler(nsm NSM, attData *AttestationData) http.HandlerFunc {
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
			WithUserData(attData.Serialize()),
		)
		if err != nil {
			http.Error(w, errFailedAttestation, http.StatusInternalServerError)
			return
		}

		_, _ = fmt.Fprintln(w, base64.StdEncoding.EncodeToString(doc))
	}
}

// signResponses signs the response to a request carrying signNonceHeader with
// the attested response-signing key, over the request as received and the
// response as sent. Other requests pass through unbuffered.
func signResponses(attData *AttestationData, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get(signNonceHeader)
		if nonce == "" {
			next.ServeHTTP(w, r)
			return
		}
		// Refuse before the app acts on the request, not after.
		key := attData.responseSigningKey()
		if key == nil {
			http.Error(w, "no response signing key", http.StatusServiceUnavailable)
			return
		}
		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read request body", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
		signingContext, err := signing.CaptureResponseSigningContext(r, reqBody)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Sign the decoded body: browsers always decompress and cannot opt out.
		// Without the header, the upstream transport requests gzip itself and
		// decodes it before we see the body.
		r.Header.Del("Accept-Encoding")

		rec := &bufferedResponse{header: http.Header{}, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		// A HEAD response carries no body on the wire; sign the empty one sent.
		if r.Method == http.MethodHead {
			rec.body.Reset()
		}
		msg := signingContext.ResponseMessage(sha256.Sum256(rec.body.Bytes()), rec.status)
		maps.Copy(w.Header(), rec.header)
		w.Header().Set(signatureHeader, base64.StdEncoding.EncodeToString(ed25519.Sign(key, msg)))
		// Lets cross-origin browser code read the signature.
		w.Header().Add("Access-Control-Expose-Headers", signatureHeader)
		// The signature answers one nonce; a cached copy could only fail verification.
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(rec.status)
		_, _ = w.Write(rec.body.Bytes())

		path, _, _ := strings.Cut(signingContext.URI, "?")
		slog.Info(
			"signed response",
			"nonce", nonce[:min(len(nonce), maxLoggedNonce)],
			"method", signingContext.Method,
			"path", path,
			"authority", signingContext.Authority,
			"status", rec.status,
		)
	})
}

// bufferedResponse holds a response until it is signed.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) WriteHeader(status int)      { b.status = status }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }

// UpstreamAppInfo reports whether the user app process has exited and, if
// so, the error from its exit. The runtime stays alive after app exit so
// admin endpoints remain reachable.
type UpstreamAppInfo struct {
	Exited bool   `json:"exited"`
	Error  string `json:"error,omitempty"`
}

// healthHandler returns 200 once Ready() is true and the app has not exited,
// 503 otherwise.
func healthHandler(rt RuntimeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !rt.Ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "initializing"})
			return
		}
		if rt.UpstreamAppInfo().Exited {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "upstream_exited"})
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
// hop, selected by ENCLAVE_UPSTREAM: "h2c" or "h1" pin a single
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

// tracedTransport records the runtime->app hop until response headers arrive and
// makes it the parent of the app's spans. The client's tracestate goes too, because
// Inject leaves that header alone when it has nothing to write.
type tracedTransport struct {
	next http.RoundTripper
}

func (t tracedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx, span := otel.Tracer(runtimeService).Start(r.Context(), "upstream",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			spanMethod(r.Method),
			attribute.String("server.address", r.URL.Hostname()),
		),
	)
	defer span.End()

	r = r.Clone(ctx)
	r.Header.Del("Tracestate")
	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(r.Header))

	res, err := t.next.RoundTrip(r)
	if err != nil {
		// Not err's text, which could quote the request.
		span.SetStatus(codes.Error, "upstream request failed")
		return nil, err
	}
	setSpanStatus(span, res.StatusCode)
	return res, nil
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
