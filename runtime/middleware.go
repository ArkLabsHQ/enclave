package runtime

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

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

// isGRPCRequest reports whether r is a gRPC or gRPC-Web call. Such requests
// bypass response-body buffering, which would break streaming RPCs and drop
// trailers.
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

// gatedMux wraps an http.ServeMux so every HandleFunc call is rewrapped
// in a gating middleware (e.g. requireInitDone or requireInitOK).
type gatedMux struct {
	inner *http.ServeMux
	gate  func(http.Handler) http.Handler
}

func (g *gatedMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	g.inner.Handle(pattern, g.gate(http.HandlerFunc(handler)))
}
