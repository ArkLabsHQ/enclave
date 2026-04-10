package sdk

import (
	"log/slog"
	"net/http"
	"os"
	"time"
)

// InitLogging configures the global slog logger with a JSON handler.
// Call this from the entry point (e.g. supervisor main) before any logging.
func InitLogging() {
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(handler))
}

// LoggingMiddleware logs each HTTP request with method, path, status, and duration.
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
