// Test application for the e2e: it observes the runtime environment, exercises
// clock recovery, and ships OTLP telemetry through the runtime's ingest
// endpoints with the stock OpenTelemetry exporters.
//
// It is exec'd as a root child with CAP_SYS_TIME, so /test/clock can call
// syscall.Settimeofday without adding a shell or other packages to the EIF.
// offset_ms exists for sub-threshold (<100ms) skews that exercise the clock
// servo's frequency path rather than its hard-step path.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"
)

const (
	maxOffsetS  = 10
	maxOffsetMs = 10_000

	signingKeyEnv = "E2E_SIGNING_KEY"
)

type clockSample struct {
	Unix int64 `json:"unix"`
	Nsec int64 `json:"nsec"`
}

func nowSample() clockSample {
	now := time.Now()
	return clockSample{Unix: now.Unix(), Nsec: int64(now.Nanosecond())}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleEnv(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "missing env name")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"name":  name,
		"value": os.Getenv(name),
	})
}

func handleClockGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, nowSample())
}

func handleClockSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		OffsetSeconds int64 `json:"offset_seconds"`
		OffsetMs      int64 `json:"offset_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode body: %v", err))
		return
	}
	if req.OffsetSeconds < -maxOffsetS || req.OffsetSeconds > maxOffsetS {
		writeError(
			w,
			http.StatusBadRequest,
			fmt.Sprintf("offset_seconds out of range (limit +/-%d)", maxOffsetS),
		)
		return
	}
	if req.OffsetMs < -maxOffsetMs || req.OffsetMs > maxOffsetMs {
		writeError(
			w,
			http.StatusBadRequest,
			fmt.Sprintf("offset_ms out of range (limit +/-%d)", maxOffsetMs),
		)
		return
	}

	before := nowSample()
	offset := time.Duration(req.OffsetSeconds)*time.Second +
		time.Duration(req.OffsetMs)*time.Millisecond
	target := time.Now().Add(offset)
	tv := syscall.NsecToTimeval(target.UnixNano())
	if err := syscall.Settimeofday(&tv); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("settimeofday: %v", err))
		return
	}
	after := nowSample()
	writeJSON(w, http.StatusOK, map[string]any{
		"before": before,
		"after":  after,
	})
}

func observe(t *telemetry, route string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := t.tracer.Start(r.Context(), route)
		defer span.End()

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rec, r.WithContext(ctx))

		attrs := []attribute.KeyValue{
			attribute.String("route", route),
			attribute.Int("status", rec.status),
		}
		span.SetAttributes(attrs...)
		t.requests.Add(ctx, 1, metric.WithAttributes(attrs...))
		t.Log(ctx, otellog.SeverityInfo, "handled "+route, attrs...)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "7074"
	}
	addr := "127.0.0.1:" + port

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	tel, err := startTelemetry(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "testapp: telemetry: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tel.Shutdown(flushCtx)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /test/health", observe(tel, "health", handleHealth))
	mux.HandleFunc("GET /test/env/{name}", observe(tel, "env", handleEnv))
	mux.HandleFunc("GET /test/clock", observe(tel, "clock_get", handleClockGet))
	mux.HandleFunc("POST /test/clock", observe(tel, "clock_set", handleClockSet))

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	tel.Log(ctx, otellog.SeverityInfo, "testapp started",
		attribute.String("addr", addr))
	fmt.Fprintf(os.Stderr, "testapp: serving on %s\n", addr)

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "testapp: %v\n", err)
		os.Exit(1)
	}
}
