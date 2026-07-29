// Minimal stdlib-only app for observing runtime env and testing clock recovery.
// It is exec'd as a root child with CAP_SYS_TIME, so /test/clock can call
// syscall.Settimeofday without adding a shell or other packages to the EIF.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"syscall"
	"time"
)

const maxOffsetS = 10

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

	before := nowSample()
	target := time.Now().Add(time.Duration(req.OffsetSeconds) * time.Second)
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

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "7074"
	}
	addr := "127.0.0.1:" + port

	mux := http.NewServeMux()
	mux.HandleFunc("GET /test/health", handleHealth)
	mux.HandleFunc("GET /test/env/{name}", handleEnv)
	mux.HandleFunc("GET /test/clock", handleClockGet)
	mux.HandleFunc("POST /test/clock", handleClockSet)

	fmt.Fprintf(os.Stderr, "testapp: serving on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "testapp: %v\n", err)
		os.Exit(1)
	}
}
