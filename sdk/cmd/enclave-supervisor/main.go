package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	sdk "github.com/ArkLabsHQ/introspector-enclave/sdk"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. Create enclave (instant — no blocking work).
	enc := sdk.New()

	// 2. Ports.
	proxyPort := envOr("ENCLAVE_PROXY_PORT", "7073")
	appPort := envOr("ENCLAVE_APP_PORT", "7074")

	// 3. Reverse proxy → user's app.
	upstream, _ := url.Parse("http://127.0.0.1:" + appPort)
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	// 4. Mux: management routes local, everything else proxied.
	mux := http.NewServeMux()
	enc.RegisterRoutes(mux) // /v1/enclave-info, /v1/export-key, /v1/extend-pcr, /v1/lock-pcr

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !enc.IsReady() {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"status": "initializing",
				"error":  enc.InitError(),
			})
			return
		}
		if enc.InitError() != "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"status": "degraded",
				"error":  enc.InitError(),
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})

	mux.Handle("/", proxy)
	handler := enc.Middleware(mux) // sign all responses

	srv := &http.Server{
		Addr:         ":" + proxyPort,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 5. Start HTTP server immediately (management endpoints available during init).
	go func() {
		log.Printf("supervisor :%s -> :%s (version=%s)", proxyPort, appPort, sdk.Version)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	// 6. Bootstrap: attestation key, KMS secrets, PCR extension (may block).
	if err := enc.Init(ctx); err != nil {
		log.Printf("enclave init error: %v", err)
	}

	// 7. Start user's app as child process (env vars from KMS are ready).
	appBinary := envOr("APP_BINARY_NAME", "app")
	appPath := fmt.Sprintf("/app/%s", appBinary)

	child := exec.Command(appPath)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = append(os.Environ(),
		"ENCLAVE_APP_PORT="+appPort,
		"PORT="+appPort,
		"ENCLAVE_MGMT_TOKEN="+enc.MgmtToken(),
	)
	if err := child.Start(); err != nil {
		log.Fatalf("start %s: %v", appPath, err)
	}
	log.Printf("child: %s pid=%d", appPath, child.Process.Pid)

	// 8. Supervise: wait for child exit or shutdown signal.
	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()

	select {
	case err := <-childDone:
		if err != nil {
			log.Printf("child exited: %v", err)
		}
		stop()
	case <-ctx.Done():
		log.Println("shutting down...")
		_ = child.Process.Signal(syscall.SIGTERM)
		select {
		case <-childDone:
		case <-time.After(10 * time.Second):
			log.Println("child did not exit, sending SIGKILL")
			_ = child.Process.Kill()
			<-childDone
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
