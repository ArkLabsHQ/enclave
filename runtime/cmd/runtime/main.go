package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	runtime "github.com/ArkLabsHQ/introspector-enclave/runtime"
	"github.com/ArkLabsHQ/introspector-enclave/runtime/nitriding"
)

func main() {
	// 1. Create enclave (instant — no blocking work).
	enc, err := runtime.New()
	if err != nil {
		runtime.InitLogging() // fallback for early errors
		slog.Error("create enclave failed", "error", err)
		os.Exit(1)
	}

	// Set up logging: every slog call writes to both stderr (JSON) and the
	// LogBuffer (queryable via GET /v1/enclave-logs). Must happen before Init() so
	// init stages are captured.
	slog.SetDefault(slog.New(
		runtime.NewBufferHandler(enc.GetLogBuffer(), enc.GetLogShipCh()),
	))

	// Set up metrics: OTEL instruments + runtime/proc collector.
	runtime.InitMetrics()

	// Set up tracing: supervisor spans go directly into the SpanBuffer.
	shutdownTracing := runtime.StartSupervisorTracing(enc.GetSpanBuffer(), enc.GetSpanShipCh())

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer func() { _ = shutdownTracing(ctx) }()

	// Point the Go DNS resolver at gvproxy's embedded DNS server. Nitriding's
	// writeResolvconf writes /run/resolvconf/resolv.conf, but the enclave
	// EIF rootfs doesn't symlink /etc/resolv.conf to that — so we write
	// directly here before any code does name resolution. This replaces the
	// `echo "nameserver …" > /etc/resolv.conf` that used to live in
	// enclave/start.sh before the runtime absorbed the entrypoint.
	if err := os.WriteFile("/etc/resolv.conf", []byte("nameserver 192.168.127.1\n"), 0644); err != nil {
		// Best-effort; outside the enclave (e.g. local dev) /etc/ may be read-only.
		slog.Debug("write /etc/resolv.conf", "error", err)
	}

	// Start the in-process IMDS vsock forwarder first so the AWS SDK calls
	// nitriding makes during Start() (certcache, metrics) have working IMDS.
	if err := runtime.StartViproxy(); err != nil {
		slog.Error("viproxy start failed", "error", err)
		os.Exit(1)
	}

	// Build nitriding in-process. It terminates TLS on ENCLAVE_NITRIDING_EXT_PORT
	// (443 by default) and reverse-proxies to the runtime's own proxy server
	// on ENCLAVE_PROXY_PORT (7073). Replaces the former /app/nitriding daemon
	// that used to exec this runtime as -appcmd.
	nitCfg, err := runtime.BuildNitridingConfig()
	if err != nil {
		slog.Error("build nitriding config", "error", err)
		os.Exit(1)
	}
	nitEnc, err := nitriding.NewEnclave(nitCfg)
	if err != nil {
		slog.Error("nitriding NewEnclave", "error", err)
		os.Exit(1)
	}
	if err := nitEnc.Start(); err != nil {
		slog.Error("nitriding start", "error", err)
		os.Exit(1)
	}
	defer func() { _ = nitEnc.Stop() }()
	enc.SetAttestationRegistrar(nitEnc)

	// 2. Ports.
	proxyPort := envOr("ENCLAVE_PROXY_PORT", "7073")
	appPort := envOr("ENCLAVE_APP_PORT", "7074")

	// 3. Reverse proxy → user's app.
	upstream, _ := url.Parse("http://127.0.0.1:" + appPort)
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	// 4. Mux: management routes local, everything else proxied.
	mux := http.NewServeMux()
	enc.RegisterRoutes(mux) // /v1/enclave-info, /v1/export-key, /v1/storage, /v1/secrets

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !enc.IsReady() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "initializing"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})

	mux.Handle("/", proxy)
	handler := runtime.LoggingMiddleware(enc.Middleware(mux)) // log + sign all responses

	srv := &http.Server{
		Addr:         ":" + proxyPort,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 5. Start HTTP server immediately (management endpoints available during init).
	srvErr := make(chan error, 1)
	go func() {
		slog.Info("supervisor started", "proxy_port", proxyPort, "app_port", appPort, "version", runtime.Version)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			srvErr <- err
		}
	}()

	// 6. Bootstrap: attestation key, KMS secrets, PCR extension (may block).
	initCtx := ctx
	if t := envOr("ENCLAVE_INIT_TIMEOUT", ""); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			var cancel context.CancelFunc
			initCtx, cancel = context.WithTimeout(ctx, d)
			defer cancel()
			slog.Info("init timeout configured", "timeout", d.String())
		}
	}

	if err := enc.Init(initCtx); err != nil {
		slog.Error("enclave init failed — app will NOT be started", "error", err)
		select {
		case err := <-srvErr:
			slog.Error("server failed", "error", err)
			os.Exit(1)
		case <-ctx.Done():
			slog.Info("shutting down (init failed, no child)")
		}
	} else {
		// 7. Start user's app as child process (env vars from KMS are ready).
		appBinary := envOr("APP_BINARY_NAME", "app")
		appPath := fmt.Sprintf("/app/%s", appBinary)

		child := exec.Command(appPath)
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		child.Env = append(os.Environ(),
			"ENCLAVE_APP_PORT="+appPort,
			"PORT="+appPort,
			"ENCLAVE_RUNTIME_TOKEN="+enc.RuntimeToken(),
		)
		if err := child.Start(); err != nil {
			slog.Error("start child failed", "path", appPath, "error", err)
			os.Exit(1)
		}
		slog.Info("child started", "path", appPath, "pid", child.Process.Pid)

		// 8. Supervise: wait for child exit or shutdown signal.
		childDone := make(chan error, 1)
		go func() { childDone <- child.Wait() }()

		select {
		case err := <-childDone:
			if err != nil {
				slog.Error("child exited", "error", err)
			}
			stop()
		case err := <-srvErr:
			slog.Error("server failed", "error", err)
			_ = child.Process.Signal(syscall.SIGTERM)
			<-childDone
			os.Exit(1)
		case <-ctx.Done():
			slog.Info("shutting down")
			_ = child.Process.Signal(syscall.SIGTERM)
			select {
			case <-childDone:
			case <-time.After(10 * time.Second):
				slog.Warn("child did not exit, sending SIGKILL")
				_ = child.Process.Kill()
				<-childDone
			}
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
