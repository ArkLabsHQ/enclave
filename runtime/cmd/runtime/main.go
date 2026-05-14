package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	runtime "github.com/ArkLabsHQ/introspector-enclave/runtime"
	// Importing the nitriding package runs its init() before main(), which
	// calls maybeSeedEntropy() — pulling 2048 cryptographic bytes from /dev/nsm
	// via NSM GetRandom, writing them to /dev/random, and crediting the
	// kernel's entropy_avail counter via the RNDADDTOENTCNT ioctl. Replaces
	// the manual `dd if=/dev/nsm of=/dev/urandom` that lived in the old
	// start.sh entrypoint. See runtime/nitriding/system_linux.go.
	"github.com/ArkLabsHQ/introspector-enclave/runtime/nitriding"
)

func main() {
	enc, err := runtime.New()
	if err != nil {
		os.Exit(1)
	}

	// Set up logging: every slog call writes to both stderr (JSON) and the
	// LogBuffer (queryable via GET /v1/enclave-logs). Must happen before Init() so
	// init stages are captured.
	slog.SetDefault(slog.New(
		runtime.NewBufferHandler(enc.Logging()),
	))

	// Set up metrics: OTEL instruments + runtime/proc collector.
	runtime.InitMetrics()

	// Tracing was already initialised inside runtime.New(); the OTEL
	// TracerProvider is set as global. Just arrange for shutdown on exit.
	tracing := enc.Tracing()

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer func() { _ = tracing.Shutdown(ctx) }()

	// Point the Go DNS resolver at gvproxy's embedded DNS server. Nitriding's
	// writeResolvconf writes /run/resolvconf/resolv.conf, but the enclave
	// EIF rootfs doesn't symlink /etc/resolv.conf to that — so we write
	// directly here before any code does name resolution.
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
	// (443 by default) and reverse-proxies directly to the user app on
	// ENCLAVE_APP_PORT (7074) via h2c — see nitriding/enclave.go where
	// revProxy.Transport is wired with http2.Transport{AllowHTTP:true}.
	// Runtime management routes (/v1/enclave-*) are registered on the same
	// chi mux below, eliminating the legacy intermediate :7073 hop.
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

	// Register the runtime's management routes (/v1/enclave-*, /health) on
	// nitriding's pubSrv chi mux. chi routes more-specific patterns before
	// the /* catch-all that revProxies to the user app.
	appPort := envOr("ENCLAVE_APP_PORT", "7074")
	adminMux := http.NewServeMux()
	enc.RegisterRoutes(adminMux)
	adminMux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !enc.IsReady() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "initializing"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})
	pubMux := nitEnc.PubMux()
	pubMux.Handle("/v1/*", adminMux)
	pubMux.Handle("/health", adminMux)

	// Apply response-signing + logging middleware once, wrapping the whole
	// pubSrv handler so it sees every route (chi-internal /enclave/*,
	// /v1/*, /health, and the catch-all proxy to the user app).
	// enc.Middleware short-circuits to next.ServeHTTP for gRPC content-type
	// so streaming RPCs aren't buffered.
	nitEnc.UseMiddleware(enc.Middleware)
	nitEnc.UseMiddleware(runtime.LoggingMiddleware)

	// Internal admin listener on :7073 for loopback callbacks from the
	// user app (storage, secrets, traces, log emission). Plain HTTP, no
	// TLS, no reverse proxy — only management routes. The user app dials
	// this via http://127.0.0.1:7073 with the ENCLAVE_RUNTIME_TOKEN.
	// External clients always go through TLS on :443.
	proxyPort := envOr("ENCLAVE_PROXY_PORT", "7073")
	adminHandler := runtime.LoggingMiddleware(enc.Middleware(adminMux))
	adminSrv := &http.Server{
		Addr:        ":" + proxyPort,
		Handler:     adminHandler,
		ReadTimeout: 10 * time.Second,
		IdleTimeout: 120 * time.Second,
	}
	adminErr := make(chan error, 1)
	go func() {
		slog.Info("admin listener started", "port", proxyPort)
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			adminErr <- err
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = adminSrv.Shutdown(shutdownCtx)
	}()

	if err := nitEnc.Start(); err != nil {
		slog.Error("nitriding start", "error", err)
		os.Exit(1)
	}
	defer func() { _ = nitEnc.Stop() }()
	enc.SetAttestationRegistrar(nitEnc)

	// Bootstrap: attestation key, KMS secrets, PCR extension (may block).
	initCtx := ctx
	if t := envOr("ENCLAVE_INIT_TIMEOUT", ""); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			var cancel context.CancelFunc
			initCtx, cancel = context.WithTimeout(ctx, d)
			defer cancel()
			slog.Info("init timeout configured", "timeout", d.String())
		}
	}

	slog.Info("supervisor started", "app_port", appPort, "version", runtime.Version)

	if err := enc.Init(initCtx); err != nil {
		slog.Error("enclave init failed — app will NOT be started", "error", err)
		<-ctx.Done()
		slog.Info("shutting down (init failed, no child)")
	} else {
		// Start user's app as child process (env vars from KMS are ready).
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

		// Supervise: wait for child exit or shutdown signal.
		childDone := make(chan error, 1)
		go func() { childDone <- child.Wait() }()

		select {
		case err := <-childDone:
			if err != nil {
				slog.Error("child exited", "error", err)
			}
			stop()
		case err := <-adminErr:
			slog.Error("admin listener failed", "error", err)
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
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
