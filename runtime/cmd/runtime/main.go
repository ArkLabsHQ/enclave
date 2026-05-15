package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	runtime "github.com/ArkLabsHQ/introspector-enclave/runtime"
	// Imported for its init() — seeds /dev/random from /dev/nsm before main()
	// runs. See runtime/nitriding/package_init.go.
	_ "github.com/ArkLabsHQ/introspector-enclave/runtime/nitriding"
)

func main() {
	cfg, err := runtime.BuildNitridingConfig()
	if err != nil {
		slog.Error("build runtime config", "error", err)
		os.Exit(1)
	}

	enc, err := runtime.New(cfg)
	if err != nil {
		slog.Error("runtime.New", "error", err)
		os.Exit(1)
	}

	// Route every slog call to both stderr and the LogBuffer so /v1/enclave-logs
	// can serve them. Must run before Init() so init stages are captured.
	slog.SetDefault(slog.New(
		runtime.NewBufferHandler(enc.Logging()),
	))

	runtime.InitMetrics()
	tracing := enc.Tracing()

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer func() { _ = tracing.Shutdown(ctx) }()

	// Point the Go resolver at gvproxy's DNS. The EIF rootfs doesn't
	// symlink /etc/resolv.conf, so we write it before any name resolution.
	if err := os.WriteFile("/etc/resolv.conf", []byte("nameserver 192.168.127.1\n"), 0644); err != nil {
		slog.Debug("write /etc/resolv.conf", "error", err)
	}

	// IMDS forwarder must be up before Start: certcache and metrics dial IMDS.
	if err := runtime.StartViproxy(); err != nil {
		slog.Error("viproxy start failed", "error", err)
		os.Exit(1)
	}

	enc.UseMiddleware(enc.Middleware)
	enc.UseMiddleware(runtime.LoggingMiddleware)

	if err := enc.Start(); err != nil {
		slog.Error("runtime.Start", "error", err)
		os.Exit(1)
	}
	defer func() { _ = enc.Stop() }()
	enc.SetAttestationRegistrar(enc)

	initCtx := ctx
	if t := envOr("ENCLAVE_INIT_TIMEOUT", ""); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			var cancel context.CancelFunc
			initCtx, cancel = context.WithTimeout(ctx, d)
			defer cancel()
			slog.Info("init timeout configured", "timeout", d.String())
		}
	}

	appPort := envOr("ENCLAVE_APP_PORT", "7074")
	slog.Info("supervisor started", "app_port", appPort, "version", runtime.Version)

	if err := enc.Init(initCtx); err != nil {
		slog.Error("enclave init failed — app will NOT be started", "error", err)
		<-ctx.Done()
		slog.Info("shutting down (init failed, no child)")
	} else {
		// Start the user app as a child process. ENCLAVE_PROXY_PORT points
		// at the private loopback listener (cfg.IntPort) for app callbacks.
		appBinary := envOr("APP_BINARY_NAME", "app")
		appPath := fmt.Sprintf("/app/%s", appBinary)

		child := exec.Command(appPath)
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		child.Env = append(os.Environ(),
			"ENCLAVE_APP_PORT="+appPort,
			"PORT="+appPort,
			"ENCLAVE_PROXY_PORT="+strconv.Itoa(int(cfg.IntPort)),
			"ENCLAVE_RUNTIME_TOKEN="+enc.RuntimeToken(),
		)
		if err := child.Start(); err != nil {
			slog.Error("start child failed", "path", appPath, "error", err)
			os.Exit(1)
		}
		slog.Info("child started", "path", appPath, "pid", child.Process.Pid)

		childDone := make(chan error, 1)
		go func() { childDone <- child.Wait() }()

		select {
		case err := <-childDone:
			if err != nil {
				slog.Error("child exited", "error", err)
			}
			stop()
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
