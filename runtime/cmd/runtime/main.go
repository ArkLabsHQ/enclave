package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	runtime "github.com/ArkLabsHQ/introspector-enclave/runtime"
	// Imported for its init() — seeds /dev/random from /dev/nsm before main()
	// runs. See runtime/nitriding/package_init.go.
	_ "github.com/ArkLabsHQ/introspector-enclave/runtime/nitriding"
)

func main() {
	if runtime.IsDev() {
		runtime.ApplyDevCmdlineOverrides()
	}

	cfg, err := runtime.LoadConfig()
	if err != nil {
		slog.Error("load runtime config", "error", err)
		os.Exit(1)
	}

	if cfg == nil {
		slog.Error("load runtime config", "error", "nil config")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := runtime.Run(ctx, *cfg); err != nil {
		slog.Error("runtime failed", "error", err)
		os.Exit(1)
	}
}
