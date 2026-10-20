package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	runtime "github.com/ArkLabsHQ/enclave/runtime"
	// Imported for its init() — seeds /dev/random from /dev/nsm before main()
	// runs. See runtime/nitriding/package_init.go.
	_ "github.com/ArkLabsHQ/enclave/runtime/nitriding"
)

func main() {
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

	// Run logs its own error, while telemetry can still export it.
	if err := runtime.Run(ctx, *cfg); err != nil {
		os.Exit(1)
	}
}
