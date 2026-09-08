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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := runtime.Run(ctx); err != nil {
		slog.Error("runtime failed", "error", err)
		os.Exit(1)
	}
}
