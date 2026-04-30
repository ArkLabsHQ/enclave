package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ArkLabsHQ/introspector-enclave/supervisor"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Validate mode is set by the self-update flow on a staged binary,
	// short-circuiting boot once preflight passes.
	if os.Getenv("ENCLAVE_SUPERVISOR_VALIDATE") == "1" {
		validateCtx, validateCancel := context.WithTimeout(ctx, 30*time.Second)
		defer validateCancel()
		if err := supervisor.Validate(validateCtx); err != nil {
			slog.Error("validation failed", "error", err)
			os.Exit(2)
		}
		slog.Info("validation passed")
		os.Exit(0)
	}

	sup, err := supervisor.New(ctx)
	if err != nil {
		slog.Error("supervisor init failed", "error", err)
		os.Exit(1)
	}

	if err := sup.Run(ctx); err != nil {
		if errors.Is(err, supervisor.ErrSelfUpdateExit) {
			os.Exit(0)
		}
		slog.Error("supervisor exited with error", "error", err)
		os.Exit(1)
	}
}
