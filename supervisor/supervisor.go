// Package supervisor implements the host-side supervisor for the enclave.
// The package main entry point lives in supervisor/cmd/supervisor/main.go.
//
// Runs on the EC2 host (not inside the enclave) and exposes:
//   - GET  /health                   — enclave status via nitro-cli
//   - GET  /supervisor/health        — supervisor self-readiness
//   - GET  /metrics                  — proxied nitriding Prometheus metrics + host metrics
//   - GET  /enclave-metrics          — proxied JSON metrics snapshot
//   - GET  /enclave-logs             — live proxy or CloudWatch Logs history
//   - GET  /enclave-traces           — live proxy or CloudWatch Logs history
//   - POST /start                    — start the enclave (Lifecycle)
//   - POST /stop                     — stop the enclave (Lifecycle)
//   - POST /schedule-key-deletion    — schedule the primary KMS key for deletion
//   - POST /migrate                  — finalise and/or orchestrate migration
//   - POST /migrate/request          — publish a migration intent via the enclave
//   - POST /migrate/abort            — publish a migration abort via the enclave
//
// Listens on 127.0.0.1:8443 (plain HTTP, localhost only). External access
// goes through SSM Run Command, gated by IAM.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"golang.org/x/sync/errgroup"
)

// ErrSelfUpdateExit signals the self-update goroutine requested a clean
// process exit. Run returns it; the cmd-level main treats it as exit 0.
var ErrSelfUpdateExit = errors.New("supervisor self-update: clean exit")

// Supervisor composes every subsystem and runs them under a single
// errgroup driven by Run.
type Supervisor struct {
	aws           *AWSClient
	lifecycle     *Lifecycle
	migration     *Migration
	observability *Observability
	networking    *Networking
	health        *Health

	addr     string
	server   *http.Server
	shutdown chan struct{} // signalled by Migration after a successful self-update
}

func New(ctx context.Context) (*Supervisor, error) {
	if err := validateEnvironment(); err != nil {
		return nil, err
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(getRegion()))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	awsClient := NewAWSClient(cfg)

	lifecycle, err := NewLifecycle()
	if err != nil {
		return nil, fmt.Errorf("lifecycle init: %w", err)
	}

	s := &Supervisor{
		aws:        awsClient,
		lifecycle:  lifecycle,
		networking: NewNetworking(),
		shutdown:   make(chan struct{}, 1),
		addr:       getSupervisorAddr(),
	}
	s.migration = NewMigration(awsClient, lifecycle, s.RequestShutdown)
	s.observability = NewObservability(awsClient)
	s.health = NewHealth(awsClient, s.migration.InProgress)

	mux := http.NewServeMux()
	s.health.RegisterRoutes(mux)
	s.lifecycle.RegisterRoutes(mux)
	s.migration.RegisterRoutes(mux)
	s.observability.RegisterRoutes(mux)

	s.server = &http.Server{
		Addr:           s.addr,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   180 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	return s, nil
}

// RequestShutdown is the Migration → Supervisor handoff after a successful
// self-update. Non-blocking send so the handler never wedges.
func (s *Supervisor) RequestShutdown() {
	select {
	case s.shutdown <- struct{}{}:
	default:
	}
}

// Run drives all subsystems until ctx cancellation or a fatal error.
// systemd Restart=always brings the process back; ErrSelfUpdateExit is
// the one error the cmd-level main treats as a clean exit.
func (s *Supervisor) Run(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.networking.Run(gctx) })

	g.Go(func() error {
		// Wait for gvproxy to bind vsock:1024 before booting the enclave.
		select {
		case <-s.networking.Ready():
		case <-gctx.Done():
			return nil
		}
		return s.lifecycle.Run(gctx)
	})

	g.Go(func() error {
		select {
		case <-gctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.server.Shutdown(shutdownCtx)
			return nil
		case <-s.shutdown:
			// Let the in-flight HTTP response flush before tearing down.
			// Returning ErrSelfUpdateExit cancels gctx → networking and
			// lifecycle exit → systemd respawns the new binary.
			slog.Info("supervisor update handoff — shutting down so systemd relaunches new binary")
			time.Sleep(500 * time.Millisecond)
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.server.Shutdown(shutdownCtx)
			return ErrSelfUpdateExit
		}
	})

	g.Go(func() error {
		slog.Info("management server started", "addr", s.addr,
			"deployment", getDeployment(), "app", getAppName())
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	})

	return g.Wait()
}
