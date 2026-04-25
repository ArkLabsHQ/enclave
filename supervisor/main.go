// Package supervisor implements the host-side supervisor server for the
// enclave. Called from supervisor/cmd/main.go.
//
// It runs on the EC2 host (not inside the enclave) and provides:
//   - GET  /health                   — enclave status via nitro-cli
//   - GET  /metrics                  — proxied nitriding Prometheus metrics + host metrics
//   - POST /start                    — start the enclave (via watchdog service)
//   - POST /stop                     — stop the enclave (via watchdog service)
//   - POST /schedule-key-deletion    — schedule KMS key for deletion
//   - POST /migrate                  — full locked-key migration (create key, export, restart)
//   - GET  /logs                     — proxied log entries from the in-enclave runtime
//
// The server listens on 127.0.0.1:8443 (plain HTTP, localhost only).
// Security: only reachable from the host itself. External access requires
// SSM Run Command, which is gated by IAM permissions.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/sync/errgroup"
)

// Execute runs the supervisor HTTP server until context cancellation.
func Execute() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	region := envOrDefault("ENCLAVE_AWS_REGION", "us-east-1")
	deployment := envOrDefault("ENCLAVE_DEPLOYMENT", "dev")
	appName := envOrDefault("ENCLAVE_APP_NAME", "app")

	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		slog.Error("load AWS config failed", "error", err)
		os.Exit(1)
	}

	// Validate mode: run init checks and exit without binding HTTP. Used by
	// the atomic supervisor binary self-update flow to verify the new binary can
	// authenticate with AWS before replacing the live binary.
	if os.Getenv("ENCLAVE_SUPERVISOR_VALIDATE") == "1" {
		validateCtx, validateCancel := context.WithTimeout(ctx, 30*time.Second)
		defer validateCancel()
		if err := runValidation(validateCtx, awsCfg, deployment, appName); err != nil {
			slog.Error("validation failed", "error", err)
			os.Exit(2)
		}
		slog.Info("validation passed")
		os.Exit(0)
	}

	// AWS clients with optional endpoint overrides for testing with mock services.
	var ssmClient *ssm.Client
	if ep := os.Getenv("AWS_ENDPOINT_URL_SSM"); ep != "" {
		ssmClient = ssm.NewFromConfig(awsCfg, func(o *ssm.Options) { o.BaseEndpoint = aws.String(ep) })
	} else {
		ssmClient = ssm.NewFromConfig(awsCfg)
	}

	var kmsClient *kms.Client
	if ep := os.Getenv("AWS_ENDPOINT_URL_KMS"); ep != "" {
		kmsClient = kms.NewFromConfig(awsCfg, func(o *kms.Options) { o.BaseEndpoint = aws.String(ep) })
	} else {
		kmsClient = kms.NewFromConfig(awsCfg)
	}

	var s3Client *s3.Client
	if ep := os.Getenv("AWS_ENDPOINT_URL_S3"); ep != "" {
		s3Client = s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(ep)
			o.UsePathStyle = true
		})
	} else {
		s3Client = s3.NewFromConfig(awsCfg)
	}

	var stsClient *sts.Client
	if ep := os.Getenv("AWS_ENDPOINT_URL_STS"); ep != "" {
		stsClient = sts.NewFromConfig(awsCfg, func(o *sts.Options) { o.BaseEndpoint = aws.String(ep) })
	} else {
		stsClient = sts.NewFromConfig(awsCfg)
	}

	cooldownStr := envOrDefault("ENCLAVE_MIGRATION_COOLDOWN", "0s")
	cooldown, err := time.ParseDuration(cooldownStr)
	if err != nil {
		slog.Error("invalid ENCLAVE_MIGRATION_COOLDOWN", "value", cooldownStr, "error", err)
		os.Exit(1)
	}

	var cwlClient *cloudwatchlogs.Client
	if ep := os.Getenv("AWS_ENDPOINT_URL_LOGS"); ep != "" {
		cwlClient = cloudwatchlogs.NewFromConfig(awsCfg, func(o *cloudwatchlogs.Options) { o.BaseEndpoint = aws.String(ep) })
	} else {
		cwlClient = cloudwatchlogs.NewFromConfig(awsCfg)
	}

	wd, err := newWatchdog()
	if err != nil {
		slog.Error("watchdog init failed", "error", err)
		os.Exit(1)
	}

	s := &server{
		deployment:        deployment,
		appName:           appName,
		region:            region,
		ssm:               ssmClient,
		kms:               kmsClient,
		s3Client:          s3Client,
		stsClient:         stsClient,
		cwlClient:         cwlClient,
		migrationCooldown: cooldown,
		exitAfterResponse: make(chan struct{}, 1),
		watchdog:          wd,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /supervisor/health", s.handleSupervisorHealth)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("POST /start", s.handleStart)
	mux.HandleFunc("POST /stop", s.handleStop)
	mux.HandleFunc("POST /schedule-key-deletion", s.handleScheduleKeyDeletion)
	mux.HandleFunc("POST /migrate", s.handleMigrate)
	mux.HandleFunc("POST /migrate/abort", s.handleMigrateAbort)
	mux.HandleFunc("GET /enclave-logs", s.handleLogs)
	mux.HandleFunc("GET /enclave-traces", s.handleTraces)
	mux.HandleFunc("GET /enclave-metrics", s.handleEnclaveMetrics)

	addr := envOrDefault("ENCLAVE_SUPERVISOR_ADDR", "127.0.0.1:8443")

	srv := &http.Server{
		Addr:           addr,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   180 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Coordinate subsystems with a single errgroup. If any fatal error fires
	// (gvproxy listener dies, nitro-cli missing, etc.), the rooted context
	// cancels and systemd Restart=always brings the supervisor back.
	g, gctx := errgroup.WithContext(ctx)

	gvproxyReady := make(chan struct{})
	g.Go(func() error { return runGvproxy(gctx, gvproxyReady) })
	g.Go(func() error { return runIMDSProxy(gctx) })

	g.Go(func() error {
		// Wait for gvproxy to bind vsock:1024 before booting the enclave —
		// the in-enclave nitriding daemon dials this immediately on start.
		select {
		case <-gvproxyReady:
		case <-gctx.Done():
			return nil
		}
		return wd.Run(gctx)
	})

	g.Go(func() error {
		select {
		case <-gctx.Done():
			// SIGINT/SIGTERM or subsystem failure — normal shutdown.
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = srv.Shutdown(shutdownCtx)
			return nil
		case <-s.exitAfterResponse:
			// handleMigrate finished a successful supervisor-binary update and is
			// handing off to the supervisor-relaunched new binary. Give the
			// HTTP response a moment to flush before tearing down.
			slog.Info("supervisor update handoff — shutting down so supervisor relaunches new binary")
			time.Sleep(500 * time.Millisecond)
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = srv.Shutdown(shutdownCtx)
			// Return sentinel so errgroup cancels gctx → gvproxy/IMDS/watchdog
			// exit → process terminates → relauncher spawns the new binary.
			return errSelfUpdateExit
		}
	})

	g.Go(func() error {
		slog.Info("management server started", "addr", addr, "deployment", deployment, "app", appName)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		if errors.Is(err, errSelfUpdateExit) {
			// Clean exit for supervisor self-update — relauncher will respawn
			// with the new binary.
			os.Exit(0)
		}
		slog.Error("supervisor exited with error", "error", err)
		os.Exit(1)
	}
}

// errSelfUpdateExit signals the self-update goroutine requested a clean
// process exit. errgroup.Wait returns it; main treats it as exit 0.
var errSelfUpdateExit = errors.New("supervisor self-update: clean exit")

type server struct {
	deployment        string
	appName           string
	region            string
	ssm               *ssm.Client
	kms               *kms.Client
	s3Client          *s3.Client
	stsClient         *sts.Client
	cwlClient         *cloudwatchlogs.Client
	watchdog          *Watchdog
	migrateMu         sync.Mutex
	migrationCooldown time.Duration
	migrationAbort    chan struct{}
	migrationAbortMu  sync.Mutex

	// exitAfterResponse is signalled by atomicSupervisorUpdate when the new supervisor
	// binary is ready to take over. main() selects on this to gracefully
	// shut down after the current HTTP response flushes, letting the
	// supervisor relaunch with the new binary. Buffer 1 + non-blocking
	// sends ensure the handler can't wedge.
	exitAfterResponse chan struct{}
}

func (s *server) ssmParam(name string) string {
	return fmt.Sprintf("/%s/%s/%s", s.deployment, s.appName, name)
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
