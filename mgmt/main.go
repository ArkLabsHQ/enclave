// Package main implements a host-side management server for the enclave.
//
// It runs on the EC2 host (not inside the enclave) and provides:
//   - GET  /health                   — enclave status via nitro-cli
//   - GET  /metrics                  — proxied nitriding Prometheus metrics + host metrics
//   - POST /start                    — start the enclave (via watchdog service)
//   - POST /stop                     — stop the enclave (via watchdog service)
//   - POST /schedule-key-deletion    — schedule KMS key for deletion
//
// The server listens on 127.0.0.1:8443 (plain HTTP, localhost only).
// Security: only reachable from the host itself. External access requires
// SSM Run Command, which is gated by IAM permissions.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	region := envOrDefault("ENCLAVE_AWS_REGION", "us-east-1")
	deployment := envOrDefault("ENCLAVE_DEPLOYMENT", "dev")
	appName := envOrDefault("ENCLAVE_APP_NAME", "app")

	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		log.Fatalf("load AWS config: %v", err)
	}

	ssmClient := ssm.NewFromConfig(awsCfg)
	kmsClient := kms.NewFromConfig(awsCfg)

	mgmt := &server{
		deployment: deployment,
		appName:    appName,
		region:     region,
		ssm:        ssmClient,
		kms:        kmsClient,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", mgmt.handleHealth)
	mux.HandleFunc("GET /metrics", mgmt.handleMetrics)
	mux.HandleFunc("POST /start", mgmt.handleStart)
	mux.HandleFunc("POST /stop", mgmt.handleStop)
	mux.HandleFunc("POST /schedule-key-deletion", mgmt.handleScheduleKeyDeletion)

	srv := &http.Server{
		Addr:         "127.0.0.1:8443",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Printf("management server listening on 127.0.0.1:8443 (deployment=%s, app=%s)", deployment, appName)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

type server struct {
	deployment string
	appName    string
	region     string
	ssm        *ssm.Client
	kms        *kms.Client
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
