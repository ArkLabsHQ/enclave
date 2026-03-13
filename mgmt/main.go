// Package main implements a host-side management server for the enclave.
//
// It runs on the EC2 host (not inside the enclave) and provides:
//   - GET  /health                   — enclave status via nitro-cli
//   - GET  /metrics                  — proxied nitriding Prometheus metrics + host metrics
//   - POST /start                    — start the enclave (via watchdog service)
//   - POST /stop                     — stop the enclave (via watchdog service)
//   - POST /schedule-key-deletion    — schedule KMS key for deletion
//   - POST /migrate                  — full locked-key migration (create key, export, restart)
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
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

	mgmt := &server{
		deployment: deployment,
		appName:    appName,
		region:     region,
		ssm:        ssmClient,
		kms:        kmsClient,
		s3Client:   s3Client,
		stsClient:  stsClient,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", mgmt.handleHealth)
	mux.HandleFunc("GET /metrics", mgmt.handleMetrics)
	mux.HandleFunc("POST /start", mgmt.handleStart)
	mux.HandleFunc("POST /stop", mgmt.handleStop)
	mux.HandleFunc("POST /schedule-key-deletion", mgmt.handleScheduleKeyDeletion)
	mux.HandleFunc("POST /migrate", mgmt.handleMigrate)

	addr := envOrDefault("ENCLAVE_MGMT_ADDR", "127.0.0.1:8443")

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 180 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Printf("management server listening on %s (deployment=%s, app=%s)", addr, deployment, appName)
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
	s3Client   *s3.Client
	stsClient  *sts.Client
	migrateMu  sync.Mutex
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
