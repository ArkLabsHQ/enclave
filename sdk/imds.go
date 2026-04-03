package sdk

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
)

// loadAWSConfigWithIMDS loads AWS config using the SDK's default credential chain.
// Inside the enclave, start.sh sets AWS_EC2_METADATA_SERVICE_ENDPOINT=http://127.0.0.1:80
// which points the SDK's built-in IMDS credential provider to viproxy. The SDK
// automatically refreshes credentials before they expire — no static snapshot.
func loadAWSConfigWithIMDS(ctx context.Context) (aws.Config, error) {
	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = os.Getenv("ENCLAVE_AWS_REGION")
	}
	if region == "" {
		region = os.Getenv("INTROSPECTOR_AWS_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}

	opts := []func(*awscfg.LoadOptions) error{
		awscfg.WithRegion(region),
		awscfg.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
	}

	// If IMDS endpoint is set via the standard env var, the SDK picks it up
	// automatically. For the legacy IMDS_ENDPOINT env var, explicitly configure it.
	if endpoint := os.Getenv("IMDS_ENDPOINT"); endpoint != "" && os.Getenv("AWS_EC2_METADATA_SERVICE_ENDPOINT") == "" {
		opts = append(opts, awscfg.WithEC2IMDSEndpoint("http://"+endpoint))
	}

	cfg, err := awscfg.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}

	return cfg, nil
}
