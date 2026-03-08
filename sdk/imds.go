package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// imdsCredentials holds temporary credentials fetched from IMDS.
type imdsCredentials struct {
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

// getIMDSEndpoint returns the IMDS endpoint, defaulting to 127.0.0.1 (viproxy).
func getIMDSEndpoint() string {
	if endpoint := os.Getenv("IMDS_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "127.0.0.1"
}

// fetchIMDSCredentials fetches temporary credentials from IMDS via viproxy.
func fetchIMDSCredentials(ctx context.Context) (*imdsCredentials, error) {
	endpoint := getIMDSEndpoint()
	client := &http.Client{Timeout: 5 * time.Second}

	tokenURL := fmt.Sprintf("http://%s/latest/api/token", endpoint)
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPut, tokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("fetch IMDS token: %w", err)
	}
	defer tokenResp.Body.Close()

	tokenBytes, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read IMDS token: %w", err)
	}
	token := string(tokenBytes)

	roleURL := fmt.Sprintf("http://%s/latest/meta-data/iam/security-credentials/", endpoint)
	roleReq, err := http.NewRequestWithContext(ctx, http.MethodGet, roleURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create role request: %w", err)
	}
	roleReq.Header.Set("X-aws-ec2-metadata-token", token)

	roleResp, err := client.Do(roleReq)
	if err != nil {
		return nil, fmt.Errorf("fetch IAM role: %w", err)
	}
	defer roleResp.Body.Close()

	roleBytes, err := io.ReadAll(roleResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read IAM role: %w", err)
	}
	roleName := strings.TrimSpace(string(roleBytes))

	credsURL := fmt.Sprintf("http://%s/latest/meta-data/iam/security-credentials/%s", endpoint, roleName)
	credsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, credsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create credentials request: %w", err)
	}
	credsReq.Header.Set("X-aws-ec2-metadata-token", token)

	credsResp, err := client.Do(credsReq)
	if err != nil {
		return nil, fmt.Errorf("fetch credentials: %w", err)
	}
	defer credsResp.Body.Close()

	var creds imdsCredentials
	if err := json.NewDecoder(credsResp.Body).Decode(&creds); err != nil {
		return nil, fmt.Errorf("decode credentials: %w", err)
	}
	return &creds, nil
}

// loadAWSConfigWithIMDS loads AWS config using credentials fetched manually from IMDS.
func loadAWSConfigWithIMDS(ctx context.Context) (aws.Config, error) {
	imdsCreds, err := fetchIMDSCredentials(ctx)
	if err != nil {
		return awscfg.LoadDefaultConfig(ctx)
	}

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

	cfg, err := awscfg.LoadDefaultConfig(ctx,
		awscfg.WithRegion(region),
		awscfg.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			imdsCreds.AccessKeyId,
			imdsCreds.SecretAccessKey,
			imdsCreds.Token,
		)),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS config with IMDS credentials: %w", err)
	}

	return cfg, nil
}
