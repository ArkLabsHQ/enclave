package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// Single home for every ENCLAVE_* business-config read in the runtime
// package. Infrastructure boilerplate (AWS SDK endpoints, nitriding,
// viproxy, cmd-level) stays with its consumer.

func getDeployment() string {
	if d := strings.TrimSpace(os.Getenv("ENCLAVE_DEPLOYMENT")); d != "" {
		return d
	}
	return "dev"
}

// nonOverridableEnv lists framework-identity vars the SSM env overlay must
// never set. They are baked into the EIF (measured into PCR0) and define the
// SSM/KMS namespace, the set of managed secrets, and security-critical timing;
// letting the overlay change them would redirect the namespace, flip checks
// like COSE skip or the KMS lock posture, or alter which secrets exist.
var nonOverridableEnv = map[string]bool{
	"ENCLAVE_DEPLOYMENT":         true,
	"ENCLAVE_APP_NAME":           true,
	"ENCLAVE_KMS_KEY_LOCKED":     true,
	"ENCLAVE_MIGRATION_COOLDOWN": true,
	"ENCLAVE_SECRETS_CONFIG":     true,
}

// skipCOSEVerification bypasses COSE verification only for the "dev" deployment,
// whose local QEMU NSM produces unsigned mock documents. Any other deployment
// verifies against the AWS Nitro root. The deployment is baked into the EIF at
// build time (measured into PCR0) and cannot be set via the SSM env overlay
// (nonOverridableEnv), so this security-critical check cannot be flipped at
// deploy time.
func skipCOSEVerification() bool {
	return getDeployment() == "dev"
}

func getAppName() string {
	if name := strings.TrimSpace(os.Getenv("ENCLAVE_APP_NAME")); name != "" {
		return name
	}
	return "app"
}

func getStaticSecretsConfig() string {
	return os.Getenv("ENCLAVE_SECRETS_CONFIG")
}

// kmsKeyLocked: when true, the KMS policy is built in strict mode (no root
// recovery principal). The choice is permanent at first lock.
func kmsKeyLocked() bool {
	return os.Getenv("ENCLAVE_KMS_KEY_LOCKED") == "true"
}

// lockSegment is the SSM namespace segment ("locked"|"unlocked") inserted after
// /{deployment}/{app}/ in every KMS-subtree path, so the lock posture is an
// IAM-enforceable boundary: a locked deployment can never read or write the
// unlocked namespace's key or ciphertexts (and vice versa).
func lockSegment() string {
	if kmsKeyLocked() {
		return "locked"
	}
	return "unlocked"
}

// kmsKeyIDParam: SSM path for the primary KMS key ID, lock-scoped.
func kmsKeyIDParam() string {
	return fmt.Sprintf("/%s/%s/%s/KMSKeyID", getDeployment(), getAppName(), lockSegment())
}

func getMigrationCooldown() time.Duration {
	v := strings.TrimSpace(os.Getenv("ENCLAVE_MIGRATION_COOLDOWN"))
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0
	}
	return d
}

func logBufferSize() int {
	if s := os.Getenv("ENCLAVE_LOG_BUFFER_SIZE"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			return n
		}
	}
	return 1000
}

func cloudwatchLogsEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("ENCLAVE_LOG_CLOUDWATCH")), "true")
}

func logShipInterval() time.Duration {
	if s := os.Getenv("ENCLAVE_LOG_SHIP_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil && d > 0 {
			return d
		}
	}
	return 5 * time.Second
}

func logRetentionDays() int32 {
	if s := os.Getenv("ENCLAVE_LOG_RETENTION_DAYS"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			return int32(n)
		}
	}
	return 30
}

func spanBufferSize() int {
	if s := os.Getenv("ENCLAVE_SPAN_BUFFER_SIZE"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			return n
		}
	}
	return 1000
}

// secretCiphertextParam: SSM path for a secret's KMS ciphertext, lock-scoped and
// scoped by the KMS key ID. Flipping the KMSKeyID param is the atomic migration commit.
func secretCiphertextParam(secretName, keyID string) string {
	return fmt.Sprintf("/%s/%s/%s/%s/Ciphertext/%s", getDeployment(), getAppName(), lockSegment(), secretName, keyID)
}

// storageDEKCiphertextParam: SSM path for the storage DEK's KMS ciphertext, lock-scoped and key-scoped.
func storageDEKCiphertextParam(keyID string) string {
	return fmt.Sprintf("/%s/%s/%s/StorageDEK/Ciphertext/%s", getDeployment(), getAppName(), lockSegment(), keyID)
}

// ssmGetter is a minimal subset of *ssm.Client. GetParameter is still used by
// loadDeployTLSConfig for known one-off lookups; GetParametersByPath drives
// the deploy-time env overlay (no need to enumerate keys at build time).
type ssmGetter interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
}

// Environment is the boot-time env-overlay step.
type Environment struct {
	aws *AWSClient
}

func NewEnvironment(aws *AWSClient) *Environment {
	return &Environment{aws: aws}
}

// Override scans /<deployment>/<app>/env/ in SSM and overlays every key
// found there onto the process env, on top of any defaults baked into the
// EIF. Trust boundary is the IAM grant on that SSM prefix.
func (e *Environment) Override(ctx context.Context) error {
	return applyEnvOverrides(ctx, e.aws.SSM, getDeployment(), getAppName())
}

func applyEnvOverrides(ctx context.Context, ssmClient ssmGetter, deployment, appName string) error {
	prefix := fmt.Sprintf("/%s/%s/env/", deployment, appName)
	var nextToken *string
	var applied int
	for {
		out, err := ssmClient.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{
			Path:           aws.String(prefix),
			Recursive:      aws.Bool(false),
			WithDecryption: aws.Bool(true),
			NextToken:      nextToken,
		})
		if err != nil {
			return fmt.Errorf("ssm get-parameters-by-path %s: %w", prefix, err)
		}
		for _, p := range out.Parameters {
			if p.Name == nil || p.Value == nil {
				continue
			}
			key := strings.TrimPrefix(*p.Name, prefix)
			// Defensive: skip empty or nested keys so a misconfigured SSM
			// tree can't surface unexpected env var names.
			if key == "" || strings.ContainsRune(key, '/') {
				continue
			}
			// Never let the overlay change the framework identity: these are
			// baked into the EIF (measured into PCR0) and name the SSM/KMS
			// namespace. Allowing an SSM writer to set them would redirect the
			// namespace or flip security-critical checks (e.g. COSE skip).
			if nonOverridableEnv[key] {
				slog.Warn("ignoring non-overridable env var from SSM overlay", "key", key)
				continue
			}
			if err := os.Setenv(key, *p.Value); err != nil {
				return fmt.Errorf("setenv %s: %w", key, err)
			}
			applied++
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	slog.Info("env overrides applied", "count", applied, "prefix", prefix)
	return nil
}

// deployTLSConfig is the TLS configuration resolved at boot from SSM. tofu
// publishes it (from enclave.yaml's tls: block) under /<deployment>/<app>/env/.
type deployTLSConfig struct {
	FQDN      string
	UseACME   bool
	Directory string // "letsencrypt" | "letsencrypt-staging" | "self-signed" | a literal https:// directory URL
	Email     string
	CA        string // optional PEM CA bundle for a custom ACME directory's HTTPS API
}

// loadDeployTLSConfig reads the ENCLAVE_NITRIDING_* TLS settings tofu wrote to
// SSM under /<deployment>/<app>/env/. Absent params keep the defaults
// (self-signed, localhost) — the common case when no domain is configured. A
// non-NotFound SSM error is returned so the caller can fail the boot.
func loadDeployTLSConfig(ctx context.Context, ssmClient ssmGetter) (deployTLSConfig, error) {
	t := deployTLSConfig{FQDN: "localhost", Directory: "self-signed"}
	dep, app := getDeployment(), getAppName()

	get := func(key string) (string, error) {
		name := fmt.Sprintf("/%s/%s/env/%s", dep, app, key)
		out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
			Name:           aws.String(name),
			WithDecryption: aws.Bool(false),
		})
		if err != nil {
			var pnf *ssmtypes.ParameterNotFound
			if errors.As(err, &pnf) {
				return "", nil
			}
			return "", fmt.Errorf("ssm get-parameter %s: %w", name, err)
		}
		if out.Parameter == nil || out.Parameter.Value == nil {
			return "", nil
		}
		return strings.TrimSpace(*out.Parameter.Value), nil
	}

	fqdn, err := get("ENCLAVE_NITRIDING_FQDN")
	if err != nil {
		return t, err
	}
	if fqdn != "" {
		t.FQDN = fqdn
	}
	useACME, err := get("ENCLAVE_NITRIDING_USE_ACME")
	if err != nil {
		return t, err
	}
	t.UseACME = strings.EqualFold(useACME, "true")
	dir, err := get("ENCLAVE_NITRIDING_ACME_DIRECTORY")
	if err != nil {
		return t, err
	}
	if dir != "" {
		t.Directory = dir
	}
	email, err := get("ENCLAVE_NITRIDING_ACME_EMAIL")
	if err != nil {
		return t, err
	}
	t.Email = email
	ca, err := get("ENCLAVE_NITRIDING_ACME_CA")
	if err != nil {
		return t, err
	}
	t.CA = ca
	return t, nil
}
