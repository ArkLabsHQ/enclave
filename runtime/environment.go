package runtime

import (
	"context"
	"encoding/json"
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

// ParamPrefix selects the SSM parameter namespace for ciphertext reads/writes.
// PrimaryPrefix targets the canonical paths; MigrationPrefix targets the
// /Migration/* staging paths used during a locked-key migration.
type ParamPrefix string

const (
	PrimaryPrefix   ParamPrefix = ""
	MigrationPrefix ParamPrefix = "Migration/"
)

// secretParamName builds the SSM path for a secret's ciphertext, scoped by
// ParamPrefix.
func secretParamName(secretName string, prefix ParamPrefix) string {
	return fmt.Sprintf("/%s/%s/%s%s/Ciphertext", getDeployment(), getAppName(), prefix, secretName)
}

// ssmGetter is a minimal subset of *ssm.Client so applyEnvOverrides can
// take a fake in unit tests without an AWSClient.
type ssmGetter interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// Environment is the boot-time env-overlay step.
type Environment struct {
	aws *AWSClient
}

func NewEnvironment(aws *AWSClient) *Environment {
	return &Environment{aws: aws}
}

// Override reads ENCLAVE_APP_ENV_KEYS (a JSON list of app.env keys baked
// into the EIF and attested via PCR0) and, for each key, overlays the
// tofu-supplied SSM value at /<deployment>/<app>/env/<key> on top of the
// baked default. Missing params (ParameterNotFound) leave the default intact.
func (e *Environment) Override(ctx context.Context) error {
	return applyEnvOverrides(ctx, e.aws.SSM, getDeployment(), getAppName())
}

func applyEnvOverrides(ctx context.Context, ssmClient ssmGetter, deployment, appName string) error {
	raw := os.Getenv("ENCLAVE_APP_ENV_KEYS")
	if raw == "" || raw == "[]" {
		return nil
	}
	var keys []string
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		return fmt.Errorf("parse ENCLAVE_APP_ENV_KEYS: %w", err)
	}
	for _, key := range keys {
		paramName := fmt.Sprintf("/%s/%s/env/%s", deployment, appName, key)
		out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
			Name:           aws.String(paramName),
			WithDecryption: aws.Bool(false),
		})
		if err != nil {
			var pnf *ssmtypes.ParameterNotFound
			if errors.As(err, &pnf) {
				continue
			}
			return fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
		}
		if out.Parameter == nil || out.Parameter.Value == nil {
			continue
		}
		value := *out.Parameter.Value
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("setenv %s: %w", key, err)
		}
		slog.Info("app.env override applied", "key", key)
	}
	return nil
}
