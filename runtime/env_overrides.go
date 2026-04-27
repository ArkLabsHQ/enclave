package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// ssmGetter is the subset of *ssm.Client used by applyEnvOverrides — kept
// minimal so tests can supply a fake.
type ssmGetter interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// applyEnvOverrides reads ENCLAVE_APP_ENV_KEYS (a JSON list of app.env keys
// baked into the EIF and attested via PCR0) and, for each key, fetches the
// tofu-supplied override from SSM at /<deployment>/<app>/env/<key>. When a
// param exists, its value replaces the baked default in os.Environ() so the
// child app inherits the override. Missing params (ParameterNotFound) leave
// the baked default intact.
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
