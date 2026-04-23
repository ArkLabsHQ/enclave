package supervisor

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
)

// runValidation performs pre-flight checks used by the atomic supervisor self-update
// flow. Called when ENCLAVE_SUPERVISOR_VALIDATE=1 is set — the new binary runs these
// checks and exits (without binding the HTTP port) so the helper script can
// decide whether it's safe to promote the staged binary to the live one.
//
// Returns non-nil on any failure: AWS auth, SSM reachability, KMS key known.
// Does NOT verify the enclave is reachable (the enclave may be stopped during
// restart) — that's verified post-swap via /supervisor/health polling.
func runValidation(ctx context.Context, awsCfg aws.Config, deployment, appName string) error {
	_ = awscfg.WithRegion // imported for consistency with main.go

	// 1. STS GetCallerIdentity — verifies the IAM role is usable.
	stsClient := sts.NewFromConfig(awsCfg)
	ident, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("sts get-caller-identity: %w", err)
	}
	if ident.Arn == nil || *ident.Arn == "" {
		return fmt.Errorf("sts returned empty ARN")
	}

	// 2. SSM GetParameter — verifies SSM is reachable and the deployment exists.
	ssmClient := ssm.NewFromConfig(awsCfg)
	paramName := fmt.Sprintf("/%s/%s/KMSKeyID", deployment, appName)
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name: aws.String(paramName),
	})
	if err != nil {
		return fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil || *out.Parameter.Value == "" {
		return fmt.Errorf("KMSKeyID not set in SSM at %s", paramName)
	}

	return nil
}
