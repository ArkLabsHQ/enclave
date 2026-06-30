package supervisor

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Validate is the pre-flight check the supervisor self-update flow runs
// against a staged binary (ENCLAVE_SUPERVISOR_VALIDATE=1) before promoting
// it. Verifies AWS auth, SSM, and that KMSKeyID is set. Doesn't probe the
// enclave — that happens post-swap via /supervisor/health.
func Validate(ctx context.Context) error {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(getRegion()))
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	stsClient := sts.NewFromConfig(awsCfg)
	ident, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("sts get-caller-identity: %w", err)
	}
	if ident.Arn == nil || *ident.Arn == "" {
		return fmt.Errorf("sts returned empty ARN")
	}

	ssmClient := ssm.NewFromConfig(awsCfg)
	paramName := kmsSubtreeParamPath("KMSKeyID")
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
