package runtime

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// =============================================================================
// KMS subsystem
// =============================================================================

// KMS owns the runtime's interactions with AWS KMS — encryption,
// ciphertext storage in SSM, key-id lookup, and the self-apply boot-time
// policy lock that pins the KMS key to this enclave's PCR0. Holds a
// shared *AWSClient so no per-call SDK init.
type KMS struct {
	aws *AWSClient
}

// NewKMS constructs the subsystem.
func NewKMS(aws *AWSClient) *KMS {
	return &KMS{aws: aws}
}

// Encrypt encrypts plaintext under keyID and returns base64 ciphertext.
func (k *KMS) Encrypt(ctx context.Context, keyID string, plaintext []byte) (string, error) {
	out, err := k.aws.KMS.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(keyID),
		Plaintext: plaintext,
	})
	if err != nil {
		return "", fmt.Errorf("kms encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(out.CiphertextBlob), nil
}

// StoreCiphertext stores a base64 ciphertext in SSM at paramName.
func (k *KMS) StoreCiphertext(ctx context.Context, paramName, ciphertext string) error {
	_, err := k.aws.SSM.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(paramName),
		Value:     aws.String(ciphertext),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("ssm put-parameter %s: %w", paramName, err)
	}
	return nil
}

// LoadCiphertext fetches a base64 ciphertext from SSM. Returns "" on
// missing/UNSET (not an error — caller treats as "no ciphertext yet").
func (k *KMS) LoadCiphertext(ctx context.Context, paramName string) (string, error) {
	out, err := k.aws.SSM.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		var pnf *ssmtypes.ParameterNotFound
		if errors.As(err, &pnf) {
			return "", nil
		}
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", nil
	}
	value := strings.TrimSpace(*out.Parameter.Value)
	if value == "" || value == "UNSET" {
		return "", nil
	}
	return value, nil
}

// GetKeyID reads the primary KMS key ID from SSM at /<dep>/<app>/KMSKeyID.
func (k *KMS) GetKeyID(ctx context.Context) (string, error) {
	deployment := getDeployment()
	appName := getAppName()
	paramName := fmt.Sprintf("/%s/%s/KMSKeyID", deployment, appName)
	out, err := k.aws.SSM.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", fmt.Errorf("KMS key ID not found in SSM parameter %s", paramName)
	}
	v := strings.TrimSpace(*out.Parameter.Value)
	if v == "" || v == "UNSET" {
		return "", fmt.Errorf("KMS key ID not set in SSM parameter %s (value: %q)", paramName, v)
	}
	return v, nil
}

// SelfApplyPolicy applies the PCR0-restricted KMS key policy from inside
// the enclave. The enclave reads its own PCR0 from NSM hardware
// (unforgeable), derives its role ARN and account ID via STS, and calls
// PutKeyPolicy to restrict Decrypt to its own attestation identity.
//
// keyID may be empty to read the current key ID from SSM. Idempotent:
// no-op if already sealed to this PCR0; error if sealed to a different one.
func (k *KMS) SelfApplyPolicy(ctx context.Context, keyID string) error {
	if keyID == "" {
		var err error
		keyID, err = k.GetKeyID(ctx)
		if err != nil {
			return fmt.Errorf("get KMS key ID: %w", err)
		}
	}

	// Get own PCR0 from NSM hardware.
	pcr0 := getPCR0()
	if pcr0 == "" {
		return fmt.Errorf("could not read PCR0 from NSM")
	}

	// Read current key policy to determine state.
	currentPolicy, err := k.aws.KMS.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
		KeyId:      aws.String(keyID),
		PolicyName: aws.String("default"),
	})
	if err != nil {
		return fmt.Errorf("get current KMS key policy: %w", err)
	}

	policyText := ""
	if currentPolicy.Policy != nil {
		policyText = *currentPolicy.Policy
	}

	hasPCR0, hasPutKeyPolicy := parseKMSPolicyState(policyText, pcr0)

	// Sealed (no PutKeyPolicy): no-op if it's ours, fatal otherwise.
	// Otherwise (fresh key, or migration key still open) fall through and apply.
	if policyText != "" && !hasPutKeyPolicy {
		if hasPCR0 {
			slog.Info("KMS policy already locked to PCR0, skipping", "pcr0", pcr0[:16])
			return nil
		}
		return fmt.Errorf("KMS key is sealed to a different PCR0 (ours: %s...)", pcr0[:16])
	}

	// Get caller identity for role ARN and account ID.
	identity, err := k.aws.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("sts get-caller-identity: %w", err)
	}

	roleARN, err := assumedRoleARNToRoleARN(*identity.Arn)
	if err != nil {
		return fmt.Errorf("resolve IAM role ARN: %w", err)
	}

	builder := NewKMSPolicyBuilder().ForRole(roleARN).LockedToPCR0Values([]string{pcr0})
	if !kmsKeyLocked() {
		account, err := arnAccount(*identity.Arn)
		if err != nil {
			return fmt.Errorf("resolve AWS account ID for recovery principal: %w", err)
		}
		builder = builder.WithRootRecovery(account)
	}
	policy := builder.Build()

	// Retry with backoff to handle IAM propagation delay on fresh deploy.
	// BypassPolicyLockoutSafetyCheck is required because we're removing
	// PutKeyPolicy from everyone — the key becomes immutably locked.
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}
		_, err = k.aws.KMS.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{
			KeyId:                          aws.String(keyID),
			Policy:                         aws.String(policy),
			PolicyName:                     aws.String("default"),
			BypassPolicyLockoutSafetyCheck: true,
		})
		if err == nil {
			slog.Info("applied PCR0-restricted KMS policy", "pcr0", pcr0[:16])
			return nil
		}
		lastErr = err
		slog.Warn("PutKeyPolicy attempt failed", "attempt", attempt+1, "error", err)
	}

	return fmt.Errorf("kms put-key-policy after retries: %w", lastErr)
}
