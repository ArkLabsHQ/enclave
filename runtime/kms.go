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
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/edgebitio/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/hf/nsm"
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

// generateDataKey mints a fresh 256-bit data key under keyID and returns the
// KMS-wrapped ciphertext (to persist) alongside its plaintext. GenerateDataKey
// is PCR0-attestation-gated in the key policy, so the call carries a fresh NSM
// attestation as Recipient — the same mechanism the decrypt path uses — and the
// plaintext comes back encrypted to this enclave's ephemeral key (recovered from
// CiphertextForRecipient), never crossing the host in the clear.
func (k *KMS) generateDataKey(ctx context.Context, keyID string) (ciphertextBlob, plaintext []byte, err error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, nil, fmt.Errorf("open nsm session: %w", err)
	}
	defer func() { _ = session.Close() }()

	attestationDoc, rsaPrivateKey, err := buildAttestationDocument(session)
	if err != nil {
		return nil, nil, err
	}

	out, err := k.aws.KMS.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:         aws.String(keyID),
		NumberOfBytes: aws.Int32(32),
		Recipient: &kmstypes.RecipientInfo{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("kms generate data key: %w", err)
	}
	if len(out.CiphertextForRecipient) == 0 {
		return nil, nil, fmt.Errorf("kms generate data key returned empty CiphertextForRecipient")
	}
	plaintext, err = cms.DecryptEnvelopedKey(rsaPrivateKey, out.CiphertextForRecipient)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt CiphertextForRecipient: %w", err)
	}
	return out.CiphertextBlob, plaintext, nil
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

// EnsureKeyID returns the primary KMS key ID, creating one PCR0-locked at
// first boot if /<dep>/<app>/KMSKeyID is the tofu-provisioned "UNSET"
// placeholder. CreateKey carries the final policy in the same call, so no
// external principal ever holds authority over the key. A missing param (or
// any other read error) is fatal — the placeholder must exist, otherwise the
// runtime is pointed at the wrong SSM namespace and shouldn't silently mint
// a key there.
func (k *KMS) EnsureKeyID(ctx context.Context, pcr0 string) (string, error) {
	deployment := getDeployment()
	appName := getAppName()
	paramName := kmsKeyIDParam()

	out, err := k.aws.SSM.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		var pnf *ssmtypes.ParameterNotFound
		if errors.As(err, &pnf) {
			return "", fmt.Errorf("KMSKeyID placeholder missing at %s — tofu apply required", paramName)
		}
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter != nil && out.Parameter.Value != nil {
		if v := strings.TrimSpace(*out.Parameter.Value); v != "" && v != "UNSET" {
			return v, nil
		}
	}

	if pcr0 == "" {
		return "", fmt.Errorf("could not read PCR0 from NSM")
	}
	identity, err := k.aws.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("sts get-caller-identity: %w", err)
	}
	roleARN, err := assumedRoleARNToRoleARN(*identity.Arn)
	if err != nil {
		return "", fmt.Errorf("resolve IAM role ARN: %w", err)
	}
	builder := NewKMSPolicyBuilder().ForRole(roleARN).LockedToPCR0Values([]string{pcr0})
	if !kmsKeyLocked() {
		account, err := arnAccount(*identity.Arn)
		if err != nil {
			return "", fmt.Errorf("resolve AWS account ID for recovery principal: %w", err)
		}
		builder = builder.WithRootRecovery(account)
	}

	createOut, err := k.aws.KMS.CreateKey(ctx, &kms.CreateKeyInput{
		Description:                    aws.String(fmt.Sprintf("introspector-enclave primary key for %s/%s", deployment, appName)),
		Policy:                         aws.String(builder.Build()),
		BypassPolicyLockoutSafetyCheck: true,
		Tags: []kmstypes.Tag{
			{TagKey: aws.String("AppName"), TagValue: aws.String(appName)},
			{TagKey: aws.String("Deployment"), TagValue: aws.String(deployment)},
			{TagKey: aws.String("ManagedBy"), TagValue: aws.String("enclave")},
		},
	})
	if err != nil {
		return "", fmt.Errorf("kms create-key: %w", err)
	}
	keyID := *createOut.KeyMetadata.KeyId

	// Schedule the just-created key for deletion if anything from here on
	// fails before we successfully register it as the primary key.
	keyOK := false
	defer func() {
		if keyOK {
			return
		}
		pendingDays := keyDeletionPendingDays
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, delErr := k.aws.KMS.ScheduleKeyDeletion(cleanupCtx, &kms.ScheduleKeyDeletionInput{
			KeyId:               aws.String(keyID),
			PendingWindowInDays: &pendingDays,
		}); delErr != nil {
			slog.Warn("schedule unregistered primary key for deletion failed", "key_id", keyID, "error", delErr)
		}
	}()

	if _, err := k.aws.SSM.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(paramName),
		Value:     aws.String(keyID),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	}); err != nil {
		return "", fmt.Errorf("ssm put-parameter %s: %w", paramName, err)
	}

	registered, _ := k.readKMSKeyID(ctx, paramName)
	if registered != "" && registered != keyID {
		// Another enclave registered first; defer schedules ours for deletion.
		slog.Warn("another enclave registered a different KMS key, scheduling own key for deletion", "ours", keyID, "registered", registered)
		return registered, nil
	}

	keyOK = true
	slog.Info("created primary KMS key", "key_id", keyID, "pcr0", pcr0[:16])
	return keyID, nil
}

// CreateMigrationKey mints a fresh KMS key with policy locked to
// [ownPCR0, newPCR0] at CreateKey time. The EC2 role never holds
// kms:PutKeyPolicy on the key, so the PCR0 set is immutable from birth —
// the only window during which the policy could be set is the single
// CreateKey call itself, and that call carries the final policy. When the
// deployment runs in non-strict mode (!kmsKeyLocked()), RootRecovery is
// included from birth, matching the primary key's posture so root retains
// the same escape hatch across migration generations.
func (k *KMS) CreateMigrationKey(ctx context.Context, ownPCR0, newPCR0 string) (string, error) {
	deployment := getDeployment()
	appName := getAppName()
	identity, err := k.aws.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("sts get-caller-identity: %w", err)
	}
	roleARN, err := assumedRoleARNToRoleARN(*identity.Arn)
	if err != nil {
		return "", fmt.Errorf("resolve IAM role ARN: %w", err)
	}
	builder := NewKMSPolicyBuilder().
		ForRole(roleARN).
		LockedToPCR0Values([]string{ownPCR0, newPCR0})
	if !kmsKeyLocked() {
		account, err := arnAccount(*identity.Arn)
		if err != nil {
			return "", fmt.Errorf("resolve AWS account ID for recovery principal: %w", err)
		}
		builder = builder.WithRootRecovery(account)
	}
	out, err := k.aws.KMS.CreateKey(ctx, &kms.CreateKeyInput{
		Description:                    aws.String(fmt.Sprintf("introspector-enclave migration key for %s/%s", deployment, appName)),
		Policy:                         aws.String(builder.Build()),
		BypassPolicyLockoutSafetyCheck: true,
		Tags: []kmstypes.Tag{
			{TagKey: aws.String("AppName"), TagValue: aws.String(appName)},
			{TagKey: aws.String("Deployment"), TagValue: aws.String(deployment)},
			{TagKey: aws.String("ManagedBy"), TagValue: aws.String("enclave")},
			{TagKey: aws.String("Purpose"), TagValue: aws.String("migration")},
		},
	})
	if err != nil {
		return "", fmt.Errorf("kms create-key: %w", err)
	}
	return *out.KeyMetadata.KeyId, nil
}

// readKMSKeyID returns the current KMSKeyID value, or "" when the SSM param
// is missing or set to "UNSET". Distinguishes "no key yet" from a hard error.
func (k *KMS) readKMSKeyID(ctx context.Context, paramName string) (string, error) {
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
	v := strings.TrimSpace(*out.Parameter.Value)
	if v == "" || v == "UNSET" {
		return "", nil
	}
	return v, nil
}

func (k *KMS) PeekKeyID(ctx context.Context) (string, error) {
	return k.readKMSKeyID(ctx, kmsKeyIDParam())
}

// GetKeyID reads the primary KMS key ID from SSM at /<dep>/<app>/KMSKeyID.
func (k *KMS) GetKeyID(ctx context.Context) (string, error) {
	paramName := kmsKeyIDParam()
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

// VerifyKeyAuthorization errors unless keyID's policy admits this enclave's
// PCR0 for Decrypt AND has the expected lock posture: Decrypt is PCR0-gated
// (no un-gated decrypt path) and kms:PutKeyPolicy is held by nobody when locked
// / root-only when unlocked. Verification only — keys are policy-locked at
// CreateKey time.
func (k *KMS) VerifyKeyAuthorization(ctx context.Context, keyID, pcr0 string) error {
	if pcr0 == "" {
		return fmt.Errorf("could not read PCR0 from NSM")
	}
	out, err := k.aws.KMS.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
		KeyId:      aws.String(keyID),
		PolicyName: aws.String("default"),
	})
	if err != nil {
		return fmt.Errorf("get current KMS key policy: %w", err)
	}
	policyText := ""
	if out.Policy != nil {
		policyText = *out.Policy
	}
	if err := verifyKeyPolicyPosture(policyText, pcr0, kmsKeyLocked()); err != nil {
		return fmt.Errorf("KMS key %s policy posture (ours: %s...): %w", keyID, pcr0[:16], err)
	}
	return nil
}
