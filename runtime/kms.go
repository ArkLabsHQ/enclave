package runtime

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	kmscmd "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	stscmd "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/edgebitio/nitro-enclaves-sdk-go/crypto/cms"
)

const (
	keyStateExists          = "exists"
	keyStatePendingDeletion = "pending_deletion"
	keyStateDeleted         = "deleted"
	keyStateUnknown         = "unknown"
	keyProbeTimeout         = 5 * time.Second
)

type kmsW struct {
	cfg   *Config
	nsm   NSM
	kms   KMSAPI
	sts   STSAPI
	keyID string
}

type DataKey struct {
	Ciphertext []byte
	Plaintext  []byte
}

type KeyStatus struct {
	State        string
	DeletionDate *time.Time
	Reason       string
}

type KMS interface {
	KeyID() string
	GenerateDataKey(ctx context.Context) (*DataKey, error)
	Encrypt(ctx context.Context, plaintext []byte) (string, error)
	Decrypt(ctx context.Context, ciphertext string) ([]byte, error)
}

type PrimaryKMS interface {
	KMS
	KeyAuditor
	CreateMigrationKMS(ctx context.Context, newPCR0 string) (KMS, error)
}

type KeyAuditor interface {
	KeyStatus(ctx context.Context, keyID string) KeyStatus
}

// FetchOrCreatePrimaryKMS returns the key at keyID after proving its policy
// admits this enclave's PCR0 and nothing else, or mints a genesis key when
// keyID is empty. Every key — genesis or migration — admits exactly one PCR0.
func FetchOrCreatePrimaryKMS(
	ctx context.Context,
	cfg *Config,
	nsm NSM,
	kms KMSAPI,
	sts STSAPI,
	keyID string,
) (PrimaryKMS, error) {
	curPCR0, err := nsm.PCR0()
	if err != nil {
		return nil, fmt.Errorf("could not read PCR0 from NSM")
	}
	curPCR0Hex := hex.EncodeToString(curPCR0)

	if keyID != "" {
		out, err := kms.GetKeyPolicy(ctx, &kmscmd.GetKeyPolicyInput{
			KeyId:      aws.String(keyID),
			PolicyName: aws.String("default"),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to fetch KMS key policy: %s - %w", keyID, err)
		}

		if out.Policy == nil {
			return nil, fmt.Errorf("KMS key policy empty: %s", keyID)
		}

		if err := VerifyKeyPolicyPosture(
			*out.Policy, []string{curPCR0Hex}, cfg.KMSLocked,
		); err != nil {
			return nil, fmt.Errorf(
				"KMS key %s policy posture mismatch (ours: %s...): %w",
				keyID,
				curPCR0Hex[:16],
				err,
			)
		}

		return &kmsW{cfg: cfg, nsm: nsm, kms: kms, sts: sts, keyID: keyID}, nil
	}

	identity, err := sts.GetCallerIdentity(ctx, &stscmd.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("sts get-caller-identity: %w", err)
	}

	recoveryAccount := ""
	if !cfg.KMSLocked {
		recoveryAccount = *identity.Arn
	}

	policy, err := BuildKMSPolicy(
		*identity.Arn,
		[]string{curPCR0Hex},
		recoveryAccount,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build KMS policy: %w", err)
	}

	description := fmt.Sprintf("enclave genesis key for %s/%s", cfg.Deployment, cfg.AppName)

	createOut, err := kms.CreateKey(ctx, &kmscmd.CreateKeyInput{
		Description:                    aws.String(description),
		Policy:                         aws.String(policy),
		BypassPolicyLockoutSafetyCheck: true,
		Tags: []kmstypes.Tag{
			{TagKey: aws.String("AppName"), TagValue: aws.String(cfg.AppName)},
			{TagKey: aws.String("Deployment"), TagValue: aws.String(cfg.Deployment)},
			{TagKey: aws.String("ManagedBy"), TagValue: aws.String("enclave")},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("kms create-key: %w", err)
	}

	keyID = *createOut.KeyMetadata.KeyId

	slog.Info("created primary KMS key", "key_id", keyID, "pcr0", curPCR0Hex[:16])

	return &kmsW{cfg: cfg, nsm: nsm, kms: kms, sts: sts, keyID: keyID}, nil
}

func (k *kmsW) KeyID() string {
	return k.keyID
}

// Encrypt encrypts plaintext under keyID and returns base64 ciphertext.
func (k *kmsW) Encrypt(ctx context.Context, plaintext []byte) (string, error) {
	out, err := k.kms.Encrypt(ctx, &kmscmd.EncryptInput{
		KeyId:     aws.String(k.keyID),
		Plaintext: plaintext,
	})
	if err != nil {
		return "", fmt.Errorf("kms encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(out.CiphertextBlob), nil
}

// Decrypt unwraps base64 KMS ciphertext for this enclave.
func (k *kmsW) Decrypt(ctx context.Context, ciphertext string) ([]byte, error) {
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	attestationDoc, rsaPrivateKey, err := k.nsm.BuildAttestationDocument(WithPublicKey())
	if err != nil {
		return nil, err
	}

	out, err := k.kms.Decrypt(ctx, &kmscmd.DecryptInput{
		KeyId:          aws.String(k.keyID),
		CiphertextBlob: ciphertextBytes,
		Recipient: &kmstypes.RecipientInfo{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("kms decrypt input failed: %w", err)
	}

	if len(out.CiphertextForRecipient) == 0 {
		return nil, fmt.Errorf("kms decrypt returned empty CiphertextForRecipient")
	}

	plaintext, err := cms.DecryptEnvelopedKey(rsaPrivateKey, out.CiphertextForRecipient)
	if err != nil {
		return nil, fmt.Errorf("decrypt envelope failed: %w", err)
	}

	return plaintext, nil
}

// GenerateDataKey returns a fresh 32-byte key and KMS ciphertext to persist.
// NSM attestation makes KMS wrap plaintext to this enclave, not the host.
func (k *kmsW) GenerateDataKey(ctx context.Context) (*DataKey, error) {
	attestationDoc, rsaPrivateKey, err := k.nsm.BuildAttestationDocument(WithPublicKey())
	if err != nil {
		return nil, err
	}

	out, err := k.kms.GenerateDataKey(ctx, &kmscmd.GenerateDataKeyInput{
		KeyId:         aws.String(k.keyID),
		NumberOfBytes: aws.Int32(32),
		Recipient: &kmstypes.RecipientInfo{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("kms generate data key: %w", err)
	}
	if len(out.CiphertextForRecipient) == 0 {
		return nil, fmt.Errorf("kms generate data key returned empty CiphertextForRecipient")
	}
	plaintext, err := cms.DecryptEnvelopedKey(rsaPrivateKey, out.CiphertextForRecipient)
	if err != nil {
		return nil, fmt.Errorf("decrypt CiphertextForRecipient: %w", err)
	}
	return &DataKey{Ciphertext: out.CiphertextBlob, Plaintext: plaintext}, nil
}

// CreateMigrationKMS creates the successor's key, locked to the successor PCR0
// alone.
// Non-strict mode keeps root recovery, matching the primary key.
func (k *kmsW) CreateMigrationKMS(ctx context.Context, newPCR0 string) (KMS, error) {
	identity, err := k.sts.GetCallerIdentity(ctx, &stscmd.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("sts get-caller-identity: %w", err)
	}

	recoveryAccount := ""
	if !k.cfg.KMSLocked {
		recoveryAccount = *identity.Arn
	}

	policy, err := BuildKMSPolicy(*identity.Arn, []string{newPCR0}, recoveryAccount)
	if err != nil {
		return nil, fmt.Errorf("failed to build KMS policy: %w", err)
	}

	description := fmt.Sprintf("enclave migration key for %s/%s", k.cfg.Deployment, k.cfg.AppName)

	out, err := k.kms.CreateKey(ctx, &kmscmd.CreateKeyInput{
		Description:                    aws.String(description),
		Policy:                         aws.String(policy),
		BypassPolicyLockoutSafetyCheck: true,
		Tags: []kmstypes.Tag{
			{TagKey: aws.String("AppName"), TagValue: aws.String(k.cfg.AppName)},
			{TagKey: aws.String("Deployment"), TagValue: aws.String(k.cfg.Deployment)},
			{TagKey: aws.String("ManagedBy"), TagValue: aws.String("enclave")},
			{TagKey: aws.String("Purpose"), TagValue: aws.String("migration")},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("migration kms create-key: %w", err)
	}

	return &kmsW{
		cfg: k.cfg, nsm: k.nsm, kms: k.kms, keyID: *out.KeyMetadata.KeyId,
	}, nil
}

func (k *kmsW) KeyStatus(ctx context.Context, keyID string) KeyStatus {
	if keyID == "" {
		return KeyStatus{State: keyStateUnknown, Reason: "no KMS key ID to probe"}
	}
	ctx, cancel := context.WithTimeout(ctx, keyProbeTimeout)
	defer cancel()

	out, err := k.kms.DescribeKey(ctx, &kmscmd.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		var notFound *kmstypes.NotFoundException
		if errors.As(err, &notFound) {
			return KeyStatus{State: keyStateDeleted}
		}
		return KeyStatus{State: keyStateUnknown, Reason: fmt.Sprintf("describe_key: %v", err)}
	}
	if out == nil || out.KeyMetadata == nil {
		return KeyStatus{State: keyStateUnknown, Reason: "describe_key returned no key metadata"}
	}
	if out.KeyMetadata.KeyState == kmstypes.KeyStatePendingDeletion ||
		out.KeyMetadata.KeyState == kmstypes.KeyStatePendingReplicaDeletion {
		return KeyStatus{
			State: keyStatePendingDeletion, DeletionDate: out.KeyMetadata.DeletionDate,
		}
	}
	return KeyStatus{State: keyStateExists}
}
