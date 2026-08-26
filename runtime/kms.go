package runtime

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	kmscmd "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	stscmd "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/edgebitio/nitro-enclaves-sdk-go/crypto/cms"
)

type kmsW struct {
	nsm   NSM
	kms   KMSAPI
	sts   STSAPI
	keyID string
}

type DataKey struct {
	Ciphertext []byte
	Plaintext  []byte
}

type KMS interface {
	KeyID() string
	GenerateDataKey(ctx context.Context) (*DataKey, error)
	Encrypt(ctx context.Context, plaintext []byte) (string, error)
	Decrypt(ctx context.Context, ciphertext string) ([]byte, error)
}

type PrimaryKMS interface {
	KMS
	CreateMigrationKMS(ctx context.Context, newPCR0 string) (KMS, error)
}

func FetchOrCreatePrimaryKMS(
	ctx context.Context,
	nsm NSM,
	kms KMSAPI,
	sts STSAPI,
	keyID string,
	prevPCR0 string,
	migrationAttest string,
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
		expectedPCR0s := []string{curPCR0Hex}
		switch {
		case prevPCR0 == "":
			// genesis/current key
		case !strings.EqualFold(prevPCR0, curPCR0Hex):
			// normal migration successor boot
			expectedPCR0s = append(expectedPCR0s, prevPCR0)
		default:
			// rollback-to-self: derive failed target from policy, prove PCR31 committed it
			admitted, err := KeyPolicyAdmittedPCR0s(*out.Policy)
			if err != nil {
				return nil, err
			}
			if len(admitted) != 2 {
				return nil, fmt.Errorf(
					"rollback KMS policy must admit current PCR0 and one target PCR0",
				)
			}
			if !admitted[curPCR0Hex] {
				return nil, fmt.Errorf("rollback KMS policy does not admit current PCR0")
			}

			delete(admitted, curPCR0Hex)
			otherPCR0 := ""
			for k := range admitted {
				otherPCR0 = k
			}
			if migrationAttest == "" {
				return nil, fmt.Errorf("previous PCR0 attestation is required for rollback")
			}
			otherPCR0Bytes, err := hex.DecodeString(otherPCR0)
			if err != nil {
				return nil, fmt.Errorf("failed decode other admitted PCR0: %w", err)
			}
			// verify the rollback-from PCR0 was committed to in the migration attestation
			if err := nsm.VerifyAttestation(migrationAttest, map[uint]string{
				0:                 curPCR0Hex,
				migrationPCRIndex: hex.EncodeToString(pcrExtendFromZero(otherPCR0Bytes)),
			}, nil); err != nil {
				return nil, fmt.Errorf(
					"other admitted PCR0 does not match PCR31 in migration attestation: %w",
					err,
				)
			}

			expectedPCR0s = append(expectedPCR0s, otherPCR0)
		}

		if err := VerifyKeyPolicyPosture(*out.Policy, expectedPCR0s, kmsKeyLocked()); err != nil {
			return nil, fmt.Errorf(
				"KMS key %s policy posture mismatch (ours: %s...): %w",
				keyID,
				curPCR0Hex[:16],
				err,
			)
		}

		return &kmsW{nsm: nsm, kms: kms, sts: sts, keyID: keyID}, nil
	}

	identity, err := sts.GetCallerIdentity(ctx, &stscmd.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("sts get-caller-identity: %w", err)
	}

	recoveryAccount := ""
	if !kmsKeyLocked() {
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

	description := fmt.Sprintf("enclave genesis key for %s/%s", getDeployment(), getAppName())

	createOut, err := kms.CreateKey(ctx, &kmscmd.CreateKeyInput{
		Description:                    aws.String(description),
		Policy:                         aws.String(policy),
		BypassPolicyLockoutSafetyCheck: true,
		Tags: []kmstypes.Tag{
			{TagKey: aws.String("AppName"), TagValue: aws.String(getAppName())},
			{TagKey: aws.String("Deployment"), TagValue: aws.String(getDeployment())},
			{TagKey: aws.String("ManagedBy"), TagValue: aws.String("enclave")},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("kms create-key: %w", err)
	}

	keyID = *createOut.KeyMetadata.KeyId

	slog.Info("created primary KMS key", "key_id", keyID, "pcr0", curPCR0Hex[:16])

	return &kmsW{nsm: nsm, kms: kms, sts: sts, keyID: keyID}, nil
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

// CreateMigrationKMS creates a key locked to current and next PCR0.
// Non-strict mode keeps root recovery, matching the primary key.
func (k *kmsW) CreateMigrationKMS(ctx context.Context, newPCR0 string) (KMS, error) {
	identity, err := k.sts.GetCallerIdentity(ctx, &stscmd.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("sts get-caller-identity: %w", err)
	}

	curPCR0, err := k.nsm.PCR0()
	if err != nil {
		return nil, fmt.Errorf("could not read PCR0 from NSM")
	}

	recoveryAccount := ""
	if !kmsKeyLocked() {
		recoveryAccount = *identity.Arn
	}

	policy, err := BuildKMSPolicy(
		*identity.Arn,
		[]string{hex.EncodeToString(curPCR0), newPCR0},
		recoveryAccount,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build KMS policy: %w", err)
	}

	description := fmt.Sprintf("enclave migration key for %s/%s", getDeployment(), getAppName())

	out, err := k.kms.CreateKey(ctx, &kmscmd.CreateKeyInput{
		Description:                    aws.String(description),
		Policy:                         aws.String(policy),
		BypassPolicyLockoutSafetyCheck: true,
		Tags: []kmstypes.Tag{
			{TagKey: aws.String("AppName"), TagValue: aws.String(getAppName())},
			{TagKey: aws.String("Deployment"), TagValue: aws.String(getDeployment())},
			{TagKey: aws.String("ManagedBy"), TagValue: aws.String("enclave")},
			{TagKey: aws.String("Purpose"), TagValue: aws.String("migration")},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("migration kms create-key: %w", err)
	}

	return &kmsW{nsm: k.nsm, kms: k.kms, keyID: *out.KeyMetadata.KeyId}, nil
}
