package runtime

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/edgebitio/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/hf/nsm"
)

// StaticSecret defines a secret managed by KMS inside the enclave runtime.
type StaticSecret struct {
	Name   string `json:"name"`
	EnvVar string `json:"env_var"`
}

// Static secrets are configured in enclave.yaml under `secrets:`. At boot, the
// supervisor either decrypts an existing KMS-encrypted ciphertext from SSM
// (one per secret), or generates a fresh 32-byte secret if none exists yet
// (primary mode only — never in migration mode). Each secret's plaintext is
// hex-encoded and exported into the configured env var, which the child app
// inherits via os.Environ().

// loadStaticSecret loads one secret's ciphertext from SSM and decrypts it with KMS.
// In primary mode (migrationMode=false), generates a fresh secret if missing.
// In migration mode (migrationMode=true), returns an error if the ciphertext
// is missing — NEVER generates fresh, which would orphan the real data.
func loadStaticSecret(ctx context.Context, secret StaticSecret, keyID, paramPrefix string, migrationMode bool) error {
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	ssmClient := newSSMClient(awsCfg)
	kmsClient := newKMSClient(awsCfg)

	paramName := getSecretSSMParamNameWithPrefix(secret.Name, paramPrefix)

	if keyID == "" {
		keyID, err = getKMSKeyID(ctx, ssmClient)
		if err != nil {
			return fmt.Errorf("get KMS key ID: %w", err)
		}
	}
	if keyID == "" {
		return fmt.Errorf("KMS key ID is empty")
	}

	ciphertextB64, err := loadCiphertextFromSSM(ctx, ssmClient, paramName)
	if err != nil {
		return err
	}

	if ciphertextB64 == "" {
		if migrationMode {
			return fmt.Errorf("migration ciphertext missing at %s — cannot generate fresh (would orphan data)", paramName)
		}
		return generateAndStoreSecret(ctx, kmsClient, ssmClient, keyID, paramName, secret.EnvVar)
	}

	return decryptExistingSecret(ctx, kmsClient, keyID, ciphertextB64, secret.EnvVar)
}

// generateAndStoreSecret uses KMS GenerateDataKey to produce a 32-byte
// secret with KMS hardware RNG, and stores the ciphertext in SSM.
func generateAndStoreSecret(ctx context.Context, kmsClient *kms.Client, ssmClient *ssm.Client, keyID, paramName, envVar string) error {
	out, err := kmsClient.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:         aws.String(keyID),
		NumberOfBytes: aws.Int32(32),
	})
	if err != nil {
		return fmt.Errorf("kms generate data key: %w", err)
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(out.CiphertextBlob)

	if err := storeCiphertextInSSM(ctx, ssmClient, paramName, ciphertextB64); err != nil {
		return err
	}

	secretHex := hex.EncodeToString(out.Plaintext)
	if err := safeSetenv(envVar, secretHex); err != nil {
		return fmt.Errorf("set %s: %w", envVar, err)
	}

	return nil
}

// decryptExistingSecret decrypts the ciphertext from SSM using KMS with attestation.
func decryptExistingSecret(ctx context.Context, kmsClient *kms.Client, keyID, ciphertextB64, envVar string) error {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return fmt.Errorf("decode ciphertext: %w", err)
	}

	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open nsm session: %w", err)
	}
	defer func() { _ = session.Close() }()

	attestationDoc, rsaPrivateKey, err := buildAttestationDocument(session)
	if err != nil {
		return err
	}

	input := &kms.DecryptInput{
		KeyId:          aws.String(keyID),
		CiphertextBlob: ciphertext,
		Recipient: &kmstypes.RecipientInfo{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
		},
	}

	out, err := kmsClient.Decrypt(ctx, input)
	if err != nil {
		return fmt.Errorf("kms decrypt: %w", err)
	}

	if len(out.CiphertextForRecipient) == 0 {
		return fmt.Errorf("kms decrypt returned empty CiphertextForRecipient")
	}

	plaintext, err := cms.DecryptEnvelopedKey(rsaPrivateKey, out.CiphertextForRecipient)
	if err != nil {
		return fmt.Errorf("decrypt CiphertextForRecipient: %w", err)
	}

	secretHex := normalizeSecretHex(plaintext)

	if err := safeSetenv(envVar, secretHex); err != nil {
		return fmt.Errorf("set %s: %w", envVar, err)
	}

	return nil
}

// normalizeSecretHex normalizes the secret to a hex string. KMS GenerateDataKey
// returns raw bytes, but secrets put via the management API may already be hex.
func normalizeSecretHex(plaintext []byte) string {
	candidate := strings.TrimSpace(string(plaintext))
	if len(candidate) == 64 {
		if _, err := hex.DecodeString(candidate); err == nil {
			return candidate
		}
	}
	return hex.EncodeToString(plaintext)
}
