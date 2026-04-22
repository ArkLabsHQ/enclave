package sdk

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/edgebitio/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// attestationDocument represents the CBOR structure of a Nitro attestation document.
type attestationDocument struct {
	PCRs map[uint][]byte `cbor:"pcrs"`
}

// waitForSecretsFromKMS waits until all configured secrets are loaded from KMS.
// Times out after 5 minutes to prevent infinite retries on broken KMS.
//
// keyID specifies the KMS key to decrypt under. Pass empty string to use the
// primary key from SSM. paramPrefix is inserted between the app name and the
// secret name in the SSM param path — use "Migration/" for migration mode,
// empty string for primary mode.
//
// In migration mode (paramPrefix != "" AND keyID != ""), this function NEVER
// generates a fresh secret — the Migration/* params MUST exist or Init fails.
// Generating a fresh secret in migration mode would orphan the real data.
func (e *Enclave) waitForSecretsFromKMS(ctx context.Context, secrets []SecretDef, keyID, paramPrefix string) error {
	const timeout = 5 * time.Minute
	interval := 5 * time.Second

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	migrationMode := paramPrefix != "" && keyID != ""

	var lastErr error
	for {
		allLoaded := true
		for _, s := range secrets {
			if err := loadSecret(ctx, s, keyID, paramPrefix, migrationMode); err != nil {
				lastErr = fmt.Errorf("secret %s: %w", s.Name, err)
				allLoaded = false
				break
			}
			if strings.TrimSpace(os.Getenv(s.EnvVar)) == "" {
				lastErr = fmt.Errorf("secret %s: env var %s is empty after load", s.Name, s.EnvVar)
				allLoaded = false
				break
			}
		}
		if allLoaded {
			return nil
		}

		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("KMS secret loading timed out after %s (last error: %v)", timeout, lastErr)
			}
			return fmt.Errorf("KMS secret loading timed out after %s", timeout)
		case <-time.After(interval):
		}
	}
}

// loadSecret loads one secret's ciphertext from SSM and decrypts it with KMS.
// In primary mode (migrationMode=false), generates a fresh secret if missing.
// In migration mode (migrationMode=true), returns an error if the ciphertext
// is missing — NEVER generates fresh, which would orphan the real data.
func loadSecret(ctx context.Context, secret SecretDef, keyID, paramPrefix string, migrationMode bool) error {
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

// buildAttestationDocument creates an attestation document with an RSA public key.
func buildAttestationDocument(session *nsm.Session) ([]byte, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(session, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate rsa key: %w", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}

	nonce := make([]byte, 32)
	if _, err := io.ReadFull(session, nonce); err != nil {
		return nil, nil, fmt.Errorf("read nonce: %w", err)
	}

	resp, err := session.Send(&request.Attestation{
		Nonce:     nonce,
		PublicKey: publicKeyDER,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("attestation request failed: %w", err)
	}
	if resp.Attestation == nil {
		return nil, nil, fmt.Errorf("attestation response missing document")
	}

	return resp.Attestation.Document, privateKey, nil
}

// extractPCR0FromAttestation parses the attestation document and returns PCR0 as hex.
func extractPCR0FromAttestation(attestationDoc []byte) (string, error) {
	pcr, err := extractPCRFromAttestation(attestationDoc, 0)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pcr), nil
}

// extractPCRFromAttestation parses a COSE Sign1 attestation document and
// returns the raw bytes for the given PCR index.
func extractPCRFromAttestation(attestationDoc []byte, index uint) ([]byte, error) {
	var coseSign1 []cbor.RawMessage
	if err := cbor.Unmarshal(attestationDoc, &coseSign1); err != nil {
		return nil, fmt.Errorf("unmarshal COSE Sign1: %w", err)
	}
	if len(coseSign1) < 3 {
		return nil, fmt.Errorf("invalid COSE Sign1 structure")
	}

	var payload []byte
	if err := cbor.Unmarshal(coseSign1[2], &payload); err != nil {
		return nil, fmt.Errorf("unmarshal COSE payload: %w", err)
	}

	var doc attestationDocument
	if err := cbor.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal attestation document: %w", err)
	}

	pcr, ok := doc.PCRs[index]
	if !ok {
		return nil, fmt.Errorf("PCR%d not found in attestation document", index)
	}

	return pcr, nil
}

// getAttestationDocumentB64 generates a minimal NSM attestation document (without
// an RSA public key) and returns it as base64. The document is a COSE Sign1 structure
// signed by AWS Nitro hardware, proving this enclave's PCR values.
func getAttestationDocumentB64() (string, error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return "", fmt.Errorf("open NSM session: %w", err)
	}
	defer func() { _ = session.Close() }()

	nonce := make([]byte, 32)
	if _, err := io.ReadFull(session, nonce); err != nil {
		return "", fmt.Errorf("read nonce: %w", err)
	}

	resp, err := session.Send(&request.Attestation{
		Nonce: nonce,
	})
	if err != nil {
		return "", fmt.Errorf("attestation request failed: %w", err)
	}
	if resp.Attestation == nil {
		return "", fmt.Errorf("attestation response missing document")
	}

	return base64.StdEncoding.EncodeToString(resp.Attestation.Document), nil
}

// encryptWithKMS encrypts plaintext using KMS and returns base64-encoded ciphertext.
func encryptWithKMS(ctx context.Context, kmsClient *kms.Client, keyID string, plaintext []byte) (string, error) {
	out, err := kmsClient.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(keyID),
		Plaintext: plaintext,
	})
	if err != nil {
		return "", fmt.Errorf("kms encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(out.CiphertextBlob), nil
}

// storeCiphertextInSSM stores the base64-encoded ciphertext in SSM Parameter Store.
func storeCiphertextInSSM(ctx context.Context, ssmClient *ssm.Client, paramName, ciphertext string) error {
	_, err := ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
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

// loadCiphertextFromSSM attempts to load the ciphertext from SSM. Returns empty string if not found.
func loadCiphertextFromSSM(ctx context.Context, ssmClient *ssm.Client, paramName string) (string, error) {
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
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

// getSecretSSMParamName returns the SSM parameter name for a secret's ciphertext
// in primary storage.
func getSecretSSMParamName(secretName string) string {
	return getSecretSSMParamNameWithPrefix(secretName, "")
}

// getSecretSSMParamNameWithPrefix returns the SSM parameter name for a secret's
// ciphertext. Pass "" for primary storage, "Migration/" for migration staging.
func getSecretSSMParamNameWithPrefix(secretName, prefix string) string {
	deployment := getDeployment()
	appName := getAppName()
	return fmt.Sprintf("/%s/%s/%s%s/Ciphertext", deployment, appName, prefix, secretName)
}

// getKMSKeyID returns the KMS key ID from environment or SSM.
func getKMSKeyID(ctx context.Context, ssmClient *ssm.Client) (string, error) {
	deployment := getDeployment()
	appName := getAppName()
	paramName := fmt.Sprintf("/%s/%s/KMSKeyID", deployment, appName)
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
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

// normalizeSecretHex normalizes the secret to a hex string.
func normalizeSecretHex(plaintext []byte) string {
	candidate := strings.TrimSpace(string(plaintext))
	if len(candidate) == 64 {
		if _, err := hex.DecodeString(candidate); err == nil {
			return candidate
		}
	}
	return hex.EncodeToString(plaintext)
}
