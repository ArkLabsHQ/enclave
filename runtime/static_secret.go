package runtime

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"crypto/sha256"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/edgebitio/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/hf/nsm"
)

// =============================================================================
// StaticSecret type + config loading
// =============================================================================

// StaticSecret defines a secret managed by KMS inside the enclave runtime.
// Configured in enclave.yaml under `secrets:`. At boot, the supervisor
// either decrypts an existing KMS-encrypted ciphertext from SSM (one per
// secret), or generates a fresh 32-byte secret if none exists yet (primary
// mode only — never in migration mode). Each secret's plaintext is
// hex-encoded and exported into the configured env var, which the child
// app inherits via os.Environ().
type StaticSecret struct {
	Name   string `json:"name"`
	EnvVar string `json:"env_var"`
}

// loadStaticSecretsConfig parses ENCLAVE_SECRETS_CONFIG (a JSON array of
// {name, env_var} objects baked into the EIF by the CLI).
func loadStaticSecretsConfig() ([]StaticSecret, error) {
	raw := getStaticSecretsConfig()
	if raw == "" {
		return nil, nil
	}
	var secrets []StaticSecret
	if err := json.Unmarshal([]byte(raw), &secrets); err != nil {
		return nil, fmt.Errorf("parse ENCLAVE_SECRETS_CONFIG: %w", err)
	}
	return secrets, nil
}

// =============================================================================
// StaticSecrets subsystem
// =============================================================================

// StaticSecrets owns the boot-time KMS-decrypt loop for declared secrets.
// It also exposes ExtendPCRs() which extends PCR(16+i) with SHA256 of the
// derived secp256k1 pubkey for each secret, so the attestation document
// covers proof-of-knowledge of the loaded secrets.
type StaticSecrets struct {
	secrets []StaticSecret
	kms     *KMS
}

// NewStaticSecrets constructs the subsystem and parses the configured
// secrets list from the EIF-baked env var.
func NewStaticSecrets(kms *KMS) (*StaticSecrets, error) {
	secs, err := loadStaticSecretsConfig()
	if err != nil {
		return nil, err
	}
	return &StaticSecrets{secrets: secs, kms: kms}, nil
}

// Secrets returns the configured list (read-only — used by Migration).
func (s *StaticSecrets) Secrets() []StaticSecret {
	if s == nil {
		return nil
	}
	return s.secrets
}

// Len returns the number of configured static secrets.
func (s *StaticSecrets) Len() int {
	if s == nil {
		return 0
	}
	return len(s.secrets)
}

// WaitForKMS waits until all configured secrets are loaded from KMS.
// Times out after 5 minutes to prevent infinite retries on broken KMS.
//
// keyID specifies the KMS key to decrypt under. Pass empty string to use
// the primary key from SSM. paramPrefix is inserted between the app name
// and the secret name in the SSM param path — use "Migration/" for
// migration mode, empty string for primary mode.
//
// In migration mode (paramPrefix != "" AND keyID != ""), this function
// NEVER generates a fresh secret — the Migration/* params MUST exist or
// Init fails. Generating a fresh secret in migration mode would orphan
// the real data.
func (s *StaticSecrets) WaitForKMS(ctx context.Context, keyID, paramPrefix string) error {
	const timeout = 5 * time.Minute
	interval := 5 * time.Second

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	migrationMode := paramPrefix != "" && keyID != ""

	var lastErr error
	for {
		allLoaded := true
		for _, sec := range s.secrets {
			if err := s.loadOne(ctx, sec, keyID, paramPrefix, migrationMode); err != nil {
				lastErr = fmt.Errorf("secret %s: %w", sec.Name, err)
				allLoaded = false
				break
			}
			if strings.TrimSpace(os.Getenv(sec.EnvVar)) == "" {
				lastErr = fmt.Errorf("secret %s: env var %s is empty after load", sec.Name, sec.EnvVar)
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

// loadOne loads a single secret's ciphertext from SSM and decrypts via KMS.
// In primary mode (migrationMode=false), generates a fresh secret if
// missing. In migration mode, returns an error if the ciphertext is missing.
func (s *StaticSecrets) loadOne(ctx context.Context, secret StaticSecret, keyID, paramPrefix string, migrationMode bool) error {
	paramName := secretParamName(secret.Name, paramPrefix)

	if keyID == "" {
		var err error
		keyID, err = s.kms.GetKeyID(ctx)
		if err != nil {
			return fmt.Errorf("get KMS key ID: %w", err)
		}
	}
	if keyID == "" {
		return fmt.Errorf("KMS key ID is empty")
	}

	ciphertextB64, err := s.kms.LoadCiphertext(ctx, paramName)
	if err != nil {
		return err
	}

	if ciphertextB64 == "" {
		if migrationMode {
			return fmt.Errorf("migration ciphertext missing at %s — cannot generate fresh (would orphan data)", paramName)
		}
		return s.generateAndStore(ctx, keyID, paramName, secret.EnvVar)
	}

	return s.decryptExisting(ctx, keyID, ciphertextB64, secret.EnvVar)
}

// generateAndStore uses KMS GenerateDataKey to produce a 32-byte secret with
// hardware RNG, and stores the ciphertext in SSM.
func (s *StaticSecrets) generateAndStore(ctx context.Context, keyID, paramName, envVar string) error {
	out, err := s.kms.aws.KMS.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:         aws.String(keyID),
		NumberOfBytes: aws.Int32(32),
	})
	if err != nil {
		return fmt.Errorf("kms generate data key: %w", err)
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(out.CiphertextBlob)

	if err := s.kms.StoreCiphertext(ctx, paramName, ciphertextB64); err != nil {
		return err
	}

	secretHex := hex.EncodeToString(out.Plaintext)
	if err := safeSetenv(envVar, secretHex); err != nil {
		return fmt.Errorf("set %s: %w", envVar, err)
	}

	return nil
}

// decryptExisting decrypts the ciphertext from SSM using KMS with attestation.
func (s *StaticSecrets) decryptExisting(ctx context.Context, keyID, ciphertextB64, envVar string) error {
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

	out, err := s.kms.aws.KMS.Decrypt(ctx, input)
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

// ExtendPCRs derives the secp256k1 compressed public key for each secret
// and extends PCR(16 + index) with SHA256(compressed_pubkey). Each PCR is
// then locked so it can't be re-extended.
func (s *StaticSecrets) ExtendPCRs() error {
	for i, sec := range s.secrets {
		pcrIndex := uint(16) + uint(i)
		if pcrIndex >= migrationPCRIndex {
			return fmt.Errorf("secret %q: PCR index %d would collide with migration PCR (PCR%d)", sec.Name, pcrIndex, migrationPCRIndex)
		}

		secretHex := os.Getenv(sec.EnvVar)
		if secretHex == "" {
			return fmt.Errorf("secret %q env var %s is empty", sec.Name, sec.EnvVar)
		}

		secretBytes, err := hex.DecodeString(secretHex)
		if err != nil {
			return fmt.Errorf("decode secret %q hex: %w", sec.Name, err)
		}

		privKey, _ := btcec.PrivKeyFromBytes(secretBytes)
		if privKey == nil {
			return fmt.Errorf("secret %q: invalid secp256k1 private key", sec.Name)
		}

		pubkeyBytes := privKey.PubKey().SerializeCompressed()
		hash := sha256.Sum256(pubkeyBytes)

		if err := extendPCR(pcrIndex, hash[:]); err != nil {
			return fmt.Errorf("extend PCR%d with secret %q pubkey: %w", pcrIndex, sec.Name, err)
		}
		if err := lockPCR(pcrIndex); err != nil {
			return fmt.Errorf("lock PCR%d after secret %q: %w", pcrIndex, sec.Name, err)
		}
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
