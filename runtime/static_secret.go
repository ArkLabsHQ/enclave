package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
)

// StaticSecretMetadata defines a secret managed by KMS inside the enclave runtime
// (configured in enclave.yaml under `secrets:`). Its plaintext is hex-encoded
// into the configured env var, which the child app inherits via os.Environ().
type StaticSecretMetadata struct {
	Name   string `json:"name"`
	EnvVar string `json:"env_var"`
}

type StaticSecret struct {
	StaticSecretMetadata
	Plaintext string
}

func LoadStaticSecretMetadata() ([]StaticSecretMetadata, error) {
	raw := getStaticSecretsConfig()
	if raw == "" {
		return nil, nil
	}
	var secretMeta []StaticSecretMetadata
	if err := json.Unmarshal([]byte(raw), &secretMeta); err != nil {
		return nil, fmt.Errorf("parse ENCLAVE_SECRETS_CONFIG: %w", err)
	}

	return secretMeta, nil
}

// FetchOrInitStaticSecrets loads each key-scoped secret, or creates one via KMS.
func FetchOrInitStaticSecrets(
	ctx context.Context,
	kms KMS,
	ssm SSM,
	metadata []StaticSecretMetadata,
) ([]StaticSecret, error) {
	secrets := make([]StaticSecret, 0, len(metadata))

	addSecret := func(m StaticSecretMetadata, p string) {
		secrets = append(secrets, StaticSecret{StaticSecretMetadata: m, Plaintext: p})
	}

	for _, s := range metadata {
		paramName := secretCiphertextParam(s.Name, kms.KeyID())
		ciphertextB64, err := ssm.MayGet(ctx, paramName)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch SSM static secret param %s: %w", paramName, err)
		}

		if ciphertextB64 == "" {
			dk, err := kms.GenerateDataKey(ctx)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to generate static secret param %s: %w",
					paramName,
					err,
				)
			}

			ciphertextB64 = base64.StdEncoding.EncodeToString(dk.Ciphertext)

			if err := ssm.Set(ctx, paramName, ciphertextB64); err != nil {
				return nil, fmt.Errorf(
					"failed to set SSM static secret param %s: %w",
					paramName,
					err,
				)
			}

			secretHex := hex.EncodeToString(dk.Plaintext)
			addSecret(s, secretHex)
			continue
		}

		plaintext, err := kms.Decrypt(ctx, ciphertextB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt static secret param %s: %w", paramName, err)
		}

		// Legacy secrets may already be hex.
		candidate := strings.TrimSpace(string(plaintext))
		if len(candidate) == 64 {
			if _, err := hex.DecodeString(candidate); err == nil {
				addSecret(s, candidate)
				continue
			}
		}

		secretHex := hex.EncodeToString(plaintext)
		addSecret(s, secretHex)
	}

	return secrets, nil
}

func SetStaticSecretEnvVars(secrets []StaticSecret) error {
	for _, s := range secrets {
		if err := safeSetenv(s.EnvVar, s.Plaintext); err != nil {
			return fmt.Errorf("set %s: %w", s.EnvVar, err)
		}
	}

	return nil
}

// ExtendPCRRegistersWithStaticSecrets commits each secret pubkey hash to PCR(16+i).
func ExtendPCRRegistersWithStaticSecrets(nsm NSM, secrets []StaticSecret) error {
	for i, s := range secrets {
		pcrIndex := uint(16) + uint(i)
		if pcrIndex >= migrationPCRIndex {
			return fmt.Errorf("secret %q: PCR index %d would collide with migration PCR (PCR%d)",
				s.Name, pcrIndex, migrationPCRIndex)
		}

		secretBytes, err := hex.DecodeString(s.Plaintext)
		if err != nil {
			return fmt.Errorf("decode secret %s hex: %w", s.Name, err)
		}

		privKey, _ := btcec.PrivKeyFromBytes(secretBytes)
		if privKey == nil {
			return fmt.Errorf("secret %q: invalid secp256k1 private key", s.Name)
		}

		pubkeyBytes := privKey.PubKey().SerializeCompressed()
		hash := sha256.Sum256(pubkeyBytes)

		if err := nsm.ExtendPCR(pcrIndex, hash[:]); err != nil {
			return fmt.Errorf("extend PCR%d with secret %q pubkey: %w", pcrIndex, s.Name, err)
		}
		if err := nsm.LockPCR(pcrIndex); err != nil {
			return fmt.Errorf("lock PCR%d after secret %q: %w", pcrIndex, s.Name, err)
		}
	}
	return nil
}
