package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

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
