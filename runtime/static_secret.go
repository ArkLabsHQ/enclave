package runtime

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
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

// StaticSecret is a KMS-managed secret (enclave.yaml `secrets:`), hex-encoded into its
// env var, which the child app inherits via os.Environ(). For a "signing" secret EnvVar
// holds what this node signs with now — its share once a group forms, else the leader
// secret (solo leader); the leader secret otherwise lives only in the storage envelope.
type StaticSecret struct {
	Name   string `json:"name"`
	EnvVar string `json:"env_var"`
	Kind   string `json:"kind,omitempty"`
}

// IsThreshold reports whether the secret is threshold-shared (kind "signing").
func (s StaticSecret) IsSigning() bool {
	return s.Kind == "signing"
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
	scaling *ScalingEntity

	// leaderSecrets caches a leader's secret (a0) by EnvVar — the source for a0 pinning,
	// and how the leader secret survives once its env var is overwritten by this node's
	// share.
	mu            sync.Mutex
	leaderSecrets map[string][]byte
}

// NewStaticSecrets constructs the subsystem and parses the configured
// secrets list from the EIF-baked env var.
func NewStaticSecrets(kms *KMS, scaling *ScalingEntity) (*StaticSecrets, error) {
	secs, err := loadStaticSecretsConfig()
	if err != nil {
		return nil, err
	}
	return &StaticSecrets{secrets: secs, kms: kms, scaling: scaling, leaderSecrets: map[string][]byte{}}, nil
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

// LoadAll loads (or generates, when missing) every configured static secret,
// retrying transient failures up to 5 minutes / 5 seconds apart. The wait
// loop is the only thing protecting boot from KMS/SSM warmup races; without
// it, a transient AWS hiccup during init fails the enclave to boot.
//
// keyID is the KMS key to decrypt under; it also scopes the SSM ciphertext path.
func (s *StaticSecrets) LoadAll(ctx context.Context, keyID string) error {
	const timeout = 5 * time.Minute
	interval := 5 * time.Second

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var lastErr error
	for {
		allLoaded := true
		for _, sec := range s.secrets {
			if err := s.LoadOrGenerate(ctx, sec, keyID); err != nil {
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

// LoadOrGenerate loads the secret's ciphertext from the key-scoped SSM path,
// generating + storing a fresh one if absent (first boot for this KMS key).
func (s *StaticSecrets) LoadOrGenerate(ctx context.Context, secret StaticSecret, keyID string) error {
	paramName := secretCiphertextParam(secret.Name, keyID)

	ciphertextB64, err := s.kms.LoadCiphertext(ctx, paramName)
	if err != nil {
		return err
	}

	if ciphertextB64 != "" {
		if secret.IsSigning() {
			return s.loadSharedSecret(ctx, keyID, ciphertextB64, secret)
		}
		return s.decryptExisting(ctx, keyID, ciphertextB64, secret.EnvVar)
	}

	if s.scaling != nil && !s.scaling.IsLeader() && secret.IsSigning() {
		if err := s.scaling.DeriveFollowerKey(ctx, secret); err != nil {
			return fmt.Errorf("derive follower key: %w", err)
		}

		// Await the share: the reshare ceremony delivers it asynchronously
		waitCtx, cancel := context.WithTimeout(ctx, followerReshareKeyTimeout)
		defer cancel()
		for {
			if strings.TrimSpace(os.Getenv(secret.EnvVar)) != "" {
				return nil
			}
			select {
			case <-waitCtx.Done():
				return fmt.Errorf("timeout waiting for follower key to be set in env var %s", secret.EnvVar)
			case <-time.After(100 * time.Millisecond):
			}
		}

	}

	ciphertextBlob, plaintext, err := s.kms.generateDataKey(ctx, keyID)
	if err != nil {
		return err
	}

	// A leader signing secret mints its leader secret (a0) into an envelope
	if secret.IsSigning() {
		return s.storeSharedSecret(ctx, keyID, secret, sharedSecret{Secret: hex.EncodeToString(plaintext)})
	}

	if err := s.kms.StoreCiphertext(ctx, paramName, base64.StdEncoding.EncodeToString(ciphertextBlob)); err != nil {
		return err
	}
	if err := safeSetenv(secret.EnvVar, hex.EncodeToString(plaintext)); err != nil {
		return fmt.Errorf("set %s: %w", secret.EnvVar, err)
	}

	return nil
}

// StoreDerivedSecret is the sink for a share from a (re-)DKG ceremony, called from
// both roles' Keys()-drain goroutines. It bundles the share into the secret's
// envelope and persists it, so a later boot skips the ceremony. label is the
// secret's EnvVar.
func (s *StaticSecrets) StoreDerivedSecret(ctx context.Context, label string, share []byte) error {
	secret, ok := s.secretByEnvVar(label)
	if !ok {
		return fmt.Errorf("no configured secret for reshare label %q", label)
	}
	keyID, err := s.kms.GetKeyID(ctx)
	if err != nil {
		return fmt.Errorf("get kms key id: %w", err)
	}

	env := sharedSecret{Share: hex.EncodeToString(share)}
	if s.scaling != nil && s.scaling.IsLeader() {
		// Fold the leader secret (a0) into the envelope so persisting the share
		// doesn't drop it. The env var now holds the share, so the leader secret is
		// read from the in-memory cache seeded when the secret was first
		// loaded/generated.
		a0, err := s.leaderSecret(label)
		if err != nil {
			return fmt.Errorf("leader secret %q not loaded before its share: %w", secret.Name, err)
		}
		env.Secret = hex.EncodeToString(a0)
	}
	return s.storeSharedSecret(ctx, keyID, secret, env)
}

// secretByEnvVar resolves a configured secret by its env var (the reshare label).
func (s *StaticSecrets) secretByEnvVar(envVar string) (StaticSecret, bool) {
	for _, sec := range s.secrets {
		if sec.EnvVar == envVar {
			return sec, true
		}
	}
	return StaticSecret{}, false
}

// decryptExisting decrypts a raw (non-signing) secret's ciphertext and sets its env
// var. Signing secrets use the sharedSecret envelope instead (loadSharedSecret).
func (s *StaticSecrets) decryptExisting(ctx context.Context, keyID, ciphertextB64, envVar string) error {
	plaintext, err := s.decryptCiphertext(ctx, keyID, ciphertextB64)
	if err != nil {
		return err
	}
	if err := safeSetenv(envVar, normalizeSecretHex(plaintext)); err != nil {
		return fmt.Errorf("set %s: %w", envVar, err)
	}
	return nil
}

// decryptCiphertext KMS-decrypts a base64 ciphertext to its raw plaintext, carrying
// a fresh NSM attestation as Recipient so the PCR0-gated key policy admits the call.
func (s *StaticSecrets) decryptCiphertext(ctx context.Context, keyID, ciphertextB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("open nsm session: %w", err)
	}
	defer func() { _ = session.Close() }()

	attestationDoc, rsaPrivateKey, err := buildAttestationDocument(session)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("kms decrypt: %w", err)
	}

	if len(out.CiphertextForRecipient) == 0 {
		return nil, fmt.Errorf("kms decrypt returned empty CiphertextForRecipient")
	}

	plaintext, err := cms.DecryptEnvelopedKey(rsaPrivateKey, out.CiphertextForRecipient)
	if err != nil {
		return nil, fmt.Errorf("decrypt CiphertextForRecipient: %w", err)
	}
	return plaintext, nil
}

// sharedSecret is the plaintext of a "signing" secret's ciphertext: the leader secret
// (a0) and this node's threshold share, bundled under one SSM slot so both are read  and written atomically
type sharedSecret struct {
	Secret string `json:"leader_secret,omitempty"` // hex; the a0/full secret (leader only)
	Share  string `json:"share,omitempty"`         // hex; this node's threshold share
}

// applySharedSecret sets the secret's env var to what this node signs with now (share
// if the envelope has one, else the leader secret) and caches any leader secret in
// memory for a0 pinning. Once a group exists, the leader secret has no env var.
func (s *StaticSecrets) applySharedSecret(secretMetadata StaticSecret, secret sharedSecret) error {
	if secret.Secret != "" {
		if b, err := hex.DecodeString(secret.Secret); err == nil {
			s.mu.Lock()
			s.leaderSecrets[secretMetadata.EnvVar] = b
			s.mu.Unlock()
		} else {
			return fmt.Errorf("decode leader secret for %q: %w", secretMetadata.Name, err)
		}
	}
	val := secret.Share
	if val == "" {
		val = secret.Secret
	}
	if val == "" {
		return fmt.Errorf("shared secret %q has neither leader secret nor share", secretMetadata.Name)
	}
	if err := safeSetenv(secretMetadata.EnvVar, val); err != nil {
		return fmt.Errorf("set %s: %w", secretMetadata.EnvVar, err)
	}
	return nil
}

// leaderSecret returns the cached leader secret (a0) for a signing secret, keyed by its
// EnvVar. Populated only on a leader, once the secret has been loaded or generated.
func (s *StaticSecrets) leaderSecret(label string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.leaderSecrets[label]; ok {
		return m, nil
	}
	return nil, fmt.Errorf("leader secret for %q not loaded", label)
}

// loadSharedSecret decrypts a signing secret's envelope and applies it to env vars.
func (s *StaticSecrets) loadSharedSecret(ctx context.Context, keyID, ciphertextB64 string, secret StaticSecret) error {
	plaintext, err := s.decryptCiphertext(ctx, keyID, ciphertextB64)
	if err != nil {
		return err
	}
	var env sharedSecret
	if err := json.Unmarshal(plaintext, &env); err != nil {
		return fmt.Errorf("parse shared secret %q: %w", secret.Name, err)
	}
	return s.applySharedSecret(secret, env)
}

// storeSharedSecret encrypts a signing secret's envelope, persists it to the single
// key-scoped slot, and materializes it into env vars.
func (s *StaticSecrets) storeSharedSecret(ctx context.Context, keyID string, secret StaticSecret, env sharedSecret) error {
	plaintext, err := json.Marshal(env)
	if err != nil {
		return err
	}
	ciphertextB64, err := s.kms.Encrypt(ctx, keyID, plaintext)
	if err != nil {
		return err
	}
	if err := s.kms.StoreCiphertext(ctx, secretCiphertextParam(secret.Name, keyID), ciphertextB64); err != nil {
		return err
	}
	return s.applySharedSecret(secret, env)
}

// ExtendPCRs derives the secp256k1 compressed public key for each secret
// and extends PCR(16 + index) with SHA256(compressed_pubkey). Each PCR is
// then locked so it can't be re-extended.
func (s *StaticSecrets) ExtendPCRs() error {
	for i, sec := range s.secrets {
		if sec.IsSigning() {
			continue // TODO (Joshua): Decide If Signing Secrets Should be Extended
		}
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
