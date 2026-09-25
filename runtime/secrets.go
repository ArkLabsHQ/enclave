package runtime

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

// SecretsMetadata is the secret configuration baked into the image: the static
// secrets minted inside the enclave, and the inherited ones handed in from
// outside.
type SecretsMetadata struct {
	Static    []StaticSecretMetadata
	Inherited []InheritSecretMetadata
}

func LoadSecretsMetadata(cfg Config) (SecretsMetadata, error) {
	static, err := LoadStaticSecretMetadata(cfg)
	if err != nil {
		return SecretsMetadata{}, err
	}
	inherited, err := LoadInheritSecretMetadata(cfg)
	if err != nil {
		return SecretsMetadata{}, err
	}
	return SecretsMetadata{Static: static, Inherited: inherited}, nil
}

func (sm SecretsMetadata) Validate() error {
	if err := sm.validateStatic(); err != nil {
		return fmt.Errorf("invalid static secret metadata: %w", err)
	}
	if err := sm.validateInherited(); err != nil {
		return fmt.Errorf("invalid inherited secret metadata: %w", err)
	}
	return nil
}

// Secrets is what boot resolved from SecretsMetadata: the decrypted static
// secrets, and the inherited ones that are present, verified and before their
// cutoff.
type Secrets struct {
	Static    []StaticSecret
	Inherited []InheritedSecret

	metadata SecretsMetadata
}

// beforeCutoff drops the inherited secrets that have reached their cutoff by
// now. Boot resolved the secrets some time ago, so the app is started, and its
// cutoffs watched, with what is left.
func (s Secrets) beforeCutoff(now time.Time) Secrets {
	var inherited []InheritedSecret
	for _, secret := range s.Inherited {
		if secret.pastCutoff(now) {
			slog.Info("inherited secret reached its cutoff before the app started",
				"name", secret.Name, "cutoff", secret.Cutoff)
			continue
		}
		inherited = append(inherited, secret)
	}
	s.Inherited = inherited
	return s
}

func (s Secrets) applyTo(env []string, now time.Time) []string {
	inherited := make(map[string]bool, len(s.metadata.Inherited))
	for _, m := range s.metadata.Inherited {
		inherited[m.EnvVar] = true
	}
	env = slices.DeleteFunc(slices.Clone(env), func(entry string) bool {
		key, _, _ := strings.Cut(entry, "=")
		return inherited[key]
	})

	// exec.Cmd.Env keeps the last value for duplicate keys, so these override.
	for _, secret := range s.Static {
		env = append(env, secret.EnvVar+"="+secret.Plaintext)
	}
	for _, secret := range s.Inherited {
		if !secret.pastCutoff(now) {
			env = append(env, secret.EnvVar+"="+secret.Plaintext)
		}
	}
	return env
}

// StaticSecretMetadata defines a secret managed by KMS inside the enclave runtime
// (configured in enclave.yaml under `secrets:`). Its plaintext is hex-encoded
// into the configured env var only in the child app's environment.
type StaticSecretMetadata struct {
	Name   string `json:"name"`
	EnvVar string `json:"env_var"`
}

type StaticSecret struct {
	StaticSecretMetadata
	Plaintext string
}

func LoadStaticSecretMetadata(cfg Config) ([]StaticSecretMetadata, error) {
	raw := cfg.StaticSecretConfig
	if raw == "" {
		return nil, nil
	}
	var secretMeta []StaticSecretMetadata
	if err := json.Unmarshal([]byte(raw), &secretMeta); err != nil {
		return nil, fmt.Errorf("parse ENCLAVE_SECRETS_CONFIG: %w", err)
	}

	return secretMeta, nil
}

func (sm SecretsMetadata) validateStatic() error {
	seen := make(map[string]bool, len(sm.Static))
	for _, secret := range sm.Static {
		if secret.Name == "StorageDEK" {
			return fmt.Errorf("static secret %q collides with storage DEK", secret.Name)
		}
		if seen[secret.Name] {
			return fmt.Errorf("duplicate static secret %q", secret.Name)
		}
		seen[secret.Name] = true
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

const (
	inheritSecretTypeHash      = "hash"
	inheritSecretTypePublicKey = "publicKey"
)

// InheritSecretMetadata defines a secret born outside the enclave and handed in
// through SSM (ENCLAVE_INHERIT_SECRETS_CONFIG). The image pins what the secret
// must be, so the pin and the cutoff are part of PCR0. Value holds one
// commitment per delivered entry: `hash` pins SHA-256 hashes, `publicKey` pins
// compressed secp256k1 public keys whose secrets are hex-encoded private keys.
// From Cutoff on, the app no longer receives it; without a Cutoff, it always does.
type InheritSecretMetadata struct {
	Name   string    `json:"name"`
	EnvVar string    `json:"env_var"`
	Type   string    `json:"type"`
	Value  []string  `json:"value"`
	Cutoff time.Time `json:"cutoff"`
}

// pastCutoff reports whether the secret has reached its cutoff by now. A secret
// without a cutoff never does.
func (m InheritSecretMetadata) pastCutoff(now time.Time) bool {
	return !m.Cutoff.IsZero() && !now.Before(m.Cutoff)
}

type InheritedSecret struct {
	InheritSecretMetadata
	Plaintext string
}

// childReservedEnv lists the vars appEnv sets on the child itself.
var childReservedEnv = map[string]bool{
	"ENCLAVE_APP_PORT":      true,
	"PORT":                  true,
	"ENCLAVE_PROXY_PORT":    true,
	"ENCLAVE_RUNTIME_TOKEN": true,
}

var (
	envVarNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// secretNamePattern is SSM's own path-segment charset.
	secretNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

func LoadInheritSecretMetadata(cfg Config) ([]InheritSecretMetadata, error) {
	raw := cfg.InheritSecretConfig
	if raw == "" {
		return nil, nil
	}
	var meta []InheritSecretMetadata
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return nil, fmt.Errorf("parse ENCLAVE_INHERIT_SECRETS_CONFIG: %w", err)
	}

	return meta, nil
}

// validateInherited also refuses an env_var a static secret already uses.
func (sm SecretsMetadata) validateInherited() error {
	envVars := make(map[string]bool, len(sm.Inherited)+len(sm.Static))
	for _, s := range sm.Static {
		envVars[s.EnvVar] = true
	}

	names := make(map[string]bool, len(sm.Inherited))
	for _, m := range sm.Inherited {
		if !secretNamePattern.MatchString(m.Name) {
			return fmt.Errorf("inherited secret name %q must be a single SSM path segment", m.Name)
		}
		if names[m.Name] {
			return fmt.Errorf("duplicate inherited secret %q", m.Name)
		}
		names[m.Name] = true

		if !envVarNamePattern.MatchString(m.EnvVar) {
			return fmt.Errorf("inherited secret %q: invalid env_var %q", m.Name, m.EnvVar)
		}
		if childReservedEnv[m.EnvVar] {
			return fmt.Errorf("inherited secret %q: env_var %q is reserved", m.Name, m.EnvVar)
		}
		if envVars[m.EnvVar] {
			return fmt.Errorf("inherited secret %q: env_var %q is already used", m.Name, m.EnvVar)
		}
		envVars[m.EnvVar] = true

		var wantLen int
		switch m.Type {
		case inheritSecretTypeHash:
			wantLen = sha256.Size
		case inheritSecretTypePublicKey:
			wantLen = btcec.PubKeyBytesLenCompressed
		default:
			return fmt.Errorf("inherited secret %q: unknown type %q", m.Name, m.Type)
		}
		if len(m.Value) == 0 {
			return fmt.Errorf(
				"inherited secret %q: value must hold at least one %s",
				m.Name,
				m.Type,
			)
		}
		seenValues := make(map[string]bool, len(m.Value))
		for i, value := range m.Value {
			if seenValues[value] {
				return fmt.Errorf("inherited secret %q: %s %d is a duplicate", m.Name, m.Type, i)
			}
			seenValues[value] = true
			commitment, err := hex.DecodeString(value)
			if err != nil {
				return fmt.Errorf(
					"inherited secret %q: %s %d is not hex: %w",
					m.Name,
					m.Type,
					i,
					err,
				)
			}
			if len(commitment) != wantLen {
				return fmt.Errorf(
					"inherited secret %q: %s %d must be %d bytes", m.Name, m.Type, i, wantLen,
				)
			}
			if m.Type == inheritSecretTypePublicKey {
				if _, err := btcec.ParsePubKey(commitment); err != nil {
					return fmt.Errorf(
						"inherited secret %q: invalid secp256k1 public key %d: %w", m.Name, i, err,
					)
				}
			}
		}
	}
	return nil
}

// verifyInheritedSecret checks a handed-in value against its measured pin: each
// comma-separated delivered entry must match one commitment, in any order, and
// each commitment is used once, so an entry must not contain a comma. The
// commitments were validated with the config; they are decoded again here so
// the check fails closed on its own.
func verifyInheritedSecret(m InheritSecretMetadata, plaintext string) error {
	values := strings.Split(plaintext, ",")
	for i := range values {
		values[i] = strings.TrimSpace(values[i])
	}
	if len(values) != len(m.Value) {
		return fmt.Errorf(
			"inherited secret %q: got %d values, want %d", m.Name, len(values), len(m.Value),
		)
	}
	commitments := make([][]byte, len(m.Value))
	for i, value := range m.Value {
		commitment, err := hex.DecodeString(value)
		if err != nil {
			return fmt.Errorf("inherited secret %q: %s %d is not hex: %w", m.Name, m.Type, i, err)
		}
		commitments[i] = commitment
	}

	for i, value := range values {
		var got []byte
		switch m.Type {
		case inheritSecretTypeHash:
			hash := sha256.Sum256([]byte(value))
			got = hash[:]
		case inheritSecretTypePublicKey:
			// A key may carry app metadata after a colon, "<key>:<unix-ts>";
			// only the key is pinned, the entry is delivered whole.
			value, _, _ = strings.Cut(value, ":")
			secretBytes, err := hex.DecodeString(value)
			if err != nil || len(secretBytes) != btcec.PrivKeyBytesLen {
				return fmt.Errorf(
					"inherited secret %q: value %d is not a hex-encoded 32-byte private key",
					m.Name, i,
				)
			}
			var scalar btcec.ModNScalar
			if overflow := scalar.SetByteSlice(secretBytes); overflow || scalar.IsZero() {
				return fmt.Errorf(
					"inherited secret %q: value %d is not a valid secp256k1 private key",
					m.Name,
					i,
				)
			}
			privKey, _ := btcec.PrivKeyFromBytes(secretBytes)
			got = privKey.PubKey().SerializeCompressed()
		}
		matched := -1
		for j, commitment := range commitments { // consumed entries are nil and never match
			if subtle.ConstantTimeCompare(got, commitment) == 1 {
				matched = j
			}
		}
		if matched < 0 {
			return fmt.Errorf(
				"inherited secret %q: value %d does not match an unused pinned %s",
				m.Name, i, m.Type,
			)
		}
		commitments[matched] = nil
	}
	return nil
}

// resolveInheritedSecrets reads the inherited secrets still before their cutoff
// and verifies each against its pin. A secret past its cutoff is never fetched,
// so its parameter and KMS key can be retired. A value that fails its pin
// aborts boot; an absent one is skipped, which withdraws the secret from this
// and future boots.
func resolveInheritedSecrets(
	ctx context.Context,
	cfg *Config,
	ssm SSM,
	meta []InheritSecretMetadata,
	now time.Time,
) ([]InheritedSecret, error) {
	prefix := cfg.inheritSecretPrefix()

	var secrets []InheritedSecret
	for _, m := range meta {
		if m.pastCutoff(now) {
			slog.Info("inherited secret is past its cutoff", "name", m.Name, "cutoff", m.Cutoff)
			continue
		}
		plaintext, err := ssm.MayGet(ctx, prefix+m.Name, WithDecryption())
		if err != nil {
			return nil, fmt.Errorf("failed to read inherited secret %q: %w", m.Name, err)
		}
		if plaintext == "" {
			slog.Warn(
				"inherited secret is not present in SSM",
				"name",
				m.Name,
				"param",
				prefix+m.Name,
			)
			continue
		}
		if err := verifyInheritedSecret(m, plaintext); err != nil {
			return nil, err
		}
		secrets = append(secrets, InheritedSecret{InheritSecretMetadata: m, Plaintext: plaintext})
	}

	return secrets, nil
}

// watchInheritCutoffs signals that the app must be relaunched once one of the
// inherited secrets it was started with reaches its cutoff. Secrets without a
// cutoff are never watched.
func watchInheritCutoffs(
	ctx context.Context,
	inherited []InheritedSecret,
	interval time.Duration,
) <-chan struct{} {
	restart := make(chan struct{}, 1)
	pending := slices.DeleteFunc(slices.Clone(inherited), func(s InheritedSecret) bool {
		return s.Cutoff.IsZero()
	})
	if len(pending) == 0 {
		return restart
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for len(pending) > 0 {
			current := time.Now()
			expired := false
			remaining := pending[:0:0]
			for _, s := range pending {
				if !s.pastCutoff(current) {
					remaining = append(remaining, s)
					continue
				}
				slog.Info("inherited secret reached its cutoff", "name", s.Name, "cutoff", s.Cutoff)
				expired = true
			}
			pending = remaining

			if expired {
				select {
				case restart <- struct{}{}:
				default:
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	return restart
}
