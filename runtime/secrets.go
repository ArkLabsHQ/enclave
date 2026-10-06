package runtime

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fxamacker/cbor/v2"
)

// SecretsMetadata is baked into the image: managed secrets (persisted or
// derived) and inherited secrets supplied from outside.
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

func (sm SecretsMetadata) Validate(overrideAllowList map[string]bool) error {
	if err := sm.validateStatic(); err != nil {
		return fmt.Errorf("invalid static secret metadata: %w", err)
	}
	if err := sm.validateInherited(); err != nil {
		return fmt.Errorf("invalid inherited secret metadata: %w", err)
	}
	if err := sm.validateChildEnv(overrideAllowList); err != nil {
		return fmt.Errorf("invalid inherited secret metadata: %w", err)
	}
	return nil
}

// Secrets holds managed values in configuration order (including hidden seeds
// and derived outputs), and verified inherited values before their cutoff.
type Secrets struct {
	Static    []StaticSecret
	Inherited []InheritedSecret
}

const (
	secretTypePassthrough = "passthrough"
	secretTypeSeed        = "seed"
	secretTypeDerived     = "derived"
	derivedSecretSalt     = "enclave.derived-secret.v1"
	maxManagedSecrets     = migrationPCRIndex - 16
)

// StaticSecretMetadata describes an ENCLAVE_SECRETS_CONFIG entry. An omitted
// type means passthrough. Only passthrough and seed entries have ciphertexts.
type StaticSecretMetadata struct {
	Name   string `json:"name"`
	EnvVar string `json:"env_var"`
	Type   string `json:"type,omitempty"`
	Seed   string `json:"seed,omitempty"`
}

type StaticSecret struct {
	StaticSecretMetadata
	Plaintext string
}

func (m StaticSecretMetadata) persisted() bool { return m.Type != secretTypeDerived }

// persisted includes hidden seeds; derived values never enter a handoff.
func (s Secrets) persisted() []StaticSecret {
	var out []StaticSecret
	for _, secret := range s.Static {
		if secret.persisted() {
			out = append(out, secret)
		}
	}
	return out
}

func (s Secrets) exported() []StaticSecret {
	var out []StaticSecret
	for _, secret := range s.Static {
		if secret.Type != secretTypeSeed {
			out = append(out, secret)
		}
	}
	return out
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
	if len(sm.Static) > maxManagedSecrets {
		return fmt.Errorf("at most %d managed secrets fit in PCR16–PCR30", maxManagedSecrets)
	}
	seen := make(map[string]StaticSecretMetadata, len(sm.Static))
	envVars := make(map[string]bool, len(sm.Static))
	for _, secret := range sm.Static {
		if !secretNamePattern.MatchString(secret.Name) {
			return fmt.Errorf(
				"static secret name %q must be a single SSM path segment",
				secret.Name,
			)
		}
		if secret.Name == "StorageDEK" {
			return fmt.Errorf("static secret %q collides with storage DEK", secret.Name)
		}
		if _, ok := seen[secret.Name]; ok {
			return fmt.Errorf("duplicate static secret %q", secret.Name)
		}
		seen[secret.Name] = secret
		switch secret.Type {
		case "", secretTypePassthrough, secretTypeSeed:
		case secretTypeDerived:
			if secret.Seed == "" {
				return fmt.Errorf("derived secret %q requires seed", secret.Name)
			}
		default:
			return fmt.Errorf("secret %q: unknown type %q", secret.Name, secret.Type)
		}
		if secret.Type == secretTypeSeed {
			continue // env_var is ignored, including for collision checks.
		}
		if !envVarNamePattern.MatchString(secret.EnvVar) || childReservedEnv[secret.EnvVar] {
			return fmt.Errorf(
				"secret %q: invalid or reserved env_var %q",
				secret.Name,
				secret.EnvVar,
			)
		}
		if envVars[secret.EnvVar] {
			return fmt.Errorf("secret %q: env_var %q is already used", secret.Name, secret.EnvVar)
		}
		envVars[secret.EnvVar] = true
	}
	for _, secret := range sm.Static {
		if secret.Type == secretTypeDerived && seen[secret.Seed].Type != secretTypeSeed {
			return fmt.Errorf(
				"derived secret %q: seed %q must name a configured seed",
				secret.Name,
				secret.Seed,
			)
		}
	}
	return nil
}

// deriveSecret uses RFC 5869 extract-and-expand with a fixed protocol salt.
// Info is one definite-length CBOR text string, not an array or a byte string.
// Names use the ASCII SSM-segment alphabet; their bytes are never normalized.
func deriveSecret(seed []byte, name string) (string, error) {
	if len(seed) != 32 {
		return "", fmt.Errorf("seed must be 32 bytes, got %d", len(seed))
	}
	// ponytail: default CBOR encoding is deterministic for a plain string.
	info, err := cbor.Marshal(name)
	if err != nil {
		return "", err
	}
	key, err := hkdf.Key(sha256.New, seed, []byte(derivedSecretSalt), string(info), 32)
	if err != nil {
		return "", err
	}
	// Reject an invalid signing scalar
	var scalar btcec.ModNScalar
	if len(key) != 32 || scalar.SetByteSlice(key) || scalar.IsZero() {
		return "", fmt.Errorf("derived value is not a secp256k1 scalar in [1, N-1]")
	}
	return hex.EncodeToString(key), nil
}

// ExtendPCRRegistersWithStaticSecrets commits each secret pubkey hash to PCR(16+i).
func ExtendPCRRegistersWithStaticSecrets(nsm NSM, secrets []StaticSecret) error {
	if len(secrets) > maxManagedSecrets {
		return fmt.Errorf(
			"at most %d managed secrets fit before migration PCR31",
			maxManagedSecrets,
		)
	}
	for i, s := range secrets {
		pcrIndex := uint(16) + uint(i)
		secretBytes, err := hex.DecodeString(s.Plaintext)
		if err != nil {
			return fmt.Errorf("decode secret %s hex: %w", s.Name, err)
		}

		// Preserve the historical PCR mapping for persisted secrets, including
		// when a passthrough becomes a seed: interpret the first 32 bytes as an
		// unsigned big-endian integer and reduce modulo N. Derived values were
		// checked by deriveSecret, so this conversion leaves their scalar unchanged.
		_, pubKey := btcec.PrivKeyFromBytes(secretBytes)

		pubkeyBytes := pubKey.SerializeCompressed()
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
// commitment per delivered entry, and every entry's secret is hex: `hash` pins
// the SHA-256 of the decoded secret, `publicKey` pins compressed secp256k1
// public keys whose secrets are private keys.
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

// validateChildEnv stops the baked env or SSM overlay standing in for an inherited secret.
func (sm SecretsMetadata) validateChildEnv(overrideAllowList map[string]bool) error {
	for _, m := range sm.Inherited {
		if overrideAllowList[m.EnvVar] {
			return fmt.Errorf(
				"inherited secret %q: env_var %q is in the override allowlist", m.Name, m.EnvVar)
		}
		if _, baked := os.LookupEnv(m.EnvVar); baked {
			return fmt.Errorf(
				"inherited secret %q: env_var %q is set in the baked environment", m.Name, m.EnvVar)
		}
	}
	return nil
}

// validateInherited also refuses an env_var a static secret already uses.
func (sm SecretsMetadata) validateInherited() error {
	envVars := make(map[string]bool, len(sm.Inherited)+len(sm.Static))
	for _, s := range sm.Static {
		if s.Type != secretTypeSeed {
			envVars[s.EnvVar] = true
		}
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
// each commitment is used once. The secrets are hex, so a comma or colon in one
// can never be mistaken for a separator. The commitments were validated with
// the config; they are decoded again here so the check fails closed on its own.
func verifyInheritedSecret(m InheritSecretMetadata, plaintext string) error {
	values := strings.Split(plaintext, ",")
	for i := range values {
		values[i] = strings.TrimSpace(values[i])
	}
	if len(values) != len(m.Value) {
		return fmt.Errorf(
			"inherited secret %q: value count %d, want %d", m.Name, len(values), len(m.Value),
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
		// An entry may carry app metadata after a colon, "<secret>:<unix-ts>";
		// only the secret is pinned, the entry is delivered whole.
		value, _, _ = strings.Cut(value, ":")
		secretBytes, err := hex.DecodeString(value)
		if err != nil || len(secretBytes) == 0 {
			return fmt.Errorf("inherited secret %q: value %d is not hex", m.Name, i)
		}
		var got []byte
		switch m.Type {
		case inheritSecretTypeHash:
			hash := sha256.Sum256(secretBytes)
			got = hash[:]
		case inheritSecretTypePublicKey:
			if len(secretBytes) != btcec.PrivKeyBytesLen {
				return fmt.Errorf(
					"inherited secret %q: value %d is not a 32-byte private key", m.Name, i,
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
		default:
			// Validation refuses this first; failing here keeps got non-empty
			// below, so it can never match a consumed (nil) commitment.
			return fmt.Errorf("inherited secret %q: unknown type %q", m.Name, m.Type)
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
// cutoff, or already past it, are never watched: the app is launched without
// the latter, so it must be called before the app is launched.
func watchInheritCutoffs(
	ctx context.Context,
	inherited []InheritedSecret,
	interval time.Duration,
) <-chan struct{} {
	restart := make(chan struct{}, 1)
	now := time.Now()
	pending := slices.DeleteFunc(slices.Clone(inherited), func(s InheritedSecret) bool {
		if s.Cutoff.IsZero() {
			return true
		}
		if !s.pastCutoff(now) {
			return false
		}
		slog.Info("inherited secret reached its cutoff before the app started",
			"name", s.Name, "cutoff", s.Cutoff)
		return true
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
			pending = slices.DeleteFunc(pending, func(s InheritedSecret) bool {
				if !s.pastCutoff(current) {
					return false
				}
				slog.Info("inherited secret reached its cutoff", "name", s.Name, "cutoff", s.Cutoff)
				expired = true
				return true
			})

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
