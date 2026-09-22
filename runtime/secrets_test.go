package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

var inheritTestCutoff = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func inheritTestKey(t *testing.T) (string, string) {
	t.Helper()
	privBytes := sha256.Sum256([]byte("inherit-secret-test-key"))
	privKey, _ := btcec.PrivKeyFromBytes(privBytes[:])
	pubBytes := privKey.PubKey().SerializeCompressed()
	return hex.EncodeToString(privBytes[:]), hex.EncodeToString(pubBytes)
}

func inheritTestHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func TestLoadInheritSecretMetadata(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv("ENCLAVE_INHERIT_SECRETS_CONFIG", "")
		meta, err := LoadInheritSecretMetadata()
		require.NoError(t, err)
		require.Empty(t, meta)
	})

	t.Run("parses entries", func(t *testing.T) {
		t.Setenv("ENCLAVE_INHERIT_SECRETS_CONFIG", `[{"name":"legacy","env_var":"LEGACY_KEY",`+
			`"type":"hash","value":"ab","cutoff":"2030-01-01T00:00:00Z"}]`)
		meta, err := LoadInheritSecretMetadata()
		require.NoError(t, err)
		require.Equal(t, []InheritSecretMetadata{
			{
				Name:   "legacy",
				EnvVar: "LEGACY_KEY",
				Type:   "hash",
				Value:  "ab",
				Cutoff: inheritTestCutoff,
			},
		}, meta)
	})

	t.Run("rejects malformed cutoff", func(t *testing.T) {
		t.Setenv("ENCLAVE_INHERIT_SECRETS_CONFIG", `[{"name":"legacy","cutoff":"next year"}]`)
		_, err := LoadInheritSecretMetadata()
		require.Error(t, err)
	})
}

func TestValidateInheritSecrets(t *testing.T) {
	_, pubKey := inheritTestKey(t)
	valid := InheritSecretMetadata{
		Name: "legacy", EnvVar: "LEGACY_KEY", Type: inheritSecretTypePublicKey,
		Value: pubKey, Cutoff: inheritTestCutoff,
	}
	with := func(mutate func(*InheritSecretMetadata)) []InheritSecretMetadata {
		m := valid
		mutate(&m)
		return []InheritSecretMetadata{m}
	}
	static := []StaticSecretMetadata{{Name: "signing-key", EnvVar: "SIGNING_KEY"}}
	validate := func(inherited []InheritSecretMetadata) error {
		return SecretsMetadata{Static: static, Inherited: inherited}.Validate()
	}

	require.NoError(t, validate(nil))
	require.NoError(t, validate([]InheritSecretMetadata{valid}))
	require.NoError(t, validate(with(func(m *InheritSecretMetadata) {
		m.Type, m.Value = inheritSecretTypeHash, inheritTestHash("token")
	})))

	tests := []struct {
		name string
		meta []InheritSecretMetadata
		want string
	}{
		{
			"empty name",
			with(func(m *InheritSecretMetadata) { m.Name = "" }),
			"single SSM path segment",
		},
		{
			"nested name",
			with(func(m *InheritSecretMetadata) { m.Name = "a/b" }),
			"single SSM path segment",
		},
		{
			"name outside the SSM charset",
			with(func(m *InheritSecretMetadata) { m.Name = "my secret" }),
			"single SSM path segment",
		},
		{"duplicate name", []InheritSecretMetadata{valid, valid}, "duplicate inherited secret"},
		{
			"empty env var",
			with(func(m *InheritSecretMetadata) { m.EnvVar = "" }),
			"invalid env_var",
		},
		{
			"malformed env var",
			with(func(m *InheritSecretMetadata) { m.EnvVar = "A=B" }),
			"invalid env_var",
		},
		{
			"non overridable env var",
			with(func(m *InheritSecretMetadata) { m.EnvVar = "ENCLAVE_DEV" }),
			"reserved",
		},
		{"child env var", with(func(m *InheritSecretMetadata) { m.EnvVar = "PORT" }), "reserved"},
		{
			"static secret env var",
			with(func(m *InheritSecretMetadata) { m.EnvVar = "SIGNING_KEY" }),
			"already used",
		},
		{"shared env var", []InheritSecretMetadata{valid, with(func(m *InheritSecretMetadata) {
			m.Name = "other"
		})[0]}, "already used"},
		{
			"unknown type",
			with(func(m *InheritSecretMetadata) { m.Type = "ed25519" }),
			"unknown type",
		},
		{"non hex value", with(func(m *InheritSecretMetadata) { m.Value = "zz" }), "not hex"},
		{"short hash", with(func(m *InheritSecretMetadata) {
			m.Type, m.Value = inheritSecretTypeHash, "abcd"
		}), "hash must be"},
		{"uncompressed public key", with(func(m *InheritSecretMetadata) {
			m.Value = "04" + strings.Repeat("11", 64)
		}), "compressed"},
		{"off curve public key", with(func(m *InheritSecretMetadata) {
			m.Value = "02" + strings.Repeat("ff", 32)
		}), "invalid secp256k1 public key"},
		{
			"missing cutoff",
			with(func(m *InheritSecretMetadata) { m.Cutoff = time.Time{} }),
			"cutoff is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorContains(t, validate(tt.meta), tt.want)
		})
	}
}

func TestVerifyInheritedSecret(t *testing.T) {
	privKey, pubKey := inheritTestKey(t)
	keyMeta := InheritSecretMetadata{
		Name:  "legacy",
		Type:  inheritSecretTypePublicKey,
		Value: pubKey,
	}
	hashMeta := InheritSecretMetadata{
		Name: "token", Type: inheritSecretTypeHash, Value: inheritTestHash("s3cr3t token"),
	}

	require.NoError(t, verifyInheritedSecret(keyMeta, privKey))
	require.NoError(t, verifyInheritedSecret(hashMeta, "s3cr3t token"))

	otherKey := sha256.Sum256([]byte("some other key"))
	require.ErrorContains(t,
		verifyInheritedSecret(keyMeta, hex.EncodeToString(otherKey[:])), "does not match")
	require.ErrorContains(t, verifyInheritedSecret(hashMeta, "another token"), "does not match")

	require.ErrorContains(t, verifyInheritedSecret(keyMeta, "not hex"), "32-byte private key")
	require.ErrorContains(t, verifyInheritedSecret(keyMeta, "abcd"), "32-byte private key")
	require.ErrorContains(t,
		verifyInheritedSecret(keyMeta, strings.Repeat("00", 32)), "invalid secp256k1 private key")
	require.ErrorContains(t,
		verifyInheritedSecret(keyMeta, strings.Repeat("ff", 32)), "invalid secp256k1 private key")
}

func TestResolveInheritedSecrets(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{Deployment: "dev", AppName: "testapp"}
	privKey, pubKey := inheritTestKey(t)
	now := inheritTestCutoff.Add(-time.Hour)

	keyMeta := InheritSecretMetadata{
		Name: "legacy", EnvVar: "LEGACY_KEY", Type: inheritSecretTypePublicKey,
		Value: pubKey, Cutoff: inheritTestCutoff,
	}
	hashMeta := InheritSecretMetadata{
		Name: "token", EnvVar: "LEGACY_TOKEN", Type: inheritSecretTypeHash,
		Value: inheritTestHash("s3cr3t"), Cutoff: inheritTestCutoff,
	}
	meta := []InheritSecretMetadata{keyMeta, hashMeta}

	t.Run("returns verified secrets read with decryption", func(t *testing.T) {
		fake := &fakeSSM{params: map[string]string{
			"/dev/testapp/inherit/legacy": privKey + "\n",
			"/dev/testapp/inherit/token":  "s3cr3t",
		}}
		secrets, err := resolveInheritedSecrets(ctx, cfg, NewSSM(fake), meta, now)
		require.NoError(t, err)
		require.Equal(t, []InheritedSecret{
			{InheritSecretMetadata: keyMeta, Plaintext: privKey},
			{InheritSecretMetadata: hashMeta, Plaintext: "s3cr3t"},
		}, secrets)
		require.Equal(t, []string{
			"/dev/testapp/inherit/legacy", "/dev/testapp/inherit/token",
		}, fake.decryptedGets, "SecureString values must be decrypted")
	})

	t.Run("mismatch is fatal", func(t *testing.T) {
		_, err := resolveInheritedSecrets(ctx, cfg, NewSSM(&fakeSSM{params: map[string]string{
			"/dev/testapp/inherit/legacy": privKey,
			"/dev/testapp/inherit/token":  "tampered",
		}}), meta, now)
		require.ErrorContains(t, err, `"token" does not match`)
	})

	t.Run("missing param is skipped", func(t *testing.T) {
		secrets, err := resolveInheritedSecrets(ctx, cfg, NewSSM(&fakeSSM{params: map[string]string{
			"/dev/testapp/inherit/token": "s3cr3t",
		}}), meta, now)
		require.NoError(t, err)
		require.Equal(
			t,
			[]InheritedSecret{{InheritSecretMetadata: hashMeta, Plaintext: "s3cr3t"}},
			secrets,
		)
	})

	// An expired secret's parameter may already be unreadable
	t.Run("past cutoff is never read", func(t *testing.T) {
		expired := hashMeta
		expired.Cutoff = now
		fake := &fakeSSM{
			params:  map[string]string{"/dev/testapp/inherit/legacy": privKey},
			getErrs: map[string]error{"/dev/testapp/inherit/token": errors.New("KMS key disabled")},
		}
		secrets, err := resolveInheritedSecrets(
			ctx, cfg, NewSSM(fake), []InheritSecretMetadata{keyMeta, expired}, now)
		require.NoError(t, err)
		require.Equal(
			t,
			[]InheritedSecret{{InheritSecretMetadata: keyMeta, Plaintext: privKey}},
			secrets,
		)
		require.NotContains(t, fake.calls, "/dev/testapp/inherit/token")
	})

	t.Run("returns SSM errors", func(t *testing.T) {
		_, err := resolveInheritedSecrets(
			ctx, cfg, NewSSM(&fakeSSM{err: errors.New("access denied")}), meta, now)
		require.Error(t, err)
	})
}

func TestSecretsSetEnvVars(t *testing.T) {
	// The overlay runs first, so the host may have planted every name.
	t.Setenv("SIGNING_KEY", "planted")
	t.Setenv("LEGACY_KEY", "planted")
	t.Setenv("LEGACY_TOKEN", "planted")

	staticMeta := StaticSecretMetadata{Name: "signing-key", EnvVar: "SIGNING_KEY"}
	keyMeta := InheritSecretMetadata{
		Name:   "legacy",
		EnvVar: "LEGACY_KEY",
		Cutoff: inheritTestCutoff,
	}
	tokenMeta := InheritSecretMetadata{
		Name:   "token",
		EnvVar: "LEGACY_TOKEN",
		Cutoff: inheritTestCutoff,
	}

	secrets := Secrets{
		Static:    []StaticSecret{{StaticSecretMetadata: staticMeta, Plaintext: "minted"}},
		Inherited: []InheritedSecret{{InheritSecretMetadata: keyMeta, Plaintext: "verified"}},
		metadata: SecretsMetadata{
			Static:    []StaticSecretMetadata{staticMeta},
			Inherited: []InheritSecretMetadata{keyMeta, tokenMeta},
		},
	}
	require.NoError(t, secrets.SetEnvVars())

	require.Equal(t, "minted", os.Getenv("SIGNING_KEY"))
	require.Equal(t, "verified", os.Getenv("LEGACY_KEY"))
	_, planted := os.LookupEnv("LEGACY_TOKEN")
	require.False(
		t,
		planted,
		"an inherited secret that was not delivered must not reach the app from the overlay",
	)
}

// Boot resolves inherited secrets alongside the static ones.
func TestBootResolvesInheritedSecrets(t *testing.T) {
	ctx := context.Background()

	boot := func(t *testing.T, cutoff, value string) (bootResult, error) {
		t.Helper()
		setStateOriginTestEnv(t)
		t.Setenv("ENCLAVE_INHERIT_SECRETS_CONFIG", `[{"name":"token","env_var":"LEGACY_TOKEN",`+
			`"type":"hash","value":"`+inheritTestHash("s3cr3t")+`","cutoff":"`+cutoff+`"}]`)
		fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))
		fx.ssmf.params[testCfg.inheritSecretPrefix()+"token"] = value
		return fx.establish(ctx)
	}

	t.Run("before cutoff", func(t *testing.T) {
		result, err := boot(t, "2999-01-01T00:00:00Z", "s3cr3t")
		require.NoError(t, err)
		require.Len(t, result.secrets.Inherited, 1)
		require.Equal(t, "s3cr3t", result.secrets.Inherited[0].Plaintext)
		require.Len(t, result.secrets.Static, len(stateOriginTestSecrets))
	})

	t.Run("past cutoff", func(t *testing.T) {
		result, err := boot(t, "2020-01-01T00:00:00Z", "s3cr3t")
		require.NoError(t, err)
		require.Empty(t, result.secrets.Inherited)
	})

	t.Run("mismatch aborts boot", func(t *testing.T) {
		_, err := boot(t, "2999-01-01T00:00:00Z", "tampered")
		require.ErrorContains(t, err, `"token" does not match`)
	})

	// plan validates the secrets config before anything else, so an empty Boot
	// is enough to reach it.
	t.Run("duplicate env var aborts plan", func(t *testing.T) {
		_, pubKey := inheritTestKey(t)
		t.Setenv("ENCLAVE_SECRETS_CONFIG", `[{"name":"signing-key","env_var":"SIGNING_KEY"}]`)
		t.Setenv("ENCLAVE_INHERIT_SECRETS_CONFIG", `[{"name":"legacy","env_var":"SIGNING_KEY",`+
			`"type":"publicKey","value":"`+pubKey+`","cutoff":"2030-01-01T00:00:00Z"}]`)

		_, err := (&Boot{}).plan(ctx)
		require.ErrorContains(t, err, `env_var "SIGNING_KEY" is already used`)
	})
}
