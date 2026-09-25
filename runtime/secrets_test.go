package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

var inheritTestCutoff = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func inheritTestKey(t *testing.T) (string, string) {
	return inheritTestKeyFrom(t, "inherit-secret-test-key")
}

func inheritTestKeyFrom(t *testing.T, seed string) (string, string) {
	t.Helper()
	privBytes := sha256.Sum256([]byte(seed))
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
		meta, err := LoadInheritSecretMetadata(Config{})
		require.NoError(t, err)
		require.Empty(t, meta)
	})

	t.Run("parses entries", func(t *testing.T) {
		meta, err := LoadInheritSecretMetadata(Config{
			InheritSecretConfig: `[{"name":"legacy","env_var":"LEGACY_KEY",` +
				`"type":"hash","value":["ab"],"cutoff":"2030-01-01T00:00:00Z"}]`,
		})
		require.NoError(t, err)
		require.Equal(t, []InheritSecretMetadata{
			{
				Name:   "legacy",
				EnvVar: "LEGACY_KEY",
				Type:   "hash",
				Value:  []string{"ab"},
				Cutoff: inheritTestCutoff,
			},
		}, meta)
	})

	t.Run("rejects malformed cutoff", func(t *testing.T) {
		_, err := LoadInheritSecretMetadata(Config{
			InheritSecretConfig: `[{"name":"legacy","cutoff":"next year"}]`,
		})
		require.Error(t, err)
	})
}

func TestValidateInheritSecrets(t *testing.T) {
	_, pubKey := inheritTestKey(t)
	_, secondPubKey := inheritTestKeyFrom(t, "second-inherit-secret-test-key")
	valid := InheritSecretMetadata{
		Name: "legacy", EnvVar: "LEGACY_KEY", Type: inheritSecretTypePublicKey,
		Value: []string{pubKey}, Cutoff: inheritTestCutoff,
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
		m.Value = []string{pubKey, secondPubKey}
	})))
	require.NoError(t, validate(with(func(m *InheritSecretMetadata) {
		m.Cutoff = time.Time{} // the cutoff is optional
	})))
	require.NoError(t, validate(with(func(m *InheritSecretMetadata) {
		m.Type, m.Value = inheritSecretTypeHash, []string{inheritTestHash("token")}
	})))
	require.NoError(t, validate(with(func(m *InheritSecretMetadata) {
		m.Type = inheritSecretTypeHash
		m.Value = []string{inheritTestHash("token"), inheritTestHash("second token")}
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
			"empty value list",
			with(func(m *InheritSecretMetadata) { m.Value = nil }),
			"at least one",
		},
		{
			"duplicate commitment",
			with(func(m *InheritSecretMetadata) { m.Value = []string{pubKey, pubKey} }),
			"publicKey 1 is a duplicate",
		},
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
		{
			"non hex value",
			with(func(m *InheritSecretMetadata) { m.Value = []string{"zz"} }),
			"not hex",
		},
		{"short hash", with(func(m *InheritSecretMetadata) {
			m.Type, m.Value = inheritSecretTypeHash, []string{"abcd"}
		}), "hash 0 must be"},
		{"malformed hash list entry", with(func(m *InheritSecretMetadata) {
			m.Type = inheritSecretTypeHash
			m.Value = []string{inheritTestHash("token"), "zz"}
		}), "hash 1 is not hex"},
		{"uncompressed public key", with(func(m *InheritSecretMetadata) {
			m.Value = []string{"04" + strings.Repeat("11", 64)}
		}), "publicKey 0 must be 33 bytes"},
		{"off curve public key", with(func(m *InheritSecretMetadata) {
			m.Value = []string{"02" + strings.Repeat("ff", 32)}
		}), "invalid secp256k1 public key"},
		{"empty public key list entry", with(func(m *InheritSecretMetadata) {
			m.Value = []string{pubKey, ""}
		}), "publicKey 1 must be 33 bytes"},
		{"malformed public key list entry", with(func(m *InheritSecretMetadata) {
			m.Value = []string{pubKey, "zz"}
		}), "publicKey 1 is not hex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorContains(t, validate(tt.meta), tt.want)
		})
	}
}

func TestVerifyInheritedSecret(t *testing.T) {
	privKey, pubKey := inheritTestKey(t)
	secondPrivKey, secondPubKey := inheritTestKeyFrom(t, "second-inherit-secret-test-key")
	keyMeta := InheritSecretMetadata{
		Name:  "legacy",
		Type:  inheritSecretTypePublicKey,
		Value: []string{pubKey},
	}
	hashMeta := InheritSecretMetadata{
		Name:  "token",
		Type:  inheritSecretTypeHash,
		Value: []string{inheritTestHash("s3cr3t token")},
	}

	require.NoError(t, verifyInheritedSecret(keyMeta, privKey))
	require.NoError(t, verifyInheritedSecret(hashMeta, "s3cr3t token"))
	// A comma always separates entries, so a value cannot contain one.
	commaHashMeta := hashMeta
	commaHashMeta.Value = []string{inheritTestHash("first,second")}
	require.ErrorContains(t,
		verifyInheritedSecret(commaHashMeta, "first,second"), "value count 2, want 1")

	hashListMeta := hashMeta
	hashListMeta.Value = []string{inheritTestHash("first"), inheritTestHash("second")}
	require.NoError(t, verifyInheritedSecret(hashListMeta, "first,second"))
	require.NoError(t, verifyInheritedSecret(hashListMeta, "second,first"))
	require.NoError(t, verifyInheritedSecret(hashListMeta, "second, first"), "entries are trimmed")
	require.ErrorContains(t, verifyInheritedSecret(hashListMeta, "first"), "value count 1, want 2")
	require.ErrorContains(t,
		verifyInheritedSecret(hashListMeta, "first,wrong"),
		"value 1 does not match an unused pinned hash",
	)
	require.ErrorContains(t,
		verifyInheritedSecret(hashListMeta, "first,first"),
		"value 1 does not match an unused pinned hash",
	)

	keyListMeta := keyMeta
	keyListMeta.Value = []string{pubKey, secondPubKey}
	require.NoError(t, verifyInheritedSecret(keyListMeta, privKey+","+secondPrivKey))
	require.NoError(t, verifyInheritedSecret(keyListMeta, secondPrivKey+","+privKey))
	// Per-key metadata after a colon is delivered to the app but not pinned.
	require.NoError(t, verifyInheritedSecret(
		keyListMeta, privKey+":1798761600,"+secondPrivKey+":1830297600"))
	require.ErrorContains(t,
		verifyInheritedSecret(keyListMeta, privKey+":1798761600,"+privKey+":1830297600"),
		"value 1 does not match")
	require.ErrorContains(t, verifyInheritedSecret(keyListMeta, privKey), "value count 1, want 2")
	otherPrivateKey, _ := inheritTestKeyFrom(t, "other-inherit-secret-test-key")
	require.ErrorContains(t,
		verifyInheritedSecret(keyListMeta, privKey+","+otherPrivateKey),
		"value 1 does not match",
	)
	require.ErrorContains(t,
		verifyInheritedSecret(keyListMeta, privKey+","+privKey),
		"value 1 does not match",
	)
	require.ErrorContains(t,
		verifyInheritedSecret(keyListMeta, privKey+",not-hex"),
		"value 1 is not a hex-encoded 32-byte private key",
	)

	otherKey := sha256.Sum256([]byte("some other key"))
	require.ErrorContains(t,
		verifyInheritedSecret(keyMeta, hex.EncodeToString(otherKey[:])), "does not match")
	require.ErrorContains(t, verifyInheritedSecret(hashMeta, "another token"), "does not match")

	require.ErrorContains(t, verifyInheritedSecret(keyMeta, "not hex"), "32-byte private key")
	require.ErrorContains(t, verifyInheritedSecret(keyMeta, "abcd"), "32-byte private key")
	require.ErrorContains(t, verifyInheritedSecret(keyMeta, strings.Repeat("00", 32)),
		"not a valid secp256k1 private key")
	require.ErrorContains(t, verifyInheritedSecret(keyMeta, strings.Repeat("ff", 32)),
		"not a valid secp256k1 private key")

	// Validation already refuses an unknown type; verification fails closed on its own.
	require.ErrorContains(t, verifyInheritedSecret(InheritSecretMetadata{
		Name: "odd", Type: "ed25519", Value: []string{inheritTestHash("v")},
	}, "v"), `unknown type "ed25519"`)
}

func TestResolveInheritedSecrets(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{Deployment: "dev", AppName: "testapp"}
	privKey, pubKey := inheritTestKey(t)
	now := inheritTestCutoff.Add(-time.Hour)

	keyMeta := InheritSecretMetadata{
		Name: "legacy", EnvVar: "LEGACY_KEY", Type: inheritSecretTypePublicKey,
		Value: []string{pubKey}, Cutoff: inheritTestCutoff,
	}
	hashMeta := InheritSecretMetadata{
		Name: "token", EnvVar: "LEGACY_TOKEN", Type: inheritSecretTypeHash,
		Value: []string{inheritTestHash("s3cr3t")}, Cutoff: inheritTestCutoff,
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
		require.ErrorContains(t, err, `"token": value 0 does not match an unused pinned hash`)
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

func TestSecretsApplyTo(t *testing.T) {
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
	// The baked environment or the SSM overlay may carry every name.
	planted := []string{
		"SIGNING_KEY=planted", "LEGACY_KEY=planted", "LEGACY_TOKEN=planted", "APP_SETTING=kept",
	}
	// What the app would see: exec keeps the last value of a duplicate key.
	childEnv := func(now time.Time) []string {
		return (&exec.Cmd{Env: secrets.applyTo(planted, now)}).Environ()
	}

	require.ElementsMatch(t,
		[]string{"SIGNING_KEY=minted", "LEGACY_KEY=verified", "APP_SETTING=kept"},
		childEnv(inheritTestCutoff.Add(-time.Second)),
		"an inherited secret that was not delivered must not reach the app from the overlay",
	)
	require.ElementsMatch(t,
		[]string{"SIGNING_KEY=minted", "APP_SETTING=kept"},
		childEnv(inheritTestCutoff),
		"nor may one past its cutoff",
	)
	require.Equal(t,
		[]string{
			"SIGNING_KEY=planted", "LEGACY_KEY=planted", "LEGACY_TOKEN=planted", "APP_SETTING=kept",
		},
		planted,
		"the caller's environment must not change",
	)
}

// Boot resolves inherited secrets alongside the static ones.
func TestBootResolvesInheritedSecrets(t *testing.T) {
	ctx := context.Background()

	boot := func(t *testing.T, cutoff, value string) (bootResult, error) {
		t.Helper()
		cfg := stateOriginTestConfig()
		cfg.InheritSecretConfig = `[{"name":"token","env_var":"LEGACY_TOKEN",` +
			`"type":"hash","value":["` + inheritTestHash("s3cr3t") + `"],"cutoff":"` + cutoff + `"}]`
		fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))
		fx.ssmf.params[testCfg.inheritSecretPrefix()+"token"] = value
		b, err := NewBoot(cfg, fx.nsm, fx.kmsf, fx.sts, fx.ssm, fx.s3f)
		if err != nil {
			return bootResult{}, err
		}
		return b.Boot(ctx)
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
		require.ErrorContains(t, err, `"token": value 0 does not match an unused pinned hash`)
	})

	// plan validates the secrets config before anything else, so a Boot with
	// only a config is enough to reach it.
	t.Run("duplicate env var aborts plan", func(t *testing.T) {
		_, pubKey := inheritTestKey(t)
		cfg := testConfig()
		cfg.StaticSecretConfig = `[{"name":"signing-key","env_var":"SIGNING_KEY"}]`
		cfg.InheritSecretConfig = `[{"name":"legacy","env_var":"SIGNING_KEY",` +
			`"type":"publicKey","value":["` + pubKey + `"],"cutoff":"2030-01-01T00:00:00Z"}]`

		_, err := (&Boot{cfg: cfg}).plan(ctx)
		require.ErrorContains(t, err, `env_var "SIGNING_KEY" is already used`)
	})
}
