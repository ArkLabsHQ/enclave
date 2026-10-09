package runtime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fxamacker/cbor/v2"
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

func TestDerivedSecretVectors(t *testing.T) {
	// Independently calculated with Python hashlib/hmac and literal CBOR bytes.
	seed := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	for _, tc := range []struct{ seed, name, info, key string }{
		{
			seed, "signing-key", "6b7369676e696e672d6b6579",
			"bf527f09d8f89bca004c459551dfb5ceb50a4df5edadae180e24e694326810f7",
		},
		{
			seed, "Signing-key", "6b5369676e696e672d6b6579",
			"761643bf0d89a83f06a6cddcdebdcb44d85d7c6b6e0cfe5126ff6a1a88288814",
		},
		{
			seed, "SIGNING-KEY", "6b5349474e494e472d4b4559",
			"5a8565be409c9df49735e71c75addd584784fb6962ab2fcaf981251ba2e4152e",
		},
		{
			seed, "signing-key-v1", "6e7369676e696e672d6b65792d7631",
			"6940476271c06be36d06e1e141ea90f6cf2bd84f77521029c5b646085f1ab8ce",
		},
		{
			seed, "signing-key-v2", "6e7369676e696e672d6b65792d7632",
			"d99feff83f1bd44a1bbf2d323b6b0b1da0256f2a69b88a2469fa6112a3838596",
		},
		{
			strings.Repeat("00", 32), strings.Repeat("a", 24),
			"7818616161616161616161616161616161616161616161616161",
			"c75c82c2b9f482fa4cef23fc5accc2386de864f47e5bd0f9a33cbd38f0143e13",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := cbor.Marshal(tc.name)
			require.NoError(t, err)
			require.Equal(t, tc.info, hex.EncodeToString(info))
			key, err := deriveSecret(mustDecodeHex(t, tc.seed), tc.name)
			require.NoError(t, err)
			require.Equal(t, tc.key, key)
		})
	}
}

func TestInternalDerivationVectors(t *testing.T) {
	// Independent Python hashlib/hmac calculation with literal CBOR text headers.
	seed := mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	for _, tc := range []struct{ name, info, key string }{
		{storageDEKDerivationName, "7272756e74696d652f53746f7261676544454b", "37c7bbea31c2a2c0dac8ec251a580fe290e7d7256f60e318934ccfcdd0d27c78"},
		{acmeAccountKeyDerivationName, "7672756e74696d652f41434d454163636f756e744b6579", "bec57a2982fe406add38a52a6907e4b1658ff8cbcb41b33782a53cdc791ffdea"},
		{"StorageDEK", "6a53746f7261676544454b", "f71b9c41253dc71047f87e42be49cbc7af08e4fde1762f8f800348c38693b99a"},
		{"ACMEAccountKey", "6e41434d454163636f756e744b6579", "37eefb0b1dee3490a97a38fb506af4ae9b6af8a77dd838e814987958f9288641"},
		{"runtime/ACMEAccountKey-v2", "781972756e74696d652f41434d454163636f756e744b65792d7632", "215e66b2f930b853f05467a009af31ae05b8d9f66b3182b2e510723f4e330099"},
		{"leading-zero-188", "706c656164696e672d7a65726f2d313838", "00fbbfbaa53904d6ee9ebe1464ac920cf58571c65d4f81e32adabecba477d0f6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := cbor.Marshal(tc.name)
			require.NoError(t, err)
			require.Equal(t, tc.info, hex.EncodeToString(info))
			raw, err := deriveKeyBytes(seed, tc.name, 32)
			require.NoError(t, err)
			require.Equal(t, tc.key, hex.EncodeToString(raw))
			// Valid first blocks preserve the reference commit's output exactly.
			secret, err := deriveSecret(seed, tc.name)
			require.NoError(t, err)
			require.Equal(t, tc.key, secret)
			require.Len(t, secret, 64)
			if tc.name == acmeAccountKeyDerivationName {
				key, err := deriveACMEAccountKey(seed)
				require.NoError(t, err)
				require.Equal(t, tc.key, hex.EncodeToString(key.D.FillBytes(make([]byte, 32))))
			}
		})
	}
}

func TestSigningScalarSelection(t *testing.T) {
	for _, curve := range []struct {
		name      string
		order     *big.Int
		selectKey func([]byte) ([]byte, error)
	}{
		{"secp256k1", btcec.S256().N, func(blocks []byte) ([]byte, error) {
			key, err := selectSecp256k1Scalar(blocks)
			if err != nil {
				return nil, err
			}
			return hex.DecodeString(key)
		}},
		{"P256", elliptic.P256().Params().N, func(blocks []byte) ([]byte, error) {
			key, err := selectP256Key(blocks)
			if err != nil {
				return nil, err
			}
			// Parsing must construct a usable signer, not just accept the integer.
			digest := make([]byte, 32)
			sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
			require.NoError(t, err)
			require.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest, sig))
			return key.D.FillBytes(make([]byte, 32)), nil
		}},
	} {
		t.Run(curve.name, func(t *testing.T) {
			n := curve.order.FillBytes(make([]byte, 32))
			nPlusOne := new(big.Int).Add(curve.order, big.NewInt(1)).FillBytes(make([]byte, 32))
			nMinusOne := new(big.Int).Sub(curve.order, big.NewInt(1)).FillBytes(make([]byte, 32))
			one := big.NewInt(1).FillBytes(make([]byte, 32))
			for _, tc := range []struct {
				name         string
				blocks, want []byte
			}{
				{"zero", make([]byte, 32), nil},
				{"order", n, nil},
				{"above order", nPlusOne, nil},
				{"maximum integer", bytes.Repeat([]byte{0xff}, 32), nil},
				{"one with leading zeros", one, one},
				{"order minus one", nMinusOne, nMinusOne},
				{"reject then accept", bytes.Join([][]byte{make([]byte, 32), n, nPlusOne, one, nMinusOne}, nil), one},
				{"first valid wins", append(bytes.Clone(nMinusOne), one...), nMinusOne},
				{"last block", append(make([]byte, 254*32), one...), one},
				{"exhaust zero blocks", make([]byte, 255*32), nil},
				{"exhaust overflow blocks", bytes.Repeat(n, 255), nil},
			} {
				t.Run(tc.name, func(t *testing.T) {
					got, err := curve.selectKey(tc.blocks)
					if tc.want == nil {
						require.ErrorContains(t, err, "no valid")
						require.Nil(t, got)
					} else {
						require.NoError(t, err)
						require.Equal(t, tc.want, got)
					}
				})
			}
		})
	}
}

func TestDerivedSeedLengthAcrossHelpers(t *testing.T) {
	for _, length := range []int{0, 1, 31, 33, 64} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			seed := make([]byte, length)
			_, err := deriveKeyBytes(seed, storageDEKDerivationName, 32)
			require.ErrorContains(t, err, "seed must be 32 bytes")
			_, err = deriveSecret(seed, "signing-key")
			require.ErrorContains(t, err, "seed must be 32 bytes")
			_, err = deriveACMEAccountKey(seed)
			require.ErrorContains(t, err, "seed must be 32 bytes")
		})
	}
}

func TestDerivationCBORLengthBoundaries(t *testing.T) {
	seed := mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	// Independent Python HMAC vectors using literal shortest-length CBOR headers.
	for _, tc := range []struct {
		length      int
		header, key string
	}{
		{23, "77", "2f67d1e2c10e60c5a48a3f62d36109d23225bc0ebf74e0564aeed42d9e3d0082"},
		{24, "7818", "498331b950de19b6a234c013fd69c193745b184366702173fe0c12de35f69a02"},
		{255, "78ff", "a5096433c8b8977c3e7eed8a65f469e1a7d02f956f322beed780e0658fe297cf"},
		{256, "790100", "e24a75e5c52865b151272a631301d1ab717740697237861d28c94d59cf493292"},
	} {
		t.Run(fmt.Sprint(tc.length), func(t *testing.T) {
			name := strings.Repeat("a", tc.length)
			encoded, err := cbor.Marshal(name)
			require.NoError(t, err)
			require.Equal(t, append(mustDecodeHex(t, tc.header), []byte(name)...), encoded)
			key, err := deriveSecret(seed, name)
			require.NoError(t, err)
			require.Equal(t, tc.key, key)
		})
	}
}

func requireChildSecretExports(
	t *testing.T,
	cfg Config,
	result bootResult,
	want map[string]string,
) {
	t.Helper()
	values := map[string]string{}
	for _, entry := range (&exec.Cmd{Env: appEnv(cfg, "token", result.secrets)}).Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "DERIVED_TEST_") {
			values[key] = value
		}
	}
	require.Equal(
		t,
		want,
		values,
		"only declared static and resolved inherited secrets are exported",
	)
	tlsDER, err := x509.MarshalPKCS8PrivateKey(result.tlsKey)
	require.NoError(t, err)
	accountDER, err := x509.MarshalPKCS8PrivateKey(result.acmeAccountKey)
	require.NoError(t, err)
	env := strings.Join(appEnv(cfg, "token", result.secrets), "\n")
	for _, secret := range [][]byte{result.masterSeed, result.dek.(*dek).key, tlsDER, accountDER, result.tlsKey.(*ecdsa.PrivateKey).D.FillBytes(make([]byte, 32)), result.acmeAccountKey.(*ecdsa.PrivateKey).D.FillBytes(make([]byte, 32))} {
		require.NotContains(t, env, hex.EncodeToString(secret))
		require.NotContains(t, env, base64.StdEncoding.EncodeToString(secret))
		require.NotContains(t, env, string(secret))
	}
}

func TestDerivedBootLifecycle(t *testing.T) {
	keyA := StaticSecretMetadata{Name: "e2e-signing-key", EnvVar: "DERIVED_TEST_A"}
	keyB := StaticSecretMetadata{Name: "e2e-second-key", EnvVar: "DERIVED_TEST_B"}
	renamedEnv := StaticSecretMetadata{Name: keyA.Name, EnvVar: "DERIVED_TEST_RENAMED"}
	rotated := StaticSecretMetadata{Name: keyA.Name + "-v2", EnvVar: keyA.EnvVar}
	replacement, pin := inheritTestKey(t)
	inherited := InheritSecretMetadata{
		Name:   "replacement",
		EnvVar: keyA.EnvVar,
		Type:   inheritSecretTypePublicKey,
		Value:  []string{pin},
	}
	type stage struct {
		name        string
		static      []StaticSecretMetadata
		replacement bool
	}
	for _, scenario := range []struct {
		name   string
		stages []stage
	}{
		{"declaration changes", []stage{
			{"Blue", []StaticSecretMetadata{keyA}, false},
			{"Green", []StaticSecretMetadata{keyA, keyB}, false},
			{"Red", []StaticSecretMetadata{keyB}, true},
			{"restored with changed env", []StaticSecretMetadata{renamedEnv, keyB}, false},
			{"rotated name", []StaticSecretMetadata{rotated, keyB}, false},
			{"removed all", nil, false},
			{"restored reordered", []StaticSecretMetadata{keyB, keyA}, false},
		}},
		{"no static declarations", []stage{{"genesis", nil, false}, {"successor", nil, false}}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := t.Context()
			fx := newGenesisFixture(t, bytes.Repeat([]byte{1}, 48))
			var first bootResult
			var stored []byte
			var certETag string
			byName := map[string]string{}
			for index, stage := range scenario.stages {
				if !t.Run(stage.name, func(t *testing.T) {
					cfg := migrationTestCfg()
					cfg.FQDN = "enclave.test"
					if index > 0 {
						cfg.PreviousPCR0 = hex.EncodeToString(bytes.Repeat([]byte{byte(index)}, 48))
					}
					raw, err := json.Marshal(stage.static)
					require.NoError(t, err)
					cfg.StaticSecretConfig = string(raw)
					if stage.replacement {
						raw, err = json.Marshal([]InheritSecretMetadata{inherited})
						require.NoError(t, err)
						cfg.InheritSecretConfig = string(raw)
					}
					pcr0 := bytes.Repeat([]byte{byte(index + 1)}, 48)
					var current bootResult
					var currentNSM NSM
					for bootIndex := 0; bootIndex < 2; bootIndex++ { // first boot, resume
						session := newStatefulNSMSession(t, map[uint][]byte{0: pcr0})
						session.attestationSign = fx.signer
						nsm := &nsmW{nsm: &fakeNSM{session: session, verifyRoots: fx.signer.roots}}
						boot, err := NewBoot(cfg, nsm, fx.kmsf, fx.sts, fx.ssm, fx.s3f)
						require.NoError(t, err)
						before := maps.Clone(fx.ssmf.params)
						seq := fx.kmsf.seq
						parent := os.Environ()
						result, err := boot.Boot(ctx)
						require.Equal(
							t,
							parent,
							os.Environ(),
							"boot must not export keys to the parent environment",
						)
						require.NoError(t, err)
						if bootIndex > 0 {
							require.Equal(
								t,
								before,
								fx.ssmf.params,
								"resume must reuse receipts and ciphertexts",
							)
							require.Equal(
								t,
								seq,
								fx.kmsf.seq,
								"resume must not generate or encrypt keys",
							)
						}
						require.Len(t, result.masterSeed, 32)
						require.Len(t, result.secrets.Static, len(stage.static))
						if index == 0 && bootIndex == 0 {
							first = result
							stored, err = result.dek.Seal(
								[]byte("before migration"),
								[]byte("object"),
							)
							require.NoError(t, err)
							store := newCertStore(
								cfg,
								fx.s3f,
								result.dek,
								result.tlsKey,
								"certs",
								cfg.FQDN,
							)
							bundle, err := store.SaveCert(
								ctx,
								issueTestCertWithKey(
									t,
									cfg.FQDN,
									time.Now().Add(90*24*time.Hour),
									result.tlsKey,
								),
								"",
							)
							require.NoError(t, err)
							certETag = bundle.etag
						}
						require.Equal(t, first.masterSeed, result.masterSeed)
						require.Equal(t, first.dek.(*dek).key, result.dek.(*dek).key)
						require.True(
							t,
							first.tlsKey.Public().(*ecdsa.PublicKey).Equal(result.tlsKey.Public()),
						)
						plaintext, err := result.dek.Open(stored, []byte("object"))
						require.NoError(t, err)
						require.Equal(t, []byte("before migration"), plaintext)
						bundle, err := newCertStore(
							cfg,
							fx.s3f,
							result.dek,
							result.tlsKey,
							"certs",
							cfg.FQDN,
						).LoadCert(ctx)
						require.NoError(t, err)
						require.Equal(t, certETag, bundle.etag)
						require.True(
							t,
							first.acmeAccountKey.Public().(*ecdsa.PublicKey).Equal(
								result.acmeAccountKey.Public(),
							),
							"ACME account key must survive every boot and migration",
						)
						var ciphertextPaths []string
						for path := range fx.ssmf.params {
							if strings.HasSuffix(path, "/Ciphertext/"+result.kms.KeyID()) {
								ciphertextPaths = append(ciphertextPaths, path)
							}
						}
						require.ElementsMatch(
							t,
							[]string{
								cfg.masterSeedCiphertextParam(result.kms.KeyID()),
								cfg.tlsKeyCiphertextParam(result.kms.KeyID()),
							},
							ciphertextPaths,
						)
						require.NoError(
							t,
							ExtendPCRRegistersWithStaticSecrets(nsm, result.secrets.Static),
						)
						wantEnv := map[string]string{}
						for i, secret := range result.secrets.Static {
							require.Equal(t, stage.static[i], secret.StaticSecretMetadata)
							if old, ok := byName[secret.Name]; ok {
								require.Equal(t, old, secret.Plaintext)
							} else {
								for _, old := range byName {
									require.NotEqual(t, old, secret.Plaintext)
								}
								byName[secret.Name] = secret.Plaintext
							}
							wantEnv[secret.EnvVar] = secret.Plaintext
							_, pub := btcec.PrivKeyFromBytes(mustDecodeHex(t, secret.Plaintext))
							hash := sha256.Sum256(pub.SerializeCompressed())
							require.Equal(t, hash[:], requireExtendPCR(t, session, uint(16+i)).Data)
							require.True(t, session.locks[uint(16+i)])
						}
						require.Len(
							t,
							session.locks,
							len(stage.static),
							"master seed and internal keys consume no application PCR",
						)
						if stage.replacement && bootIndex > 0 {
							wantEnv[inherited.EnvVar] = replacement
						}
						requireChildSecretExports(t, *cfg, result, wantEnv)
						current, currentNSM = result, nsm
						if stage.replacement && bootIndex == 0 {
							fx.ssmf.params[cfg.inheritSecretPrefix()+inherited.Name] = replacement
						}
					}
					if index+1 < len(scenario.stages) {
						m, err := newMigrator(
							cfg,
							currentNSM,
							fx.ssm,
							fx.s3f,
							current.migrationIntentBucketName,
						)
						require.NoError(t, err)
						m.kms, m.masterSeed, m.tlsKey = current.kms, current.masterSeed, current.tlsKey
						_, err = requestMigrationTo(
							t,
							ctx,
							m,
							fx.signer,
							hex.EncodeToString(bytes.Repeat([]byte{byte(index + 2)}, 48)),
						)
						require.NoError(t, err)
						require.NoError(t, m.handOffToSuccessor(ctx))
					}
				}) {
					return
				}
			}
		})
	}
}

func inheritTestHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

// inheritTestHex is value as delivered for a `hash` secret pinned by inheritTestHash.
func inheritTestHex(value string) string {
	return hex.EncodeToString([]byte(value))
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

func TestValidateStaticSecrets(t *testing.T) {
	require.NoError(t, SecretsMetadata{Static: stateOriginTestSecrets}.Validate(nil))
	for _, tc := range []struct {
		name, env string
		valid     bool
	}{
		{"signing-key", "SIGNING_KEY", true},
		{"A_Z.09-a", "_KEY0", true},
		{"StorageDEK", "KEY", true},
		{"ACMEAccountKey", "KEY", true},
		{"MasterSeed", "KEY", true},
		{"runtime/StorageDEK", "KEY", false},
		{"runtime/ACMEAccountKey", "KEY", false},
		{"runtime/ACMEAccountKey-v2", "KEY", false},
		{"runtime/future-key", "KEY", false},
		{"some/other", "KEY", false},
		{"", "KEY", false},
		{"../key", "KEY", false},
		{"café", "KEY", false},
		{" key", "KEY", false},
		{"key\x00", "KEY", false},
		{"key", "", false},
		{"key", "0KEY", false},
		{"key", "BAD=KEY", false},
		{"key", "PORT", false},
		{"key", "ENCLAVE_RUNTIME_TOKEN", false},
		{"key", "ENCLAVE_APP_PORT", false},
		{"key", "ENCLAVE_PROXY_PORT", false},
	} {
		t.Run(tc.name+"/"+tc.env, func(t *testing.T) {
			err := (SecretsMetadata{Static: []StaticSecretMetadata{{Name: tc.name, EnvVar: tc.env}}}).Validate(
				nil,
			)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
	require.Error(t, SecretsMetadata{Static: []StaticSecretMetadata{
		{Name: "duplicate", EnvVar: "ONE"},
		{Name: "duplicate", EnvVar: "TWO"},
	}}.Validate(nil))
	require.Error(t, SecretsMetadata{Static: []StaticSecretMetadata{
		{Name: "one", EnvVar: "KEY"},
		{Name: "two", EnvVar: "KEY"},
	}}.Validate(nil))
	_, pin := inheritTestKey(t)
	require.Error(t, SecretsMetadata{
		Static: []StaticSecretMetadata{{Name: "one", EnvVar: "KEY"}},
		Inherited: []InheritSecretMetadata{
			{Name: "two", EnvVar: "KEY", Type: inheritSecretTypePublicKey, Value: []string{pin}},
		},
	}.Validate(nil))

	var meta SecretsMetadata
	for i := 0; i < 15; i++ {
		meta.Static = append(meta.Static, StaticSecretMetadata{
			Name: fmt.Sprintf("key%d", i), EnvVar: fmt.Sprintf("KEY%d", i),
		})
	}
	require.NoError(t, meta.Validate(nil))
	meta.Static = append(meta.Static, StaticSecretMetadata{Name: "extra", EnvVar: "EXTRA"})
	require.ErrorContains(t, meta.Validate(nil), "PCR16–PCR30")

	session := newStatefulNSMSession(t, nil)
	require.Error(t, ExtendPCRRegistersWithStaticSecrets(
		&nsmW{nsm: &fakeNSM{session: session}}, make([]StaticSecret, 16),
	))
	require.Empty(t, session.requests)
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
		return SecretsMetadata{Static: static, Inherited: inherited}.Validate(nil)
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
	require.NoError(t, verifyInheritedSecret(hashMeta, inheritTestHex("s3cr3t token")))
	require.NoError(t, verifyInheritedSecret(hashMeta,
		strings.ToUpper(inheritTestHex("s3cr3t token"))), "the decoded bytes are pinned")
	// A hash secret must be hex, so it can hold neither separator.
	require.ErrorContains(t, verifyInheritedSecret(hashMeta, "s3cr3t token"), "value 0 is not hex")
	require.ErrorContains(t, verifyInheritedSecret(hashMeta, ":1798761600"), "value 0 is not hex")
	// Metadata after a colon is delivered to the app but not pinned.
	require.NoError(t,
		verifyInheritedSecret(hashMeta, inheritTestHex("s3cr3t token")+":1798761600"))
	require.ErrorContains(t,
		verifyInheritedSecret(hashMeta, inheritTestHex("another token")+":1798761600"),
		"does not match")
	emptyHashMeta := hashMeta
	emptyHashMeta.Value = []string{inheritTestHash("")}
	require.ErrorContains(t, verifyInheritedSecret(emptyHashMeta, ""), "value 0 is not hex")

	hashListMeta := hashMeta
	hashListMeta.Value = []string{inheritTestHash("first"), inheritTestHash("second")}
	first, second := inheritTestHex("first"), inheritTestHex("second")
	require.NoError(t, verifyInheritedSecret(hashListMeta, first+","+second))
	require.NoError(t, verifyInheritedSecret(hashListMeta, second+","+first))
	require.NoError(
		t,
		verifyInheritedSecret(hashListMeta, first+":1798761600,"+second+":1830297600"),
	)
	require.NoError(
		t,
		verifyInheritedSecret(hashListMeta, second+", "+first),
		"entries are trimmed",
	)
	require.ErrorContains(t, verifyInheritedSecret(hashListMeta, first), "value count 1, want 2")
	require.ErrorContains(
		t,
		verifyInheritedSecret(hashListMeta, first+","+inheritTestHex("wrong")),
		"value 1 does not match an unused pinned hash",
	)
	require.ErrorContains(
		t,
		verifyInheritedSecret(hashListMeta, first+","+first),
		"value 1 does not match an unused pinned hash",
	)

	keyListMeta := keyMeta
	keyListMeta.Value = []string{pubKey, secondPubKey}
	require.NoError(t, verifyInheritedSecret(keyListMeta, privKey+","+secondPrivKey))
	require.NoError(t, verifyInheritedSecret(keyListMeta, secondPrivKey+","+privKey))
	// Per-key metadata after a colon is delivered to the app but not pinned.
	require.NoError(t, verifyInheritedSecret(
		keyListMeta, privKey+":1798761600,"+secondPrivKey+":1830297600",
	))
	require.ErrorContains(t,
		verifyInheritedSecret(keyListMeta, privKey+":1798761600,"+privKey+":1830297600"),
		"value 1 does not match")
	require.ErrorContains(t, verifyInheritedSecret(keyListMeta, privKey), "value count 1, want 2")
	otherPrivateKey, _ := inheritTestKeyFrom(t, "other-inherit-secret-test-key")
	require.ErrorContains(
		t,
		verifyInheritedSecret(keyListMeta, privKey+","+otherPrivateKey),
		"value 1 does not match",
	)
	require.ErrorContains(
		t,
		verifyInheritedSecret(keyListMeta, privKey+","+privKey),
		"value 1 does not match",
	)
	require.ErrorContains(
		t,
		verifyInheritedSecret(keyListMeta, privKey+",not-hex"),
		"value 1 is not hex",
	)

	otherKey := sha256.Sum256([]byte("some other key"))
	require.ErrorContains(t,
		verifyInheritedSecret(keyMeta, hex.EncodeToString(otherKey[:])), "does not match")
	require.ErrorContains(t,
		verifyInheritedSecret(hashMeta, inheritTestHex("another token")), "does not match")

	require.ErrorContains(t, verifyInheritedSecret(keyMeta, "not hex"), "value 0 is not hex")
	require.ErrorContains(t, verifyInheritedSecret(keyMeta, "abcd"), "32-byte private key")
	require.ErrorContains(t, verifyInheritedSecret(keyMeta, strings.Repeat("00", 32)),
		"not a valid secp256k1 private key")
	require.ErrorContains(t, verifyInheritedSecret(keyMeta, strings.Repeat("ff", 32)),
		"not a valid secp256k1 private key")

	// Validation already refuses an unknown type; verification fails closed on its own.
	require.ErrorContains(t, verifyInheritedSecret(InheritSecretMetadata{
		Name: "odd", Type: "ed25519", Value: []string{inheritTestHash("v")},
	}, inheritTestHex("v")), `unknown type "ed25519"`)
}

func TestResolveInheritedSecrets(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{Namespace: "dev", AppName: "testapp"}
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
			"/dev/testapp/enclave/inherit/legacy": privKey + "\n",
			"/dev/testapp/enclave/inherit/token":  inheritTestHex("s3cr3t"),
		}}
		secrets, err := resolveInheritedSecrets(ctx, cfg, NewSSM(fake), meta, now)
		require.NoError(t, err)
		require.Equal(t, []InheritedSecret{
			{InheritSecretMetadata: keyMeta, Plaintext: privKey},
			{InheritSecretMetadata: hashMeta, Plaintext: inheritTestHex("s3cr3t")},
		}, secrets)
		require.Equal(t, []string{
			"/dev/testapp/enclave/inherit/legacy", "/dev/testapp/enclave/inherit/token",
		}, fake.decryptedGets, "SecureString values must be decrypted")
	})

	t.Run("mismatch is fatal", func(t *testing.T) {
		_, err := resolveInheritedSecrets(ctx, cfg, NewSSM(&fakeSSM{params: map[string]string{
			"/dev/testapp/enclave/inherit/legacy": privKey,
			"/dev/testapp/enclave/inherit/token":  inheritTestHex("tampered"),
		}}), meta, now)
		require.ErrorContains(t, err, `"token": value 0 does not match an unused pinned hash`)
	})

	t.Run("missing param is skipped", func(t *testing.T) {
		secrets, err := resolveInheritedSecrets(ctx, cfg, NewSSM(&fakeSSM{params: map[string]string{
			"/dev/testapp/enclave/inherit/token": inheritTestHex("s3cr3t"),
		}}), meta, now)
		require.NoError(t, err)
		require.Equal(
			t,
			[]InheritedSecret{
				{InheritSecretMetadata: hashMeta, Plaintext: inheritTestHex("s3cr3t")},
			},
			secrets,
		)
	})

	// An expired secret's parameter may already be unreadable
	t.Run("past cutoff is never read", func(t *testing.T) {
		expired := hashMeta
		expired.Cutoff = now
		fake := &fakeSSM{
			params: map[string]string{"/dev/testapp/enclave/inherit/legacy": privKey},
			getErrs: map[string]error{
				"/dev/testapp/enclave/inherit/token": errors.New("KMS key disabled"),
			},
		}
		secrets, err := resolveInheritedSecrets(
			ctx, cfg, NewSSM(fake), []InheritSecretMetadata{keyMeta, expired}, now,
		)
		require.NoError(t, err)
		require.Equal(
			t,
			[]InheritedSecret{{InheritSecretMetadata: keyMeta, Plaintext: privKey}},
			secrets,
		)
		require.NotContains(t, fake.calls, "/dev/testapp/enclave/inherit/token")
	})

	t.Run("returns SSM errors", func(t *testing.T) {
		_, err := resolveInheritedSecrets(
			ctx, cfg, NewSSM(&fakeSSM{err: errors.New("access denied")}), meta, now,
		)
		require.Error(t, err)
	})
}

func TestValidateChildEnv(t *testing.T) {
	meta := SecretsMetadata{
		Static:    []StaticSecretMetadata{{Name: "signing-key", EnvVar: "SIGNING_KEY"}},
		Inherited: []InheritSecretMetadata{{Name: "legacy", EnvVar: "LEGACY_KEY"}},
	}
	// A static secret is always set, so it may share its env var with either.
	t.Setenv("SIGNING_KEY", "baked")
	require.NoError(t,
		meta.validateChildEnv(map[string]bool{"SIGNING_KEY": true, "APP_SETTING": true}))

	require.ErrorContains(t,
		meta.validateChildEnv(map[string]bool{"LEGACY_KEY": true}), "override allowlist")
	t.Setenv("LEGACY_KEY", "")
	require.ErrorContains(t, meta.validateChildEnv(nil), "baked environment")
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
		result, err := boot(t, "2999-01-01T00:00:00Z", inheritTestHex("s3cr3t"))
		require.NoError(t, err)
		require.Len(t, result.secrets.Inherited, 1)
		require.Equal(t, inheritTestHex("s3cr3t"), result.secrets.Inherited[0].Plaintext)
		require.Len(t, result.secrets.Static, len(stateOriginTestSecrets))
	})

	t.Run("past cutoff", func(t *testing.T) {
		result, err := boot(t, "2020-01-01T00:00:00Z", inheritTestHex("s3cr3t"))
		require.NoError(t, err)
		require.Empty(t, result.secrets.Inherited)
	})

	t.Run("mismatch aborts boot", func(t *testing.T) {
		_, err := boot(t, "2999-01-01T00:00:00Z", inheritTestHex("tampered"))
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

	t.Run("allowlisted env var aborts plan", func(t *testing.T) {
		_, pubKey := inheritTestKey(t)
		cfg := testConfig()
		cfg.InheritSecretConfig = `[{"name":"legacy","env_var":"LEGACY_KEY",` +
			`"type":"publicKey","value":["` + pubKey + `"]}]`
		cfg.OverrideAllowList = map[string]bool{"LEGACY_KEY": true}

		_, err := (&Boot{cfg: cfg}).plan(ctx)
		require.ErrorContains(t, err, `env_var "LEGACY_KEY" is in the override allowlist`)
	})
}
