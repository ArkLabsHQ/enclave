package runtime

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestDerivedSecretVectors(t *testing.T) {
	// Independently calculated with Python hashlib/hmac and literal CBOR bytes.
	seed := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	t.Run("valid", func(t *testing.T) {
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
	})

	t.Run("invalid", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			seed    []byte
			wantErr string
		}{
			{"empty seed", nil, "seed must be 32 bytes, got 0"},
			{"short seed", make([]byte, 31), "seed must be 32 bytes, got 31"},
			{"long seed", make([]byte, 33), "seed must be 32 bytes, got 33"},
			{"double length seed", make([]byte, 64), "seed must be 32 bytes, got 64"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				key, err := deriveSecret(tc.seed, "signing-key")
				require.EqualError(t, err, tc.wantErr)
				require.Empty(t, key)
			})
		}
	})
}

func TestLoadManagedSecretMetadata(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			raw  string
			want []StaticSecretMetadata
		}{
			{name: "unset"},
			{
				name: "unknown field ignored",
				raw:  `[{"name":"key","env_var":"KEY","version":1}]`,
				want: []StaticSecretMetadata{{Name: "key", EnvVar: "KEY"}},
			},
			{
				name: "omitted type",
				raw:  `[{"name":"key","env_var":"KEY"}]`,
				want: []StaticSecretMetadata{{Name: "key", EnvVar: "KEY"}},
			},
			{
				name: "explicit passthrough",
				raw:  `[{"name":"key","type":"passthrough","env_var":"KEY"}]`,
				want: []StaticSecretMetadata{{Name: "key", Type: secretTypePassthrough, EnvVar: "KEY"}},
			},
			{
				name: "seed preserves ignored env var",
				raw:  `[{"name":"key","type":"seed","env_var":"ignored=anything"}]`,
				want: []StaticSecretMetadata{{Name: "key", Type: secretTypeSeed, EnvVar: "ignored=anything"}},
			},
			{
				name: "derived before seed",
				raw: `[{"name":"app","type":"derived","seed":"key","env_var":"KEY"},
				      {"name":"key","type":"seed","env_var":"KEY"}]`,
				want: []StaticSecretMetadata{
					{Name: "app", Type: secretTypeDerived, Seed: "key", EnvVar: "KEY"},
					{Name: "key", Type: secretTypeSeed, EnvVar: "KEY"},
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				meta, err := LoadStaticSecretMetadata(Config{StaticSecretConfig: tc.raw})
				require.NoError(t, err)
				require.Equal(t, tc.want, meta)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			raw     string
			wantErr string
		}{
			{
				name:    "multiple arrays",
				raw:     `[] []`,
				wantErr: "invalid character '[' after top-level value",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := LoadStaticSecretMetadata(Config{StaticSecretConfig: tc.raw})
				require.ErrorContains(t, err, tc.wantErr)
			})
		}
	})
}

func TestManagedSecretMetadata(t *testing.T) {
	_, pin := inheritTestKey(t)
	inherited := []InheritSecretMetadata{{
		Name: "same", EnvVar: "INHERITED",
		Type: inheritSecretTypePublicKey, Value: []string{pin},
	}}
	t.Run("valid", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			static    []StaticSecretMetadata
			inherited []InheritSecretMetadata
		}{
			{
				name:   "omitted type",
				static: []StaticSecretMetadata{{Name: "key", EnvVar: "KEY"}},
			},
			{
				name:   "explicit passthrough ignores seed reference",
				static: []StaticSecretMetadata{{Name: "key", Type: secretTypePassthrough, EnvVar: "KEY", Seed: "other"}},
			},
			{
				name:   "passthrough ignores seed reference",
				static: []StaticSecretMetadata{{Name: "key", EnvVar: "KEY", Seed: "other"}},
			},
			{
				name:   "seed ignores seed reference",
				static: []StaticSecretMetadata{{Name: "key", Type: secretTypeSeed, Seed: "other"}},
			},
			{
				name:   "seed ignores malformed env var",
				static: []StaticSecretMetadata{{Name: "key", Type: secretTypeSeed, EnvVar: "ignored=anything"}},
			},
			{
				name: "derived before seed with shared env var",
				static: []StaticSecretMetadata{
					{Name: "app", Type: secretTypeDerived, Seed: "key", EnvVar: "KEY"},
					{Name: "key", Type: secretTypeSeed, EnvVar: "KEY"},
				},
			},
			{
				name:      "seed and inherited names are separate domains",
				static:    []StaticSecretMetadata{{Name: "same", Type: secretTypeSeed, EnvVar: "INHERITED"}},
				inherited: inherited,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				err := (SecretsMetadata{Static: tc.static, Inherited: tc.inherited}).Validate(nil)
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			static    []StaticSecretMetadata
			inherited []InheritSecretMetadata
			wantErr   string
		}{
			{
				name:    "unknown type",
				static:  []StaticSecretMetadata{{Name: "key", Type: "unknown", EnvVar: "KEY"}},
				wantErr: `secret "key": unknown type "unknown"`,
			},
			{
				name:    "derived requires a seed reference",
				static:  []StaticSecretMetadata{{Name: "key", Type: secretTypeDerived, EnvVar: "KEY"}},
				wantErr: `derived secret "key" requires seed`,
			},
			{
				name:    "derived references an absent seed",
				static:  []StaticSecretMetadata{{Name: "key", Type: secretTypeDerived, Seed: "absent", EnvVar: "KEY"}},
				wantErr: `derived secret "key": seed "absent" must name a configured seed`,
			},
			{
				name:    "derived references itself",
				static:  []StaticSecretMetadata{{Name: "key", Type: secretTypeDerived, Seed: "key", EnvVar: "KEY"}},
				wantErr: `derived secret "key": seed "key" must name a configured seed`,
			},
			{
				name: "derived references a passthrough",
				static: []StaticSecretMetadata{
					{Name: "key", EnvVar: "KEY"},
					{Name: "app", Type: secretTypeDerived, Seed: "key", EnvVar: "APP"},
				},
				wantErr: `derived secret "app": seed "key" must name a configured seed`,
			},
			{
				name: "duplicate name",
				static: []StaticSecretMetadata{
					{Name: "key", Type: secretTypeSeed},
					{Name: "key", EnvVar: "KEY"},
				},
				wantErr: `duplicate static secret "key"`,
			},
			{
				name: "duplicate exported env var",
				static: []StaticSecretMetadata{
					{Name: "key", EnvVar: "KEY"},
					{Name: "app", EnvVar: "KEY"},
				},
				wantErr: `secret "app": env_var "KEY" is already used`,
			},
			{
				name:    "reserved env var",
				static:  []StaticSecretMetadata{{Name: "key", EnvVar: "PORT"}},
				wantErr: `secret "key": invalid or reserved env_var "PORT"`,
			},
			{
				name:    "malformed env var",
				static:  []StaticSecretMetadata{{Name: "key", EnvVar: "bad=name"}},
				wantErr: `secret "key": invalid or reserved env_var "bad=name"`,
			},
			{
				name: "derived requires an env var",
				static: []StaticSecretMetadata{
					{Name: "key", Type: secretTypeDerived, Seed: "seed"},
					{Name: "seed", Type: secretTypeSeed},
				},
				wantErr: `secret "key": invalid or reserved env_var ""`,
			},
			{
				name:    "name outside SSM path segment",
				static:  []StaticSecretMetadata{{Name: "../key", Type: secretTypeSeed}},
				wantErr: `static secret name "../key" must be a single SSM path segment`,
			},
			{
				name:    "storage DEK name collision",
				static:  []StaticSecretMetadata{{Name: "StorageDEK", Type: secretTypeSeed}},
				wantErr: `static secret "StorageDEK" collides with storage DEK`,
			},
			{
				name: "derived and inherited env vars collide",
				static: []StaticSecretMetadata{
					{Name: "same", Type: secretTypeSeed, EnvVar: "INHERITED"},
					{Name: "derived", Type: secretTypeDerived, Seed: "same", EnvVar: "INHERITED"},
				},
				inherited: inherited,
				wantErr:   `inherited secret "same": env_var "INHERITED" is already used`,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				err := (SecretsMetadata{Static: tc.static, Inherited: tc.inherited}).Validate(nil)
				require.ErrorContains(t, err, tc.wantErr)
			})
		}
	})
}

func TestSeedGenesisPersistsOnlyKMSValues(t *testing.T) {
	meta := []StaticSecretMetadata{
		{Name: "seed", Type: secretTypeSeed},
		{Name: "old", Type: secretTypePassthrough, EnvVar: "OLD"},
		{Name: "derived", Type: secretTypeDerived, Seed: "seed", EnvVar: "APP"},
	}
	fake, ssm := stateOriginTestSSM(nil)
	kms := &stateOriginTestKMS{keyID: "genesis"}
	snapshot, err := (&genesisBoot{}).buildSnapshot(t.Context(), &bootState{
		cfg: testCfg, secretsMetadata: SecretsMetadata{Static: meta},
		snapshot: bootSnapshot{ownerPCR0: stateOriginTestPCR0Hex()},
	}, kms, ssm)
	require.NoError(t, err)
	require.EqualValues(t, 3, kms.generateCall, "one DEK and two persisted secrets")
	require.Len(t, snapshot.staticSecrets, 2)
	require.Len(t, fake.params, 4, "DEK, TLS and two managed ciphertexts")
	require.NotContains(t, fake.params, testCfg.secretCiphertextParam("derived", "genesis"))
}

func TestSeedAdoptsLegacySignedSnapshot(t *testing.T) {
	const keyID = "legacy-key"
	seedCiphertext := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	shortCiphertext := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 31))
	derived := StaticSecretMetadata{
		Name:   "signing-key",
		Type:   secretTypeDerived,
		Seed:   "alpha",
		EnvVar: "APP_KEY",
	}
	seed := StaticSecretMetadata{Name: "alpha", Type: secretTypeSeed, EnvVar: "IGNORED_SEED"}
	legacy := StaticSecretMetadata{Name: "beta", EnvVar: "BETA"}
	// Independently calculated with Python hashlib/hmac and CBOR text-string info.
	const derivedKey = "30969ba2efdc4254de6eae1fd8880d7c616726b2b6e89496fe89f3add0ef9730"

	setup := func(
		t *testing.T,
		signedSeed string,
		storedSeeds map[string]string,
		metadata []StaticSecretMetadata,
	) (*Boot, bootState, *stateOriginTestKMS) {
		t.Helper()
		params := stateOriginParams(keyID)
		seedPath := testCfg.secretCiphertextParam("alpha", keyID)
		params[seedPath] = signedSeed
		_, signedSSM := stateOriginTestSSM(params)
		root := mustStateRoot(t, t.Context(), signedSSM, keyID)
		att := signedOriginReceipt(t,
			map[uint][]byte{0: mustDecodeHex(t, stateOriginTestPCR0Hex())}, root,
			bootSnapshot{ownerPCR0: stateOriginTestPCR0Hex(), kmsKeyID: keyID})

		// The signed snapshot uses the legacy declaration; boot reads this row's state.
		delete(params, seedPath)
		for name, ciphertext := range storedSeeds {
			params[testCfg.secretCiphertextParam(name, keyID)] = ciphertext
		}
		fake, ssm := stateOriginTestSSM(params)
		before := maps.Clone(fake.params)
		var writes []string
		fake.beforePut = func(name string) { writes = append(writes, name) }
		kms := &stateOriginTestKMS{keyID: keyID}
		boot := &Boot{cfg: testCfg, ssm: ssm, nsm: NewNSM(WithAttestationRoots(att.roots))}
		state := bootState{
			cfg: testCfg, secretsMetadata: SecretsMetadata{Static: metadata},
			bootReceipt: att.docB64, snapshot: bootSnapshot{
				ownerPCR0:                 stateOriginTestPCR0Hex(),
				migrationIntentBucketName: stateOriginTestMigrationIntentBucket(),
			},
		}
		t.Cleanup(func() {
			require.Zero(t, kms.generateCall)
			require.Empty(t, writes)
			require.Equal(t, before, fake.params, "resume never writes derived ciphertexts")
		})
		return boot, state, kms
	}

	t.Run("valid", func(t *testing.T) {
		for _, tc := range []struct {
			name             string
			signedSeed       string
			storedSeeds      map[string]string
			metadata         []StaticSecretMetadata
			wantDecryptCalls int
			wantSecrets      []StaticSecret
		}{
			{
				name:             "adopt legacy ciphertext as seed",
				signedSeed:       seedCiphertext,
				storedSeeds:      map[string]string{"alpha": seedCiphertext},
				metadata:         []StaticSecretMetadata{derived, seed, legacy},
				wantDecryptCalls: 4,
				wantSecrets: []StaticSecret{
					{StaticSecretMetadata: derived, Plaintext: derivedKey},
					{StaticSecretMetadata: seed, Plaintext: strings.Repeat("42", 32)},
					{StaticSecretMetadata: legacy, Plaintext: "01112233"},
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				boot, state, kms := setup(t, tc.signedSeed, tc.storedSeeds, tc.metadata)
				require.NoError(t, boot.loadSnapshotArtifacts(t.Context(), &state, keyID))
				result, err := boot.establish(
					t.Context(),
					&plannedBoot{state: state, mode: &resumeBoot{}},
					kms,
				)
				require.NoError(t, err)
				require.Equal(t, tc.wantSecrets, result.secrets.Static)
				require.Len(t, kms.decryptCalls, tc.wantDecryptCalls)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, tc := range []struct {
			name             string
			signedSeed       string
			storedSeeds      map[string]string
			metadata         []StaticSecretMetadata
			wantLoadErr      string
			wantEstablishErr string
			wantDecryptCalls int
		}{
			{
				name:       "tampered ciphertext",
				signedSeed: seedCiphertext,
				storedSeeds: map[string]string{
					"alpha": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				},
				metadata:         []StaticSecretMetadata{derived, seed, legacy},
				wantEstablishErr: "invalid state-origin receipt: attested user data does not match expected user data",
				wantDecryptCalls: 0,
			},
			{
				name:             "missing seed ciphertext",
				signedSeed:       seedCiphertext,
				storedSeeds:      map[string]string{},
				metadata:         []StaticSecretMetadata{derived, seed, legacy},
				wantLoadErr:      "required static secret SSM param missing",
				wantDecryptCalls: 0,
			},
			{
				name:             "invalid base64 ciphertext",
				signedSeed:       seedCiphertext,
				storedSeeds:      map[string]string{"alpha": "!invalid"},
				metadata:         []StaticSecretMetadata{derived, seed, legacy},
				wantEstablishErr: "illegal base64 data",
				wantDecryptCalls: 0,
			},
			{
				name:             "omit authenticated seed",
				signedSeed:       seedCiphertext,
				storedSeeds:      map[string]string{"alpha": seedCiphertext},
				metadata:         []StaticSecretMetadata{legacy},
				wantEstablishErr: "invalid state-origin receipt: attested user data does not match expected user data",
				wantDecryptCalls: 0,
			},
			{
				name:             "new seed has no ciphertext",
				signedSeed:       seedCiphertext,
				storedSeeds:      map[string]string{"alpha": seedCiphertext},
				metadata:         []StaticSecretMetadata{derived, seed, legacy, {Name: "new", Type: secretTypeSeed}},
				wantLoadErr:      "required static secret SSM param missing",
				wantDecryptCalls: 0,
			},
			{
				name:             "signed seed decrypts to 31 bytes",
				signedSeed:       shortCiphertext,
				storedSeeds:      map[string]string{"alpha": shortCiphertext},
				metadata:         []StaticSecretMetadata{derived, seed, legacy},
				wantEstablishErr: `seed "alpha" must be 32 bytes, got 31`,
				wantDecryptCalls: 3,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				boot, state, kms := setup(t, tc.signedSeed, tc.storedSeeds, tc.metadata)
				err := boot.loadSnapshotArtifacts(t.Context(), &state, keyID)
				var result bootResult
				if tc.wantLoadErr != "" {
					require.ErrorContains(t, err, tc.wantLoadErr)
				} else {
					require.NoError(t, err)
					result, err = boot.establish(
						t.Context(),
						&plannedBoot{state: state, mode: &resumeBoot{}},
						kms,
					)
					require.ErrorContains(t, err, tc.wantEstablishErr)
				}
				require.Empty(t, result)
				require.Nil(t, result.secrets.Static)
				require.Len(t, kms.decryptCalls, tc.wantDecryptCalls)
			})
		}
	})
}

func TestDerivedExportChangesPreserveSignedSnapshot(t *testing.T) {
	const keyID = "legacy-key"
	seed := StaticSecretMetadata{Name: "alpha", Type: secretTypeSeed, EnvVar: "IGNORED_SEED"}
	legacy := StaticSecretMetadata{Name: "beta", EnvVar: "BETA"}
	original := StaticSecretMetadata{
		Name:   "signing-key",
		Type:   secretTypeDerived,
		Seed:   "alpha",
		EnvVar: "APP_KEY",
	}
	next := StaticSecretMetadata{
		Name:   "signing-key-v2",
		Type:   secretTypeDerived,
		Seed:   "alpha",
		EnvVar: "NEXT",
	}
	remapped := StaticSecretMetadata{
		Name:   "signing-key",
		Type:   secretTypeDerived,
		Seed:   "alpha",
		EnvVar: "REMAPPED",
	}
	// Independently calculated with Python hashlib/hmac and CBOR text-string info.
	const originalKey = "30969ba2efdc4254de6eae1fd8880d7c616726b2b6e89496fe89f3add0ef9730"
	const nextKey = "650c5cbf7700d4f550d29cb862a3142b1d307a294e6896074e5f08ffd05805ef"

	fake, ssm := stateOriginTestSSM(stateOriginParams(keyID))
	fake.params[testCfg.secretCiphertextParam("alpha", keyID)] = base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x42}, 32),
	)
	root := mustStateRoot(t, t.Context(), ssm, keyID)
	att := signedOriginReceipt(t,
		map[uint][]byte{0: mustDecodeHex(t, stateOriginTestPCR0Hex())}, root,
		bootSnapshot{ownerPCR0: stateOriginTestPCR0Hex(), kmsKeyID: keyID})
	before := maps.Clone(fake.params)

	// Apply each measured configuration to the same authenticated artifacts.
	for _, tc := range []struct {
		name         string
		metadata     []StaticSecretMetadata
		wantExported []StaticSecret
		wantEnv      []string
	}{
		{
			name:     "original export",
			metadata: []StaticSecretMetadata{original, seed, legacy},
			wantExported: []StaticSecret{
				{StaticSecretMetadata: original, Plaintext: originalKey},
				{StaticSecretMetadata: legacy, Plaintext: "01112233"},
			},
			wantEnv: []string{"APP_KEY=" + originalKey, "BETA=01112233"},
		},
		{
			name:         "remove derived export",
			metadata:     []StaticSecretMetadata{seed, legacy},
			wantExported: []StaticSecret{{StaticSecretMetadata: legacy, Plaintext: "01112233"}},
			wantEnv:      []string{"BETA=01112233"},
		},
		{
			name:     "add versioned export",
			metadata: []StaticSecretMetadata{original, seed, legacy, next},
			wantExported: []StaticSecret{
				{StaticSecretMetadata: original, Plaintext: originalKey},
				{StaticSecretMetadata: legacy, Plaintext: "01112233"},
				{StaticSecretMetadata: next, Plaintext: nextKey},
			},
			wantEnv: []string{"APP_KEY=" + originalKey, "BETA=01112233", "NEXT=" + nextKey},
		},
		{
			name:     "restore original export",
			metadata: []StaticSecretMetadata{original, seed, legacy},
			wantExported: []StaticSecret{
				{StaticSecretMetadata: original, Plaintext: originalKey},
				{StaticSecretMetadata: legacy, Plaintext: "01112233"},
			},
			wantEnv: []string{"APP_KEY=" + originalKey, "BETA=01112233"},
		},
		{
			name:     "remap env var",
			metadata: []StaticSecretMetadata{remapped, seed, legacy},
			wantExported: []StaticSecret{
				{StaticSecretMetadata: remapped, Plaintext: originalKey},
				{StaticSecretMetadata: legacy, Plaintext: "01112233"},
			},
			wantEnv: []string{"REMAPPED=" + originalKey, "BETA=01112233"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := bootState{
				cfg:             testCfg,
				secretsMetadata: SecretsMetadata{Static: tc.metadata},
				bootReceipt:     att.docB64,
				snapshot: bootSnapshot{
					ownerPCR0:                 stateOriginTestPCR0Hex(),
					migrationIntentBucketName: stateOriginTestMigrationIntentBucket(),
				},
			}
			boot := &Boot{cfg: testCfg, ssm: ssm, nsm: NewNSM(WithAttestationRoots(att.roots))}
			require.NoError(t, boot.loadSnapshotArtifacts(t.Context(), &state, keyID))
			gotRoot, err := stateRoot(testCfg, state.snapshot)
			require.NoError(t, err)
			require.Equal(t, root, gotRoot)
			kms := &stateOriginTestKMS{keyID: keyID}
			result, err := boot.establish(
				t.Context(),
				&plannedBoot{state: state, mode: &resumeBoot{}},
				kms,
			)
			require.NoError(t, err)
			require.Equal(t, []StaticSecret{
				{StaticSecretMetadata: seed, Plaintext: strings.Repeat("42", 32)},
				{StaticSecretMetadata: legacy, Plaintext: "01112233"},
			}, result.secrets.persisted())
			require.Equal(t, tc.wantExported, result.secrets.exported())
			env := (&exec.Cmd{Env: appEnv(Config{}, "token", result.secrets)}).Environ()
			require.Subset(t, env, tc.wantEnv)
			require.NotContains(t, strings.Join(env, "\n"), "IGNORED_SEED=")
			require.Zero(t, kms.generateCall)
			require.Equal(t, before, fake.params)
		})
	}
}

func TestManagedSecretPCRs(t *testing.T) {
	// Fixed SHA-384 PCR vectors, independently calculated from compressed public keys.
	vectors := []struct {
		secret  StaticSecret
		pcr     uint
		wantPCR string
	}{
		{
			secret: StaticSecret{
				StaticSecretMetadata: StaticSecretMetadata{Name: "legacy", EnvVar: "LEGACY"},
				Plaintext:            strings.Repeat("01", 32),
			},
			pcr:     16,
			wantPCR: "16f398f1694cc5a35790e713cea58d3b624ab7884d3e250ecd872c0ea22136689a5b3d7ff86beef4b746eddcebddf341",
		},
		{
			secret: StaticSecret{
				StaticSecretMetadata: StaticSecretMetadata{Name: "seed", Type: secretTypeSeed},
				Plaintext:            strings.Repeat("02", 32),
			},
			pcr:     17,
			wantPCR: "2f02b99bf4e11ea2a0b5ebab95996b2f87fb094f437a61781169776039eab969fcbdc349892533da1266fc624fcee60e",
		},
		{
			secret: StaticSecret{
				StaticSecretMetadata: StaticSecretMetadata{
					Name: "derived", Type: secretTypeDerived, Seed: "seed", EnvVar: "DERIVED",
				},
				Plaintext: strings.Repeat("03", 32),
			},
			pcr:     18,
			wantPCR: "0ca31a575bcdbb66987bb9775a1f01bfb7a1c779e6f9f7a9b35acfeb2c9159bb92eb779090839b2f64be68992887f6d6",
		},
		{
			secret: StaticSecret{
				StaticSecretMetadata: StaticSecretMetadata{
					Name:   "explicit",
					Type:   secretTypePassthrough,
					EnvVar: "EXPLICIT",
				},
				Plaintext: strings.Repeat("00", 31) + "01",
			},
			pcr:     19,
			wantPCR: "0ab18de2920f558b74715ca379bd6c80dd07517d01f8c9a60dd5befea8ee93ddd37c45156939b7f16a42f3aa502bd47a",
		},
	}
	var secrets []StaticSecret
	var metadata []StaticSecretMetadata
	for _, vector := range vectors {
		secrets = append(secrets, vector.secret)
		metadata = append(metadata, vector.secret.StaticSecretMetadata)
	}
	require.NoError(t, (SecretsMetadata{Static: metadata}).Validate(nil))
	session := newStatefulNSMSession(t, nil)
	require.NoError(
		t,
		ExtendPCRRegistersWithStaticSecrets(&nsmW{nsm: &fakeNSM{session: session}}, secrets),
	)
	for _, vector := range vectors {
		t.Run(vector.secret.Name, func(t *testing.T) {
			require.Equal(t, vector.wantPCR, hex.EncodeToString(session.currentPCR(vector.pcr)))
			require.True(t, session.locks[vector.pcr])
		})
	}
	require.Len(t, session.requests, 8)
	require.False(t, session.locks[migrationPCRIndex])
}

func TestManagedSecretCapacity(t *testing.T) {
	const onePCR = "0ab18de2920f558b74715ca379bd6c80dd07517d01f8c9a60dd5befea8ee93ddd37c45156939b7f16a42f3aa502bd47a"
	metadata := []StaticSecretMetadata{
		{Name: "legacy", EnvVar: "LEGACY"},
		{Name: "explicit", Type: secretTypePassthrough, EnvVar: "EXPLICIT"},
		{Name: "seed", Type: secretTypeSeed},
		{Name: "key-1", Type: secretTypeDerived, Seed: "seed", EnvVar: "KEY_1"},
		{Name: "key-2", Type: secretTypeDerived, Seed: "seed", EnvVar: "KEY_2"},
		{Name: "key-3", Type: secretTypeDerived, Seed: "seed", EnvVar: "KEY_3"},
		{Name: "key-4", Type: secretTypeDerived, Seed: "seed", EnvVar: "KEY_4"},
		{Name: "key-5", Type: secretTypeDerived, Seed: "seed", EnvVar: "KEY_5"},
		{Name: "key-6", Type: secretTypeDerived, Seed: "seed", EnvVar: "KEY_6"},
		{Name: "key-7", Type: secretTypeDerived, Seed: "seed", EnvVar: "KEY_7"},
		{Name: "key-8", Type: secretTypeDerived, Seed: "seed", EnvVar: "KEY_8"},
		{Name: "key-9", Type: secretTypeDerived, Seed: "seed", EnvVar: "KEY_9"},
		{Name: "key-10", Type: secretTypeDerived, Seed: "seed", EnvVar: "KEY_10"},
		{Name: "key-11", Type: secretTypeDerived, Seed: "seed", EnvVar: "KEY_11"},
		{Name: "key-12", Type: secretTypeDerived, Seed: "seed", EnvVar: "KEY_12"},
		{Name: "key-13", Type: secretTypeDerived, Seed: "seed", EnvVar: "KEY_13"},
	}
	t.Run("valid", func(t *testing.T) {
		for _, tc := range []struct {
			name         string
			metadata     []StaticSecretMetadata
			wantRequests int
			wantPCRs     map[uint]string
		}{
			{
				name:         "15 secrets fill PCR16 through PCR30",
				metadata:     metadata[:15],
				wantRequests: 30,
				wantPCRs: map[uint]string{
					16: onePCR, 17: onePCR, 18: onePCR, 19: onePCR, 20: onePCR,
					21: onePCR, 22: onePCR, 23: onePCR, 24: onePCR, 25: onePCR,
					26: onePCR, 27: onePCR, 28: onePCR, 29: onePCR, 30: onePCR,
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var secrets []StaticSecret
				for _, meta := range tc.metadata {
					secrets = append(secrets, StaticSecret{
						StaticSecretMetadata: meta,
						Plaintext:            strings.Repeat("00", 31) + "01",
					})
				}
				err := (SecretsMetadata{Static: tc.metadata}).Validate(nil)
				require.NoError(t, err)
				session := newStatefulNSMSession(t, nil)
				err = ExtendPCRRegistersWithStaticSecrets(
					&nsmW{nsm: &fakeNSM{session: session}},
					secrets,
				)
				require.NoError(t, err)
				require.Len(t, session.requests, tc.wantRequests)
				gotPCRs := make(map[uint]string)
				for index, value := range session.pcrs {
					gotPCRs[index] = hex.EncodeToString(value)
				}
				require.Equal(t, tc.wantPCRs, gotPCRs)
				require.Len(t, session.locks, len(tc.wantPCRs))
				for index := range tc.wantPCRs {
					require.True(t, session.locks[index], "PCR%d must be locked", index)
				}
				require.False(t, session.locks[31])
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, tc := range []struct {
			name            string
			metadata        []StaticSecretMetadata
			wantMetadataErr string
			wantPCRErr      string
			wantRequests    int
			wantPCRs        map[uint]string
		}{
			{
				name:            "16 secrets rejected before any NSM writes",
				metadata:        metadata,
				wantMetadataErr: "at most 15 managed secrets fit in PCR16–PCR30",
				wantPCRErr:      "at most 15 managed secrets fit before migration PCR31",
				wantRequests:    0,
				wantPCRs:        map[uint]string{},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var secrets []StaticSecret
				for _, meta := range tc.metadata {
					secrets = append(secrets, StaticSecret{
						StaticSecretMetadata: meta,
						Plaintext:            strings.Repeat("00", 31) + "01",
					})
				}
				err := (SecretsMetadata{Static: tc.metadata}).Validate(nil)
				require.ErrorContains(t, err, tc.wantMetadataErr)
				session := newStatefulNSMSession(t, nil)
				err = ExtendPCRRegistersWithStaticSecrets(
					&nsmW{nsm: &fakeNSM{session: session}},
					secrets,
				)
				require.EqualError(t, err, tc.wantPCRErr)
				require.Len(t, session.requests, tc.wantRequests)
				gotPCRs := make(map[uint]string)
				for index, value := range session.pcrs {
					gotPCRs[index] = hex.EncodeToString(value)
				}
				require.Equal(t, tc.wantPCRs, gotPCRs)
				require.Len(t, session.locks, len(tc.wantPCRs))
				for index := range tc.wantPCRs {
					require.True(t, session.locks[index], "PCR%d must be locked", index)
				}
				require.False(t, session.locks[31])
			})
		}
	})
}

func TestManagedSecretPCRScalarBounds(t *testing.T) {
	const (
		order         = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
		orderMinusOne = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
		orderPlusOne  = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"
		// Fixed SHA-384 PCR vectors for the historical modulo-N public-key commitment.
		zeroPCR          = "9c39f04da2a9468455bff2cd7b588621b19f04e4072d7c5d19442ed449bb07b623632e3f56c3e98a432cce3805bcf887"
		onePCR           = "0ab18de2920f558b74715ca379bd6c80dd07517d01f8c9a60dd5befea8ee93ddd37c45156939b7f16a42f3aa502bd47a"
		orderMinusOnePCR = "e09672481254566214a3ae2e791ccac02b5133e46bc7eba3d51d5eb4996d08e4393cef9e6c673b04566d68eb179b1069"
		maximumPCR       = "666f0ee2a49292372db12876c51abbb417434126b7a183e52ca0ac1f71eecff789efb742dca687d41b7647f8bdbd7443"
	)
	zero := strings.Repeat("00", 32)
	one := strings.Repeat("00", 31) + "01"
	maximum := strings.Repeat("ff", 32)
	t.Run("valid", func(t *testing.T) {
		for _, tc := range []struct {
			name, typ, plaintext string
			wantPCR              string
			wantLocked           bool
			wantRequests         int
		}{
			{"legacy zero", "", zero, zeroPCR, true, 4},
			{"passthrough zero", secretTypePassthrough, zero, zeroPCR, true, 4},
			{"seed zero", secretTypeSeed, zero, zeroPCR, true, 4},
			{"legacy N", "", order, zeroPCR, true, 4},
			{"passthrough N", secretTypePassthrough, order, zeroPCR, true, 4},
			{"seed N", secretTypeSeed, order, zeroPCR, true, 4},
			{"legacy N+1", "", orderPlusOne, onePCR, true, 4},
			{"passthrough N+1", secretTypePassthrough, orderPlusOne, onePCR, true, 4},
			{"seed N+1", secretTypeSeed, orderPlusOne, onePCR, true, 4},
			{"legacy maximum", "", maximum, maximumPCR, true, 4},
			{"passthrough maximum", secretTypePassthrough, maximum, maximumPCR, true, 4},
			{"seed maximum", secretTypeSeed, maximum, maximumPCR, true, 4},
			{"derived one", secretTypeDerived, one, onePCR, true, 4},
			{"derived N-1", secretTypeDerived, orderMinusOne, orderMinusOnePCR, true, 4},
		} {
			t.Run(tc.name, func(t *testing.T) {
				secrets := []StaticSecret{
					{
						StaticSecretMetadata: StaticSecretMetadata{
							Name: "first",
							Type: secretTypeDerived,
						},
						Plaintext: one,
					},
					{
						StaticSecretMetadata: StaticSecretMetadata{Name: "boundary", Type: tc.typ},
						Plaintext:            tc.plaintext,
					},
				}
				session := newStatefulNSMSession(t, nil)
				err := ExtendPCRRegistersWithStaticSecrets(
					&nsmW{nsm: &fakeNSM{session: session}},
					secrets,
				)
				require.NoError(t, err)
				require.Equal(t, onePCR, hex.EncodeToString(session.currentPCR(16)))
				require.True(t, session.locks[16])
				require.Equal(t, tc.wantPCR, hex.EncodeToString(session.currentPCR(17)))
				require.Equal(t, tc.wantLocked, session.locks[17])
				require.Len(t, session.requests, tc.wantRequests)
			})
		}
	})
}

func TestManagedSecretSelectorsAndEnvironment(t *testing.T) {
	legacy := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{Name: "legacy", EnvVar: "LEGACY_KEY"},
		Plaintext:            strings.Repeat("11", 32),
	}
	explicit := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{
			Name: "explicit", EnvVar: "EXPLICIT_KEY", Type: secretTypePassthrough,
		},
		Plaintext: strings.Repeat("22", 32),
	}
	seed := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{
			Name:   "seed",
			Type:   secretTypeSeed,
			EnvVar: "HIDDEN_SEED",
		},
		Plaintext: strings.Repeat("33", 32),
	}
	derived := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{
			Name: "derived", EnvVar: "DERIVED_KEY", Type: secretTypeDerived, Seed: "seed",
		},
		Plaintext: strings.Repeat("44", 32),
	}
	for _, tc := range []struct {
		name                     string
		all, persisted, exported []StaticSecret
		wantEnv                  []string
	}{
		{name: "empty"},
		{
			name:      "interleaved",
			all:       []StaticSecret{derived, explicit, seed, legacy},
			persisted: []StaticSecret{explicit, seed, legacy},
			exported:  []StaticSecret{derived, explicit, legacy},
			wantEnv: []string{
				"DERIVED_KEY=" + derived.Plaintext,
				"EXPLICIT_KEY=" + explicit.Plaintext,
				"LEGACY_KEY=" + legacy.Plaintext,
			},
		},
		{
			name:      "reordered",
			all:       []StaticSecret{legacy, seed, explicit, derived},
			persisted: []StaticSecret{legacy, seed, explicit},
			exported:  []StaticSecret{legacy, explicit, derived},
			wantEnv: []string{
				"LEGACY_KEY=" + legacy.Plaintext,
				"EXPLICIT_KEY=" + explicit.Plaintext,
				"DERIVED_KEY=" + derived.Plaintext,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secrets := Secrets{Static: tc.all}
			require.Equal(t, tc.persisted, secrets.persisted())
			require.Equal(t, tc.exported, secrets.exported())
			env := (&exec.Cmd{Env: appEnv(Config{}, "token", secrets)}).Environ()
			require.Subset(t, env, tc.wantEnv)
			require.NotContains(t, strings.Join(env, "\n"), "HIDDEN_SEED=")
		})
	}
}

func TestUnusedSeedRejectsMalformedSignedSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name      string
		plaintext []byte
		wantErr   string
	}{
		{"short unused seed", bytes.Repeat([]byte{0x42}, 31), `seed "alpha" must be 32 bytes, got 31`},
		{"long unused seed", bytes.Repeat([]byte{0x42}, 33), `seed "alpha" must be 32 bytes, got 33`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const keyID = "malformed-seed"
			fake, ssm := stateOriginTestSSM(stateOriginParams(keyID))
			fake.params[testCfg.secretCiphertextParam("alpha", keyID)] = base64.StdEncoding.EncodeToString(
				tc.plaintext,
			)
			root := mustStateRoot(t, t.Context(), ssm, keyID)
			att := signedOriginReceipt(
				t,
				map[uint][]byte{0: mustDecodeHex(t, stateOriginTestPCR0Hex())},
				root,
				bootSnapshot{ownerPCR0: stateOriginTestPCR0Hex(), kmsKeyID: keyID},
			)
			state := bootState{
				cfg: testCfg,
				secretsMetadata: SecretsMetadata{Static: []StaticSecretMetadata{
					{Name: "alpha", Type: secretTypeSeed},
					{Name: "beta", EnvVar: "BETA"},
				}},
				bootReceipt: att.docB64,
				snapshot: bootSnapshot{
					ownerPCR0:                 stateOriginTestPCR0Hex(),
					migrationIntentBucketName: stateOriginTestMigrationIntentBucket(),
				},
			}
			before := maps.Clone(fake.params)
			var writes []string
			fake.beforePut = func(name string) { writes = append(writes, name) }
			boot := &Boot{cfg: testCfg, ssm: ssm, nsm: NewNSM(WithAttestationRoots(att.roots))}
			require.NoError(t, boot.loadSnapshotArtifacts(t.Context(), &state, keyID))
			kms := &stateOriginTestKMS{keyID: keyID}
			result, err := boot.establish(
				t.Context(),
				&plannedBoot{state: state, mode: &resumeBoot{}},
				kms,
			)
			require.EqualError(t, err, tc.wantErr)
			require.Empty(t, result)
			require.Zero(t, kms.generateCall)
			require.Empty(t, writes, "no replacement state or receipt is written")
			require.Equal(t, before, fake.params)
		})
	}
}

func TestEstablishMultipleDerivedSecrets(t *testing.T) {
	const keyID = "multiple-seeds"
	fake, ssm := stateOriginTestSSM(stateOriginParams(keyID))
	fake.params[testCfg.secretCiphertextParam("alpha", keyID)] = base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x42}, 32),
	)
	fake.params[testCfg.secretCiphertextParam("beta", keyID)] = base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x24}, 32),
	)
	root := mustStateRoot(t, t.Context(), ssm, keyID)
	att := signedOriginReceipt(t, map[uint][]byte{0: mustDecodeHex(t, stateOriginTestPCR0Hex())},
		root, bootSnapshot{ownerPCR0: stateOriginTestPCR0Hex(), kmsKeyID: keyID})

	// Independently calculated with Python hashlib/hmac and CBOR text-string info.
	betaKey := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{
			Name:   "beta-key",
			Type:   secretTypeDerived,
			Seed:   "beta",
			EnvVar: "BETA_KEY",
		},
		Plaintext: "518df9398d9aaf7262f4987bbd71b8df3d1548f6a40a5ec42a67c485d9f74132",
	}
	alphaSeed := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{Name: "alpha", Type: secretTypeSeed},
		Plaintext:            strings.Repeat("42", 32),
	}
	alphaKey := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{
			Name:   "alpha-key",
			Type:   secretTypeDerived,
			Seed:   "alpha",
			EnvVar: "ALPHA_KEY",
		},
		Plaintext: "d166197c6c23298bac0ccaf1539f4dc3741451d3f802d338f0e5a07104f085d9",
	}
	betaSeed := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{Name: "beta", Type: secretTypeSeed},
		Plaintext:            strings.Repeat("24", 32),
	}
	alphaNext := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{
			Name:   "alpha-next",
			Type:   secretTypeDerived,
			Seed:   "alpha",
			EnvVar: "ALPHA_NEXT",
		},
		Plaintext: "04f921ec27c39b911eac12daf9bc33e7277d6bb073f69f802a176a27cf64d834",
	}
	want := []StaticSecret{betaKey, alphaSeed, alphaKey, betaSeed, alphaNext}
	var meta []StaticSecretMetadata
	for _, vector := range want {
		meta = append(meta, vector.StaticSecretMetadata)
	}
	state := bootState{
		cfg: testCfg, secretsMetadata: SecretsMetadata{Static: meta}, bootReceipt: att.docB64,
		snapshot: bootSnapshot{
			ownerPCR0:                 stateOriginTestPCR0Hex(),
			migrationIntentBucketName: stateOriginTestMigrationIntentBucket(),
		},
	}
	boot := &Boot{cfg: testCfg, ssm: ssm, nsm: NewNSM(WithAttestationRoots(att.roots))}
	require.NoError(t, boot.loadSnapshotArtifacts(t.Context(), &state, keyID))
	kms := &stateOriginTestKMS{keyID: keyID}
	result, err := boot.establish(t.Context(), &plannedBoot{state: state, mode: &resumeBoot{}}, kms)
	require.NoError(t, err)
	require.Equal(t, want, result.secrets.Static, "resolve every entry in configuration order")
	require.Equal(t, []StaticSecret{betaKey, alphaKey, alphaNext}, result.secrets.exported())
	env := (&exec.Cmd{Env: appEnv(Config{}, "token", result.secrets)}).Environ()
	require.Subset(t, env, []string{
		"BETA_KEY=" + betaKey.Plaintext,
		"ALPHA_KEY=" + alphaKey.Plaintext,
		"ALPHA_NEXT=" + alphaNext.Plaintext,
	})
	require.Zero(t, kms.generateCall)
}

func TestBootSeedGenesisAndResume(t *testing.T) {
	fx := newGenesisFixture(t, mustDecodeHex(t, stateOriginTestPCR0Hex()))
	const generated = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	derived := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{
			Name:   "app-key",
			Type:   secretTypeDerived,
			Seed:   "seed",
			EnvVar: "APP_KEY",
		},
		// Independently calculated HKDF vector for the fake KMS's generated seed.
		Plaintext: "eb5530abc1ba4a84ac3b44f7b9be658281692e29f139c51ba4a8246778a71906",
	}
	explicit := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{
			Name:   "explicit",
			Type:   secretTypePassthrough,
			EnvVar: "EXPLICIT_KEY",
		},
		Plaintext: generated,
	}
	seed := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{
			Name:   "seed",
			Type:   secretTypeSeed,
			EnvVar: "HIDDEN_SEED",
		},
		Plaintext: generated,
	}
	legacy := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{Name: "legacy", EnvVar: "LEGACY_KEY"},
		Plaintext:            generated,
	}
	cfg := testConfig()
	cfg.StaticSecretConfig = managedSecretConfig(t, []StaticSecretMetadata{
		derived.StaticSecretMetadata, explicit.StaticSecretMetadata,
		seed.StaticSecretMetadata, legacy.StaticSecretMetadata,
	})
	boot, err := NewBoot(cfg, fx.nsm, fx.kmsf, fx.sts, fx.ssm, fx.s3f)
	require.NoError(t, err)
	first, err := boot.Boot(t.Context())
	require.NoError(t, err)
	keyID := first.kms.KeyID()
	require.Equal(t, keyID, fx.ssmf.params[cfg.kmsKeyIDParam(fx.pcr0Hex)])
	require.Len(t, fx.kmsf.keys, 1)
	require.Len(t, fx.kmsf.blobs, 5, "DEK, TLS key, seed and both passthrough values")
	require.NotContains(t, fx.ssmf.params, cfg.secretCiphertextParam("app-key", keyID))
	require.Equal(t, []StaticSecret{derived, explicit, seed, legacy}, first.secrets.Static)
	for _, tc := range []struct {
		name          string
		wantPlaintext string
	}{
		{"seed", generated},
		{"explicit", generated},
		{"legacy", generated},
	} {
		t.Run(tc.name+" ciphertext", func(t *testing.T) {
			requireKMSCiphertextPlaintext(
				t,
				fx.kmsf,
				fx.ssmf.params[cfg.secretCiphertextParam(tc.name, keyID)],
				mustDecodeHex(t, tc.wantPlaintext),
			)
		})
	}
	planned, err := boot.plan(t.Context())
	require.NoError(t, err)
	require.IsType(t, &resumeBoot{}, planned.mode)
	root, err := stateRoot(cfg, planned.state.snapshot)
	require.NoError(t, err)
	receipt := fx.ssmf.params[cfg.stateOriginReceiptParam(keyID, fx.pcr0Hex)]
	require.NotEmpty(t, receipt)
	require.NoError(t, verifyOriginReceipt(fx.nsm, receipt, root, first.lineage))
	before := maps.Clone(fx.ssmf.params)
	blobs := maps.Clone(fx.kmsf.blobs)
	var writes []string
	fx.ssmf.beforePut = func(name string) { writes = append(writes, name) }
	resumed, err := boot.Boot(t.Context())
	require.NoError(t, err)
	require.Equal(t, first.secrets, resumed.secrets)
	require.Equal(t, first.dek, resumed.dek)
	require.Equal(t, first.tlsKey, resumed.tlsKey)
	require.Equal(t, keyID, resumed.kms.KeyID())
	require.Len(t, fx.kmsf.keys, 1)
	require.Equal(t, blobs, fx.kmsf.blobs, "resume generates no additional state")
	require.Empty(t, writes)
	require.Equal(t, before, fx.ssmf.params)
}

func TestInheritedReplacementUsesRenamedPathWithoutDerivedFallback(t *testing.T) {
	key, pin := inheritTestKey(t)
	meta := InheritSecretMetadata{
		Name: "new-name", EnvVar: "APP_KEY",
		Type: inheritSecretTypePublicKey, Value: []string{pin},
	}
	oldPath := testCfg.inheritSecretPrefix() + "old-name"
	newPath := testCfg.inheritSecretPrefix() + "new-name"
	t.Run("valid", func(t *testing.T) {
		for _, tc := range []struct {
			name         string
			params       map[string]string
			wantResolved []InheritedSecret
			wantEnv      string
		}{
			{
				name:   "old path is not an alias or a seed fallback",
				params: map[string]string{oldPath: key},
			},
			{
				name:         "new path matches the pinned key",
				params:       map[string]string{oldPath: key, newPath: key},
				wantResolved: []InheritedSecret{{InheritSecretMetadata: meta, Plaintext: key}},
				wantEnv:      "APP_KEY=" + key,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, ssm := stateOriginTestSSM(tc.params)
				resolved, err := resolveInheritedSecrets(
					t.Context(),
					testCfg,
					ssm,
					[]InheritSecretMetadata{meta},
					time.Now(),
				)
				require.NoError(t, err)
				require.Equal(t, tc.wantResolved, resolved)
				secrets := Secrets{Static: []StaticSecret{
					{
						StaticSecretMetadata: StaticSecretMetadata{
							Name:   "seed",
							Type:   secretTypeSeed,
							EnvVar: "APP_KEY",
						},
						Plaintext: key,
					},
				}, Inherited: resolved}
				env := (&exec.Cmd{Env: appEnv(Config{}, "token", secrets)}).Environ()
				if tc.wantEnv == "" {
					require.NotContains(t, strings.Join(env, "\n"), "APP_KEY=")
				} else {
					require.Contains(t, env, tc.wantEnv)
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			params  map[string]string
			wantErr string
		}{
			{
				name:    "new path mismatches the pinned key",
				params:  map[string]string{oldPath: key, newPath: strings.Repeat("01", 32)},
				wantErr: "does not match",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, ssm := stateOriginTestSSM(tc.params)
				resolved, err := resolveInheritedSecrets(
					t.Context(),
					testCfg,
					ssm,
					[]InheritSecretMetadata{meta},
					time.Now(),
				)
				require.ErrorContains(t, err, tc.wantErr)
				require.Nil(t, resolved)
			})
		}
	})
}

// Keep the config and signed migration fixtures on the same JSON parsing path
// as production without embedding hand-written field mappings in each test.
func managedSecretConfig(t *testing.T, entries []StaticSecretMetadata) string {
	t.Helper()
	b, err := json.Marshal(entries)
	require.NoError(t, err)
	return string(b)
}
