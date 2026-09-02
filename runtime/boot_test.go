package runtime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestStateOriginReceiptParamIsPCRScoped(t *testing.T) {
	setStateOriginTestEnv(t)

	pcr0 := strings.Repeat("AB", 48)
	require.Equal(
		t,
		"/prod/state-origin/StateOriginReceipt/key-1/"+strings.ToLower(pcr0),
		stateOriginReceiptParam("key-1", pcr0),
	)
}

func TestLoadUnverifiedState(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	keyID := "key-classify"
	currentPCR0 := bytes.Repeat([]byte{0xab}, 48)
	currentPCR0Hex := hex.EncodeToString(currentPCR0)
	prevPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0x99}, 48))
	withKey := func(params map[string]string) map[string]string {
		maps.Copy(params, stateOriginParams(keyID))
		return params
	}

	withReceipt := func(params map[string]string) map[string]string {
		params[stateOriginReceiptParam(keyID, currentPCR0Hex)] = "receipt"
		return params
	}
	withMigration := func(params map[string]string) map[string]string {
		params[migrationStateOriginReceiptParam(keyID)] = "transition"
		params[migrationPreviousPCR0Param(currentPCR0Hex)] = prevPCR0
		params[migrationPreviousPCR0AttestationParam(currentPCR0Hex)] = "attestation"
		return params
	}

	cases := []struct {
		name            string
		freshDeployment bool
		params          map[string]string
		previousPCR0    string
		want            bootMode
		wantErr         string
	}{
		{
			name:            "genesis clean",
			freshDeployment: true,
			params:          map[string]string{},
			want:            &genesisBoot{},
		},
		{
			name:            "genesis blocked by migration artifacts",
			freshDeployment: true,
			params:          withMigration(map[string]string{}),
			wantErr:         "genesis state has predecessor artifacts",
		},
		{
			name:            "genesis blocked by partial migration artifacts",
			freshDeployment: true,
			params: map[string]string{
				migrationPreviousPCR0Param(currentPCR0Hex): prevPCR0,
			},
			wantErr: "inconsistent migration predecessor artifacts",
		},
		{
			name:   "resume with receipt",
			params: withReceipt(withKey(map[string]string{})),
			want:   &resumeBoot{},
		},
		{
			name:    "without receipt fails",
			params:  withKey(map[string]string{}),
			wantErr: "no predecessor to migrate from",
		},
		{
			name:         "migration with transition receipt",
			params:       withMigration(withKey(map[string]string{})),
			previousPCR0: prevPCR0,
			want:         &migrationBoot{},
		},
		{
			name:         "foreign receipt selects migration",
			previousPCR0: prevPCR0,
			params: func() map[string]string {
				params := withMigration(withKey(map[string]string{}))
				params[stateOriginReceiptParam(keyID, strings.Repeat("cd", 48))] = "foreign"
				return params
			}(),
			want: &migrationBoot{},
		},
		{
			name:         "exact receipt takes precedence over transition",
			params:       withReceipt(withMigration(withKey(map[string]string{}))),
			previousPCR0: prevPCR0,
			want:         &resumeBoot{},
		},
		{
			name:         "migration artifacts without transition receipt fail",
			previousPCR0: prevPCR0,
			params: withKey(func() map[string]string {
				params := map[string]string{}
				params[migrationPreviousPCR0Param(currentPCR0Hex)] = prevPCR0
				params[migrationPreviousPCR0AttestationParam(currentPCR0Hex)] = "attestation"
				return params
			}()),
			wantErr: "no migration transition receipt",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.previousPCR0 != "" {
				t.Setenv("ENCLAVE_PREVIOUS_PCR0", tc.previousPCR0)
			}
			_, ssm := stateOriginTestSSM(tc.params)
			s3f := newFakeS3()
			if !tc.freshDeployment {
				seedGenesisRecord(t, s3f, currentPCR0Hex)
			}
			boot := &Boot{
				nsm: fakePredecessorNSM{
					NSM: &nsmW{nsm: &fakeNSM{
						verifyErr: errors.New("unexpected attestation verification"),
					}},
					doc: "attestation",
				},
				ssm: ssm, s3: s3f, sts: &fakeSTS{}, pcr0: currentPCR0,
			}
			planned, err := boot.plan(ctx)

			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.IsType(t, tc.want, planned.mode)

			switch planned.mode.(type) {
			case *resumeBoot:
				require.Equal(t, "receipt", planned.state.bootReceipt)
			case *migrationBoot:
				require.Equal(t, "transition", planned.state.migrationReceipt)
				require.Equal(t, prevPCR0, planned.state.predecessorPCR0)
				require.Equal(t, "attestation", planned.state.predecessorAttestation)
			}
		})
	}
}

func TestNewBootRejectsInvalidPCR0BeforeStateReads(t *testing.T) {
	setStateOriginTestEnv(t)

	fake, ssm := stateOriginTestSSM(nil)
	session := newStatefulNSMSession(t, map[uint][]byte{0: bytes.Repeat([]byte{0xaa}, 47)})

	_, err := NewBoot(&nsmW{nsm: &fakeNSM{session: session}}, nil, nil, ssm, nil)

	require.ErrorContains(t, err, "exactly 48 bytes")
	require.Empty(t, fake.calls)
}

func TestVerifyStateOriginReceipt(t *testing.T) {
	setStateOriginTestEnv(t)

	stateRoot := []byte("state-root-commitment")
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	pcr0Hex := hex.EncodeToString(pcr0)
	att := signedReceipt(t, map[uint][]byte{0: pcr0}, purposeStateOrigin, stateRoot)
	verifier := NewNSM(WithAttestationRoots(att.roots))

	require.NoError(t, verifyStateReceipt(
		verifier,
		att.docB64,
		purposeStateOrigin,
		stateRoot,
		map[uint]string{0: pcr0Hex},
	))

	cases := []struct {
		name     string
		receipt  string
		purpose  string
		root     []byte
		expected map[uint]string
	}{
		{
			name:     "wrong PCR0",
			receipt:  att.docB64,
			purpose:  purposeStateOrigin,
			root:     stateRoot,
			expected: map[uint]string{0: hex.EncodeToString(bytes.Repeat([]byte{0x22}, 48))},
		},
		{
			name:     "wrong purpose",
			receipt:  att.docB64,
			purpose:  purposeMigrationTransition,
			root:     stateRoot,
			expected: map[uint]string{0: pcr0Hex},
		},
		{
			name:     "wrong state root",
			receipt:  att.docB64,
			purpose:  purposeStateOrigin,
			root:     []byte("other-root"),
			expected: map[uint]string{0: pcr0Hex},
		},
		{
			name: "forged receipt",
			receipt: base64.StdEncoding.EncodeToString(
				buildForgedAttestation(t, map[uint][]byte{0: pcr0}),
			),
			purpose:  purposeStateOrigin,
			root:     stateRoot,
			expected: map[uint]string{0: pcr0Hex},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyStateReceipt(verifier, tc.receipt, tc.purpose, tc.root, tc.expected)
			require.Error(t, err)
		})
	}
}

func TestVerifyStateOriginReceiptMigrationPCR31(t *testing.T) {
	setStateOriginTestEnv(t)

	prevPCR0 := bytes.Repeat([]byte{0x99}, 48)
	ownPCR0 := bytes.Repeat([]byte{0xab}, 48)
	stateRoot := []byte("successor-state-root")
	pcr31 := pcrExtendFromZero(ownPCR0)
	att := signedReceipt(t, map[uint][]byte{
		0:                 prevPCR0,
		migrationPCRIndex: pcr31,
	}, purposeMigrationTransition, stateRoot)
	verifier := NewNSM(WithAttestationRoots(att.roots))

	err := verifyStateReceipt(
		verifier,
		att.docB64,
		purposeMigrationTransition,
		stateRoot,
		map[uint]string{
			0:                 hex.EncodeToString(prevPCR0),
			migrationPCRIndex: hex.EncodeToString(pcr31),
		},
	)
	require.NoError(t, err)

	err = verifyStateReceipt(
		verifier,
		att.docB64,
		purposeMigrationTransition,
		stateRoot,
		map[uint]string{
			0: hex.EncodeToString(prevPCR0),
			migrationPCRIndex: hex.EncodeToString(
				pcrExtendFromZero(bytes.Repeat([]byte{0x33}, 48)),
			),
		},
	)
	require.Error(t, err)
}

func TestValidateStaticSecretArtifacts(t *testing.T) {
	setStateOriginTestEnv(t)

	require.NoError(t, validateStaticSecretNames(stateOriginTestSecrets))
	require.Error(t, validateStaticSecretNames([]StaticSecretMetadata{
		{Name: "duplicate", EnvVar: "ONE"},
		{Name: "duplicate", EnvVar: "TWO"},
	}))
	require.Error(t, validateStaticSecretNames([]StaticSecretMetadata{
		{Name: "StorageDEK", EnvVar: "COLLISION"},
	}))
}

func TestEstablishLoadedStateUsesSinglePersistedSnapshot(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	keyID := "key-single-snapshot"
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	original := stateOriginParams(keyID)
	fake, ssm := stateOriginTestSSM(original)
	root := mustStateRoot(t, ctx, ssm, keyID)
	receipt := signedReceipt(t, map[uint][]byte{0: pcr0}, purposeStateOrigin, root)
	fake.params[stateOriginReceiptParam(keyID, hex.EncodeToString(pcr0))] = receipt.docB64
	session := newStatefulNSMSession(t, map[uint][]byte{0: pcr0})
	kms := &stateOriginTestKMS{keyID: keyID}
	s3f := newFakeS3()
	seedGenesisRecord(t, s3f, hex.EncodeToString(pcr0))
	boot := &Boot{ssm: ssm, s3: s3f, sts: &fakeSTS{}, pcr0: pcr0}
	planned, err := boot.plan(ctx)
	require.NoError(t, err)
	readCount := len(fake.calls)
	fake.params[storageDEKCiphertextParam(keyID)] = base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0xdd}, 32),
	)

	established, err := (&Boot{
		nsm: &nsmW{nsm: &fakeNSM{session: session, verifyRoots: receipt.roots}},
		ssm: ssm,
	}).establish(ctx, planned, kms)

	require.NoError(t, err)
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, established.dek.(*dek).key)
	require.Len(t, fake.calls, readCount, "establishment must not read SSM")
}

func TestLoadUnverifiedStateDoesNotInitializeMissingResumeState(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	keyID := "key-missing-state"
	params := stateOriginParams(keyID)
	delete(params, secretCiphertextParam("alpha", keyID))
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	params[stateOriginReceiptParam(keyID, hex.EncodeToString(pcr0))] = "receipt"
	fake, ssm := stateOriginTestSSM(params)
	s3f := newFakeS3()
	seedGenesisRecord(t, s3f, hex.EncodeToString(pcr0))

	_, err := (&Boot{ssm: ssm, s3: s3f, sts: &fakeSTS{}, pcr0: pcr0}).plan(ctx)

	require.Error(t, err)
	_, exists := fake.params[secretCiphertextParam("alpha", keyID)]
	require.False(t, exists)
}

func TestEstablishLoadedStateGenesisWritesReceipt(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	keyID := "key-genesis"
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fake, ssm := stateOriginTestSSM(nil)
	session := newStatefulNSMSession(t, map[uint][]byte{0: pcr0})
	nsm := &nsmW{nsm: &fakeNSM{session: session, verifyRoots: session.attestationSign.roots}}
	s3f := newFakeS3()
	boot := &Boot{nsm: nsm, ssm: ssm, s3: s3f, sts: &fakeSTS{}, pcr0: pcr0}
	planned, err := boot.plan(ctx)
	require.NoError(t, err)
	lease, err := TryAcquireLease(ctx, s3f, "genesis-leases", genesisLeaseName, leaseTTL)
	require.NoError(t, err)
	require.NotNil(t, lease)
	t.Cleanup(func() { _ = lease.Release(context.Background()) })
	planned.mode.(*genesisBoot).lease = lease

	established, err := (&Boot{nsm: nsm, ssm: ssm}).establish(
		ctx, planned, &stateOriginTestKMS{keyID: keyID},
	)

	require.NoError(t, err)
	require.NotNil(t, established.dek)
	require.Len(t, established.secrets, len(stateOriginTestSecrets))
	require.Equal(t, stateOriginTestMigrationIntentBucket(), established.migrationIntentBucketName)
	root := mustStateRoot(t, ctx, ssm, keyID)
	written := fake.params[stateOriginReceiptParam(keyID, hex.EncodeToString(pcr0))]
	require.NoError(t, verifyStateReceipt(
		NewNSM(WithAttestationRoots(session.attestationRoots)),
		written,
		purposeStateOrigin,
		root,
		map[uint]string{0: hex.EncodeToString(pcr0)},
	))
	require.Equal(t, keyID, fake.params[kmsKeyIDParam(hex.EncodeToString(pcr0))])
	_, hasLegacyReceipt := fake.params["/prod/state-origin/StateOriginReceipt/"+keyID]
	require.False(t, hasLegacyReceipt)
}

func TestEstablishLoadedStateGenesisWithoutLeaseWritesNoReceipt(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	keyID := "key-genesis-without-lease"
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fake, ssm := stateOriginTestSSM(nil)
	session := newStatefulNSMSession(t, map[uint][]byte{0: pcr0})
	nsm := &nsmW{nsm: &fakeNSM{session: session, verifyRoots: session.attestationSign.roots}}
	s3f := newFakeS3()
	planned, err := (&Boot{nsm: nsm, ssm: ssm, s3: s3f, sts: &fakeSTS{}, pcr0: pcr0}).plan(ctx)
	require.NoError(t, err)

	_, err = (&Boot{nsm: nsm, ssm: ssm}).establish(
		ctx, planned, &stateOriginTestKMS{keyID: keyID},
	)

	require.ErrorContains(t, err, "refusing to commit genesis without lease")
	require.Empty(t, fake.params[stateOriginReceiptParam(keyID, hex.EncodeToString(pcr0))])
}

func TestEstablishLoadedStateCommitsGenesisKeyAfterReceipt(t *testing.T) {
	setStateOriginTestEnv(t)

	keyID := "key-genesis-failure"
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fake, ssm := stateOriginTestSSM(
		map[string]string{kmsKeyIDParam(stateOriginTestPCR0Hex()): "UNSET"},
	)
	fake.putErrs = map[string]error{
		stateOriginReceiptParam(keyID, hex.EncodeToString(pcr0)): errors.New(
			"receipt write failed",
		),
	}
	session := newStatefulNSMSession(t, map[uint][]byte{0: pcr0})
	nsm := &nsmW{nsm: &fakeNSM{session: session, verifyRoots: session.attestationSign.roots}}
	boot := &Boot{nsm: nsm, ssm: ssm, s3: newFakeS3(), sts: &fakeSTS{}, pcr0: pcr0}
	planned, err := boot.plan(context.Background())
	require.NoError(t, err)
	lease, err := TryAcquireLease(
		context.Background(), boot.s3, "genesis-leases", genesisLeaseName, leaseTTL,
	)
	require.NoError(t, err)
	require.NotNil(t, lease)
	t.Cleanup(func() { _ = lease.Release(context.Background()) })
	planned.mode.(*genesisBoot).lease = lease

	_, err = (&Boot{nsm: nsm, ssm: ssm}).establish(
		context.Background(), planned, &stateOriginTestKMS{keyID: keyID},
	)

	require.Error(t, err)
	require.Equal(t, "UNSET", fake.params[kmsKeyIDParam(hex.EncodeToString(pcr0))])
}

func TestEstablishLoadedStateRejectsStateChangeBeforeDecrypt(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	keyID := "key-resume"
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	for _, tc := range []struct {
		name  string
		param string
		value string
	}{
		{
			name:  "ciphertext swap",
			param: secretCiphertextParam("alpha", keyID),
			value: base64.StdEncoding.EncodeToString([]byte{0xff, 0xff, 0xff}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, ssm := stateOriginTestSSM(stateOriginParams(keyID))
			root := mustStateRoot(t, ctx, ssm, keyID)
			att := signedReceipt(t, map[uint][]byte{0: pcr0}, purposeStateOrigin, root)
			fake.params[stateOriginReceiptParam(keyID, hex.EncodeToString(pcr0))] = att.docB64
			if tc.param != "" {
				fake.params[tc.param] = tc.value
			}
			s3f := newFakeS3()
			seedGenesisRecord(t, s3f, hex.EncodeToString(pcr0))
			boot := &Boot{ssm: ssm, s3: s3f, sts: &fakeSTS{}, pcr0: pcr0}
			planned, err := boot.plan(ctx)
			require.NoError(t, err)
			kms := &stateOriginTestKMS{keyID: keyID}

			_, err = (&Boot{
				nsm: &nsmW{nsm: &fakeNSM{
					session:     newStatefulNSMSession(t, map[uint][]byte{0: pcr0}),
					verifyRoots: att.roots,
				}},
				ssm: ssm,
			}).establish(ctx, planned, kms)

			require.ErrorContains(t, err, "invalid state-origin receipt")
			require.Empty(t, kms.decryptCalls)
		})
	}
}

func TestEstablishLoadedStateMigration(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	keyID := "key-migration"
	ownPCR0 := bytes.Repeat([]byte{0xab}, 48)
	prevPCR0 := bytes.Repeat([]byte{0x99}, 48)
	wrongPCR0 := bytes.Repeat([]byte{0x77}, 48)
	failedTargetPCR0 := bytes.Repeat([]byte{0x33}, 48)
	t.Setenv("ENCLAVE_PREVIOUS_PCR0", hex.EncodeToString(prevPCR0))

	run := func(t *testing.T, prevPCR0Hex string, verifiedPCRs map[uint][]byte) (*fakeSSM, []byte, *x509.CertPool, error) {
		t.Helper()
		fake, ssm := stateOriginTestSSM(stateOriginParams(keyID))
		root := mustStateRoot(t, ctx, ssm, keyID)
		transition := signedReceipt(t, verifiedPCRs, purposeMigrationTransition, root)
		stateReceipt := signedReceipt(t, map[uint][]byte{0: ownPCR0}, purposeStateOrigin, root)
		fake.params[migrationStateOriginReceiptParam(keyID)] = transition.docB64
		fake.params[migrationPreviousPCR0Param(hex.EncodeToString(ownPCR0))] = prevPCR0Hex
		fake.params[migrationPreviousPCR0AttestationParam(hex.EncodeToString(ownPCR0))] = "previous-attestation"

		session := &fakeNSMSession{}
		session.responses = append(session.responses, attestationDocumentResponse(stateReceipt.doc))
		nsm := &nsmW{nsm: &fakeNSM{
			session: session,
			verifyResult: verifyDocResult(
				verifiedPCRs,
				receiptPayload(t, purposeMigrationTransition, root),
			),
		}}
		s3f := newFakeS3()
		seedGenesisRecord(t, s3f, prevPCR0Hex)
		boot := &Boot{
			nsm: seededGenesisNSM{NSM: fakePredecessorNSM{
				NSM: nsm, doc: "previous-attestation",
			}},
			ssm: ssm, s3: s3f, sts: &fakeSTS{}, pcr0: ownPCR0,
		}
		planned, err := boot.plan(ctx)
		if err != nil {
			return fake, root, stateReceipt.roots, err
		}

		_, err = (&Boot{nsm: nsm, ssm: ssm}).establish(
			ctx, planned, &stateOriginTestKMS{keyID: keyID},
		)
		return fake, root, stateReceipt.roots, err
	}

	t.Run("accepts valid handoff", func(t *testing.T) {
		fake, root, roots, err := run(t, hex.EncodeToString(prevPCR0), map[uint][]byte{
			0:                 prevPCR0,
			migrationPCRIndex: pcrExtendFromZero(ownPCR0),
		})
		require.NoError(t, err)
		require.NoError(t, verifyStateReceipt(
			NewNSM(WithAttestationRoots(roots)),
			fake.params[stateOriginReceiptParam(keyID, hex.EncodeToString(ownPCR0))],
			purposeStateOrigin,
			root,
			map[uint]string{0: hex.EncodeToString(ownPCR0)},
		))
	})

	t.Run("rejects wrong PCR31", func(t *testing.T) {
		_, _, _, err := run(t, hex.EncodeToString(prevPCR0), map[uint][]byte{
			0:                 prevPCR0,
			migrationPCRIndex: pcrExtendFromZero(wrongPCR0),
		})
		require.Error(t, err)
	})

	// Naming yourself as your own predecessor used to be allowed as a rollback and
	// skipped PCR31 with it, which let an attestation committing to nobody satisfy
	// the handoff check. Each generation now keeps its own key, so it is rejected.
	t.Run("rejects an enclave as its own predecessor", func(t *testing.T) {
		_, _, _, err := run(t, hex.EncodeToString(ownPCR0), map[uint][]byte{
			0:                 ownPCR0,
			migrationPCRIndex: pcrExtendFromZero(failedTargetPCR0),
		})
		require.ErrorContains(t, err, "cannot be its own predecessor")
	})
}

// stateOriginTestPCR0Hex is the PCR0 every boot test runs as. Key IDs and
// predecessor artifacts are scoped to it.
func stateOriginTestPCR0Hex() string {
	return hex.EncodeToString(bytes.Repeat([]byte{0xab}, 48))
}

var stateOriginTestSecrets = []StaticSecretMetadata{
	{Name: "alpha", EnvVar: "ALPHA"},
	{Name: "beta", EnvVar: "BETA"},
}

// stateOriginTestMigrationIntentBucket mirrors the derivation the runtime uses,
// so a change to the formula fails here rather than silently.
func stateOriginTestMigrationIntentBucket() string {
	return migrationIntentBucketName(fakeSTSAccountID)
}

func setStateOriginTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "state-origin")
	t.Setenv("ENCLAVE_PREVIOUS_PCR0", "genesis")
	// Boot opens the intent log to classify itself; validateEnvironment
	// guarantees this is set before any real boot reaches that point.
	t.Setenv("ENCLAVE_MIGRATION_INTENT_RETENTION", "87600h")
	t.Setenv("ENCLAVE_SECRETS_CONFIG", `[
		{"name":"alpha","env_var":"ALPHA"},
		{"name":"beta","env_var":"BETA"}
	]`)
}

type stateOriginTestKMS struct {
	PrimaryKMS
	keyID        string
	generateCall byte
	decryptCalls []string
}

func (k *stateOriginTestKMS) KeyID() string { return k.keyID }

func (k *stateOriginTestKMS) GenerateDataKey(context.Context) (*DataKey, error) {
	k.generateCall++
	return &DataKey{
		Ciphertext: bytes.Repeat([]byte{k.generateCall}, 32),
		Plaintext:  bytes.Repeat([]byte{k.generateCall + 0x40}, 32),
	}, nil
}

func (k *stateOriginTestKMS) Encrypt(_ context.Context, plaintext []byte) (string, error) {
	return base64.StdEncoding.EncodeToString(plaintext), nil
}

func (k *stateOriginTestKMS) Decrypt(_ context.Context, ciphertext string) ([]byte, error) {
	k.decryptCalls = append(k.decryptCalls, ciphertext)
	return base64.StdEncoding.DecodeString(ciphertext)
}

func stateOriginTestSSM(params map[string]string) (*fakeSSM, SSM) {
	fake := &fakeSSM{params: map[string]string{}}
	maps.Copy(fake.params, params)
	return fake, NewSSM(fake)
}

func stateOriginParams(keyID string) map[string]string {
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tlsKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		panic(err)
	}
	params := map[string]string{
		kmsKeyIDParam(stateOriginTestPCR0Hex()): keyID,
		storageDEKCiphertextParam(keyID): base64.StdEncoding.EncodeToString(
			[]byte{0xde, 0xad, 0xbe, 0xef},
		),
		tlsKeyCiphertextParam(keyID): base64.StdEncoding.EncodeToString(tlsKeyPKCS8),
	}
	for i, secret := range stateOriginTestSecrets {
		params[secretCiphertextParam(secret.Name, keyID)] = base64.StdEncoding.EncodeToString(
			[]byte{byte(i), 0x11, 0x22, 0x33},
		)
	}
	return params
}

func mustStateRoot(
	t *testing.T,
	ctx context.Context,
	ssm SSM,
	keyID string,
) []byte {
	t.Helper()
	secrets := make(map[StaticSecretMetadata]string, len(stateOriginTestSecrets))
	for _, secret := range stateOriginTestSecrets {
		param := secretCiphertextParam(secret.Name, keyID)
		ciphertext, err := ssm.MustGet(ctx, param)
		require.NoError(t, err)
		secrets[secret] = ciphertext
	}
	dekCiphertext, err := ssm.MustGet(ctx, storageDEKCiphertextParam(keyID))
	require.NoError(t, err)
	tlsKeyCiphertext, err := ssm.MustGet(ctx, tlsKeyCiphertextParam(keyID))
	require.NoError(t, err)
	root, err := stateRoot(bootSnapshot{
		kmsKeyID:                  keyID,
		ownerPCR0:                 stateOriginTestPCR0Hex(),
		staticSecrets:             secrets,
		storageDEK:                dekCiphertext,
		tlsKeyCiphertext:          tlsKeyCiphertext,
		migrationIntentBucketName: stateOriginTestMigrationIntentBucket(),
	})
	require.NoError(t, err)
	return root
}

func receiptPayload(t *testing.T, purpose string, stateRoot []byte) []byte {
	t.Helper()
	payload, err := cbor.Marshal(stateOriginPayloadV1{Purpose: purpose, StateRoot: stateRoot})
	require.NoError(t, err)
	return payload
}

func signedReceipt(
	t *testing.T,
	pcrs map[uint][]byte,
	purpose string,
	stateRoot []byte,
) signedAttestation {
	t.Helper()
	now := time.Now()
	return buildSignedAttestationCustom(
		t,
		pcrs,
		now.Add(-time.Hour),
		now.Add(time.Hour),
		now,
		receiptPayload(t, purpose, stateRoot),
	)
}

// genesisFixture builds the shared AWS surface N enclaves of one PCR0 boot
// against. The NSM session is shared because identical PCR0 means an identical
// EIF, and receipts written by one enclave must verify under another's roots.
type genesisFixture struct {
	nsm     NSM
	ssmf    *fakeSSM
	ssm     SSM
	s3f     *fakeS3
	kmsf    *fakeKMS
	sts     *fakeSTS
	pcr0Hex string
}

// keyIDParam is this fixture's own generation pointer: key IDs are PCR0-scoped,
// so a handoff adds a generation instead of overwriting one.
func (f *genesisFixture) keyIDParam() string { return kmsKeyIDParam(f.pcr0Hex) }

// seedGenesisRecord writes the record a completed genesis leaves behind. The
// attestation is a placeholder: Genesis does not verify it.
func seedGenesisRecord(t *testing.T, s3f *fakeS3, targetPCR0 string) {
	t.Helper()
	body, err := json.Marshal(deploymentGenesisV1{
		Schema:      deploymentGenesisSchemaV1,
		PCR0:        targetPCR0,
		Attestation: seededGenesisAttestation,
	})
	require.NoError(t, err)
	s3f.putRawObject(deploymentGenesisKey, body)
}

func (f *genesisFixture) genesisLog(t *testing.T) *genesisLog {
	t.Helper()
	log, err := newGenesisLog(f.s3f, f.nsm, stateOriginTestMigrationIntentBucket())
	require.NoError(t, err)
	return log
}

func newGenesisFixture(t *testing.T, pcr0 []byte) *genesisFixture {
	t.Helper()
	t.Setenv("ENCLAVE_PREVIOUS_PCR0", "genesis")
	session := newStatefulNSMSession(t, map[uint][]byte{0: pcr0})
	ssmf, ssm := stateOriginTestSSM(map[string]string{
		leaseBucketParam(): "genesis-leases",
	})
	return &genesisFixture{
		nsm:     &nsmW{nsm: &fakeNSM{session: session, verifyRoots: session.attestationSign.roots}},
		pcr0Hex: hex.EncodeToString(pcr0),
		ssmf:    ssmf,
		ssm:     ssm,
		s3f:     newFakeS3(),
		kmsf:    newFakeKMS(),
		sts:     &fakeSTS{arn: testRoleARN},
	}
}

func (f *genesisFixture) establish(ctx context.Context) (bootResult, error) {
	boot, err := NewBoot(f.nsm, f.kmsf, f.sts, f.ssm, f.s3f)
	if err != nil {
		return bootResult{}, err
	}
	return boot.Boot(ctx)
}

// A live peer lease must stop genesis before any KMS key is minted
func TestBootGenesisBlocksOnPeerLease(t *testing.T) {
	setStateOriginTestEnv(t)
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))
	writeLeaseDoc(t, fx.s3f, leaseObjectKey(genesisLeaseName), time.Now().Add(time.Hour))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := fx.establish(ctx)

	require.ErrorContains(t, err, "genesis did not complete")
	require.Empty(t, fx.kmsf.keys, "no KMS key may be minted while a peer holds genesis")
	require.Empty(t, fx.ssmf.params[fx.keyIDParam()])
}

// A second enclave arriving after a peer's genesis resumes against the committed
// key and derives the identical DEK, rather than minting its own.
func TestBootResumesAfterPeerGenesis(t *testing.T) {
	setStateOriginTestEnv(t)
	ctx := context.Background()
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))

	first, err := fx.establish(ctx)
	require.NoError(t, err)
	require.Len(t, fx.kmsf.keys, 1)
	committed := fx.ssmf.params[fx.keyIDParam()]
	require.NotEmpty(t, committed)

	second, err := fx.establish(ctx)
	require.NoError(t, err)

	require.Len(t, fx.kmsf.keys, 1, "the second boot must not mint a key")
	require.Equal(t, committed, fx.ssmf.params[fx.keyIDParam()])
	require.Equal(t, first.kms.KeyID(), second.kms.KeyID())
	require.Equal(t, first.dek.(*dek).key, second.dek.(*dek).key, "fleet must share one DEK")
	require.Equal(t, first.secrets, second.secrets)
}

// The lease is released once genesis commits, so it never wedges later boots.
func TestBootReleasesGenesisLease(t *testing.T) {
	setStateOriginTestEnv(t)
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))

	_, err := fx.establish(context.Background())
	require.NoError(t, err)

	require.Empty(t, fx.s3f.currentETag(leaseObjectKey(genesisLeaseName)))
}

// Losers must not queue on the lease. Once a peer has committed, a waiting
// enclave resumes immediately instead of winning the lock just to find the work
// already done — otherwise a fleet's first boot drains one poll interval at a time.
func TestAwaitGenesisSkipsLeaseWhenPeerCommitted(t *testing.T) {
	setStateOriginTestEnv(t)
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)

	_, err := fx.establish(context.Background())
	require.NoError(t, err)

	// A peer still holds the genesis lease, but the work is already committed.
	writeLeaseDoc(t, fx.s3f, leaseObjectKey(genesisLeaseName), time.Now().Add(time.Hour))

	// Far shorter than leasePollInterval: passing proves we never waited on it.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	boot := &Boot{ssm: fx.ssm, s3: fx.s3f, sts: fx.sts, pcr0: pcr0}
	lease, err := boot.awaitGenesisLease(ctx, fx.genesisLog(t))

	require.NoError(t, err)
	require.Nil(t, lease, "a committed genesis needs no lease")

	planned, err := boot.plan(ctx)
	require.NoError(t, err)
	require.IsType(t, &resumeBoot{}, planned.mode, "a peer's committed genesis leaves us resuming")
}

// A peer that has claimed the key but not yet written the artifact has not
// finished. Resuming there replans into a genesis boot with a committed key,
// which verify refuses — so the wait must hold until both are visible.
func TestAwaitGenesisWaitsForTheArtifactNotTheKeyAlone(t *testing.T) {
	setStateOriginTestEnv(t)
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)

	// Mid-genesis: key claimed, artifact not written, peer still holding.
	fx.ssmf.params[fx.keyIDParam()] = "key-from-peer"
	writeLeaseDoc(t, fx.s3f, leaseObjectKey(genesisLeaseName), time.Now().Add(time.Hour))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	boot := &Boot{ssm: fx.ssm, s3: fx.s3f, sts: fx.sts, pcr0: pcr0}

	lease, err := boot.awaitGenesisLease(ctx, fx.genesisLog(t))

	require.Error(t, err, "an unfinished genesis must keep us waiting, not resume")
	require.Nil(t, lease)
}

// A peer can commit between our poll and our winning the lease. Winning proves
// nobody else is running genesis, not that genesis has not already happened, so
// the lease must be given straight back rather than used to redo the work.
func TestAwaitGenesisLeaseReleasesWhenPeerCommitsAfterWin(t *testing.T) {
	setStateOriginTestEnv(t)
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)

	// The artifact is visible while our first cross-service key read is stale;
	// the re-read under the lease observes the completed commit.
	seedGenesisRecord(t, fx.s3f, hex.EncodeToString(pcr0))
	fx.ssmf.getSeq = map[string][]string{
		fx.keyIDParam(): {"", "key-from-peer"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	boot := &Boot{ssm: fx.ssm, s3: fx.s3f, sts: fx.sts, pcr0: pcr0}
	lease, err := boot.awaitGenesisLease(ctx, fx.genesisLog(t))

	require.NoError(t, err)
	require.Nil(t, lease, "a genesis completed under us must not leave us holding the lease")
	require.Empty(t, fx.s3f.currentETag(leaseObjectKey(genesisLeaseName)),
		"the lease must be released, not held through the resume path")
}

// A holder that died mid-genesis must not wedge the deployment forever — not
// even against its own restart. Once the lease lapses the lock is reclaimable.
func TestAwaitGenesisReclaimsLapsedLock(t *testing.T) {
	setStateOriginTestEnv(t)
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)

	// A previous boot died mid-genesis: lock left behind, KMSKeyID never committed.
	writeLeaseDoc(t, fx.s3f, leaseObjectKey(genesisLeaseName), time.Now().Add(-time.Hour))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	boot := &Boot{ssm: fx.ssm, s3: fx.s3f, sts: fx.sts, pcr0: pcr0}
	lease, err := boot.awaitGenesisLease(ctx, fx.genesisLog(t))

	require.NoError(t, err)
	require.NotNil(t, lease, "a lapsed lock must be reclaimable")

	planned, err := boot.plan(ctx)
	require.NoError(t, err)
	require.IsType(
		t,
		&genesisBoot{},
		planned.mode,
		"holding the lease means genesis is still ours to do",
	)
	require.NoError(t, lease.Release(context.Background()))
}

// A live holder is still never displaced.
func TestAwaitGenesisWaitsOnLiveHolder(t *testing.T) {
	setStateOriginTestEnv(t)
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)

	writeLeaseDoc(t, fx.s3f, leaseObjectKey(genesisLeaseName), time.Now().Add(time.Hour))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	lease, err := (&Boot{ssm: fx.ssm, s3: fx.s3f, sts: fx.sts, pcr0: pcr0}).
		awaitGenesisLease(ctx, fx.genesisLog(t))

	require.Nil(t, lease)
	require.ErrorContains(t, err, "genesis did not complete")
	require.Empty(t, fx.kmsf.keys, "a live holder's genesis must not be duplicated")
}

// The KMSKeyID commit is unconditional, so losing the lock mid-genesis must
// stop the commit rather than let it clobber whoever took over.
func TestEstablishLoadedStateRefusesCommitWithoutTheLease(t *testing.T) {
	setStateOriginTestEnv(t)
	ctx := context.Background()
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)

	bucket, err := fx.ssm.MustGet(ctx, leaseBucketParam())
	require.NoError(t, err)
	lease, err := AcquireLease(ctx, fx.s3f, bucket, genesisLeaseName, leaseTTL)
	require.NoError(t, err)

	// A peer takes the lock over while this enclave is mid-genesis.
	writeLeaseDoc(t, fx.s3f, leaseObjectKey(genesisLeaseName), time.Now().Add(time.Hour))

	boot := &Boot{nsm: fx.nsm, ssm: fx.ssm, s3: fx.s3f, sts: fx.sts, pcr0: pcr0}
	planned, err := boot.plan(ctx)
	require.NoError(t, err)
	genesis, ok := planned.mode.(*genesisBoot)
	require.True(t, ok, "an uncommitted deployment must plan a genesis boot")
	genesis.lease = lease
	session := newStatefulNSMSession(t, map[uint][]byte{0: pcr0})

	_, err = (&Boot{
		nsm: &nsmW{nsm: &fakeNSM{
			session:     session,
			verifyRoots: session.attestationSign.roots,
		}},
		ssm: fx.ssm,
	}).establish(ctx, planned, &stateOriginTestKMS{keyID: "key-zombie"})

	require.ErrorContains(t, err, "refusing to commit genesis")
	require.ErrorIs(t, err, ErrLeaseLost)
	require.Empty(t, fx.ssmf.params[fx.keyIDParam()], "KMSKeyID must not be committed")
}

// fakePredecessorNSM answers the predecessor attestation check, which the tests
// using it are not about, and delegates every other document.
const seededGenesisAttestation = "seeded"

// seededGenesisNSM accepts the placeholder attestation seedGenesisRecord writes,
// so a seeded peer record reads back as a genuine one.
type seededGenesisNSM struct {
	NSM
}

func (n seededGenesisNSM) VerifyAttestation(
	doc string, pcrs map[uint]string, userData []byte,
) error {
	if doc == seededGenesisAttestation {
		return nil
	}
	return n.NSM.VerifyAttestation(doc, pcrs, userData)
}

type fakePredecessorNSM struct {
	NSM
	doc string
}

func (n fakePredecessorNSM) VerifyAttestation(
	doc string, pcrs map[uint]string, userData []byte,
) error {
	if doc == n.doc {
		return nil
	}
	return n.NSM.VerifyAttestation(doc, pcrs, userData)
}

func TestDeletingKMSKeyIDFailsClosed(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)

	first, err := fx.establish(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, fx.ssmf.params[fx.keyIDParam()])
	originalDEK := fx.ssmf.params[storageDEKCiphertextParam(first.kms.KeyID())]
	require.NotEmpty(t, originalDEK)

	delete(fx.ssmf.params, fx.keyIDParam())

	_, err = fx.establish(ctx)

	require.ErrorContains(t, err, "deployment genesis is recorded but")
	require.Empty(t, fx.ssmf.params[fx.keyIDParam()])
	require.Equal(t, originalDEK, fx.ssmf.params[storageDEKCiphertextParam(first.kms.KeyID())],
		"the original generation's ciphertexts must survive")
}

func TestGenesisRequiresAnEmptyGenesisIntent(t *testing.T) {
	ctx := context.Background()
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	pcr0Hex := hex.EncodeToString(pcr0)
	otherPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0x99}, 48))

	for _, tc := range []struct {
		name    string
		seed    func(t *testing.T, fx *genesisFixture)
		wantErr string
	}{
		{
			name: "a fresh deployment creates itself",
		},
		{
			name: "another enclave's record vetoes genesis",
			seed: func(t *testing.T, fx *genesisFixture) {
				seedGenesisRecord(t, fx.s3f, otherPCR0)
				fx.nsm = seededGenesisNSM{NSM: fx.nsm}
			},
			wantErr: "deployment genesis is recorded but",
		},
		{
			name: "a committed key with an empty log is a wiped log",
			seed: func(_ *testing.T, fx *genesisFixture) {
				fx.ssmf.params[fx.keyIDParam()] = "key-from-nowhere"
			},
			wantErr: "genesis boot with a committed KMS key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setStateOriginTestEnv(t)
			fx := newGenesisFixture(t, pcr0)
			if tc.seed != nil {
				tc.seed(t, fx)
			}

			_, err := fx.establish(ctx)

			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.Empty(t, fx.kmsf.keys, "no key may be minted on a refused genesis")
				if tc.name == "a committed key with an empty log is a wiped log" {
					require.Empty(t, fx.s3f.latestBody(migrationIntentObjectKey(pcr0Hex, 1)),
						"a refused genesis must not claim the intent")
				}
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, fx.ssmf.params[fx.keyIDParam()])
		})
	}
}

// A failed create-only key claim must not leave an immutable genesis commit.
func TestGenesisClaimsKMSKeyBeforeCommittingIntent(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)
	fx.ssmf.putErrs = map[string]error{
		fx.keyIDParam(): errors.New("key commit failed"),
	}

	_, err := fx.establish(ctx)

	require.ErrorContains(t, err, "key commit failed")
	require.Empty(t, fx.ssmf.params[fx.keyIDParam()])
	intent, loadErr := newGenesisLog(
		fx.s3f, fx.nsm, stateOriginTestMigrationIntentBucket(),
	)
	require.NoError(t, loadErr)
	commit, loadErr := intent.Genesis(ctx)
	require.NoError(t, loadErr)
	require.Nil(t, commit)
}

// A peer claiming KMSKeyID inside the window between our verify and our
// create-only write must stop us dead, leaving its claim and no genesis.
func TestGenesisAbandonsCommitWhenPeerClaimsKeyFirst(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)
	fx.ssmf.beforePut = func(name string) {
		if name == fx.keyIDParam() {
			fx.ssmf.params[name] = "peer-key"
		}
	}

	_, err := fx.establish(ctx)

	require.ErrorContains(t, err, "failed to claim genesis KMS key ID")
	require.Equal(t, "peer-key", fx.ssmf.params[fx.keyIDParam()],
		"the peer's claim must stand")
	genesis, loadErr := newGenesisLog(fx.s3f, fx.nsm, stateOriginTestMigrationIntentBucket())
	require.NoError(t, loadErr)
	committed, loadErr := genesis.Genesis(ctx)
	require.NoError(t, loadErr)
	require.Nil(t, committed, "a lost key claim must not record genesis")
}

// Once the create-only KMS claim succeeds, an intent failure leaves an
// interrupted genesis that every later boot rejects.
func TestGenesisIntentFailureLeavesFailClosedKMSClaim(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)
	boot := &Boot{nsm: fx.nsm, ssm: fx.ssm, s3: fx.s3f, sts: fx.sts, pcr0: pcr0}
	planned, err := boot.plan(ctx)
	require.NoError(t, err)
	lease, err := TryAcquireLease(
		ctx, fx.s3f, "genesis-leases", genesisLeaseName, leaseTTL,
	)
	require.NoError(t, err)
	require.NotNil(t, lease)
	planned.mode.(*genesisBoot).lease = lease
	t.Cleanup(func() { _ = lease.Release(context.Background()) })
	fx.s3f.putErr = errors.New("intent bucket unwritable")

	_, err = boot.establish(ctx, planned, &stateOriginTestKMS{keyID: "claimed-key"})

	require.ErrorContains(t, err, "intent bucket unwritable")
	require.Equal(t, "claimed-key", fx.ssmf.params[fx.keyIDParam()])
}

// The intent bucket is measured, never read from SSM. A host that can write the
// application's SSM namespace could otherwise aim the genesis check at an empty
// bucket and have a second generation created beside the live one.
func TestIntentBucketIsMeasuredNotReadFromSSM(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)
	fx.ssmf.params["/prod/state-origin/MigrationIntentBucketName"] = "attacker-empty-bucket"

	result, err := fx.establish(ctx)

	require.NoError(t, err)
	require.Equal(t, stateOriginTestMigrationIntentBucket(), result.migrationIntentBucketName)
	require.NotContains(t, fx.ssmf.calls, "/prod/state-origin/MigrationIntentBucketName")
}
