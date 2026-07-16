package runtime

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

var stateOriginTestSecrets = []StaticSecretMetadata{
	{Name: "alpha", EnvVar: "ALPHA"},
	{Name: "beta", EnvVar: "BETA"},
}

func setStateOriginTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "state-origin")
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
	params := map[string]string{
		kmsKeyIDParam(): keyID,
		storageDEKCiphertextParam(keyID): base64.StdEncoding.EncodeToString(
			[]byte{0xde, 0xad, 0xbe, 0xef},
		),
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
	secrets := make([]persistedSecret, 0, len(stateOriginTestSecrets))
	for _, secret := range stateOriginTestSecrets {
		param := secretCiphertextParam(secret.Name, keyID)
		ciphertext, err := ssm.MustGet(ctx, param)
		require.NoError(t, err)
		secrets = append(secrets, persistedSecret{
			metadata:   secret,
			ciphertext: ciphertext,
		})
	}
	dekCiphertext, err := ssm.MustGet(ctx, storageDEKCiphertextParam(keyID))
	require.NoError(t, err)
	root, err := stateRoot(persistedStateSnapshot{
		kmsKeyID:      keyID,
		staticSecrets: secrets,
		storageDEK:    dekCiphertext,
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

func TestLoadUnverifiedState(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	keyID := "key-classify"
	prevPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0x99}, 48))
	withKey := func(params map[string]string) map[string]string {
		maps.Copy(params, stateOriginParams(keyID))
		return params
	}

	withReceipt := func(params map[string]string) map[string]string {
		params[stateOriginReceiptParam(keyID)] = "receipt"
		return params
	}
	withMigration := func(params map[string]string) map[string]string {
		params[migrationStateOriginReceiptParam(keyID)] = "transition"
		params[migrationPreviousPCR0Param()] = prevPCR0
		params[migrationPreviousPCR0AttestationParam()] = "attestation"
		return params
	}

	cases := []struct {
		name    string
		params  map[string]string
		want    startState
		wantErr bool
	}{
		{
			name:   "genesis clean",
			params: map[string]string{},
			want:   startStateGenesis,
		},
		{
			name:    "genesis blocked by migration artifacts",
			params:  withMigration(map[string]string{}),
			wantErr: true,
		},
		{
			name: "genesis blocked by partial migration artifacts",
			params: map[string]string{
				migrationPreviousPCR0Param(): prevPCR0,
			},
			wantErr: true,
		},
		{
			name:   "resume with receipt",
			params: withReceipt(withKey(map[string]string{})),
			want:   startStateResume,
		},
		{
			name: "without receipt fails", params: withKey(map[string]string{}), wantErr: true,
		},
		{
			name:   "migration with transition receipt",
			params: withMigration(withKey(map[string]string{})),
			want:   startStateMigration,
		},
		{
			name: "migration artifacts without transition receipt fail",
			params: withKey(func() map[string]string {
				params := map[string]string{}
				params[migrationPreviousPCR0Param()] = prevPCR0
				params[migrationPreviousPCR0AttestationParam()] = "attestation"
				return params
			}()),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ssm := stateOriginTestSSM(tc.params)
			got, err := loadUnverifiedState(ctx, ssm)

			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got.startState)
			switch tc.want {
			case startStateResume:
				require.Equal(t, "receipt", got.receipt)
			case startStateMigration:
				require.Equal(t, "transition", got.receipt)
				require.Equal(t, prevPCR0, got.predecessorPCR0)
				require.Equal(t, "attestation", got.predecessorAttestation)
			}
		})
	}
}

func TestVerifyStateOriginReceipt(t *testing.T) {
	setStateOriginTestEnv(t)

	stateRoot := []byte("state-root-commitment")
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	pcr0Hex := hex.EncodeToString(pcr0)
	att := signedReceipt(t, map[uint][]byte{0: pcr0}, purposeStateOrigin, stateRoot)
	verifier := NewNSM(WithAttestationRoots(att.roots))

	require.NoError(t, verifyStateOriginReceipt(
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
			err := verifyStateOriginReceipt(verifier, tc.receipt, tc.purpose, tc.root, tc.expected)
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

	err := verifyStateOriginReceipt(
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

	err = verifyStateOriginReceipt(
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

	require.NoError(t, validateStaticSecretArtifacts(stateOriginTestSecrets))
	require.Error(t, validateStaticSecretArtifacts([]StaticSecretMetadata{
		{Name: "duplicate", EnvVar: "ONE"},
		{Name: "duplicate", EnvVar: "TWO"},
	}))
	require.Error(t, validateStaticSecretArtifacts([]StaticSecretMetadata{
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
	fake.params[stateOriginReceiptParam(keyID)] = receipt.docB64
	session := newStatefulNSMSession(t, map[uint][]byte{0: pcr0})
	kms := &stateOriginTestKMS{keyID: keyID}
	unverified, err := loadUnverifiedState(ctx, ssm)
	require.NoError(t, err)
	readCount := len(fake.calls)
	fake.params[storageDEKCiphertextParam(keyID)] = base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0xdd}, 32),
	)

	established, err := establishLoadedState(
		ctx,
		&nsmW{nsm: &fakeNSM{session: session, verifyRoots: receipt.roots}},
		kms,
		ssm,
		unverified,
	)

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
	params[stateOriginReceiptParam(keyID)] = "receipt"
	fake, ssm := stateOriginTestSSM(params)

	_, err := loadUnverifiedState(ctx, ssm)

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
	nsm := &nsmW{nsm: &fakeNSM{session: session}}
	unverified, err := loadUnverifiedState(ctx, ssm)
	require.NoError(t, err)

	established, err := establishLoadedState(
		ctx,
		nsm,
		&stateOriginTestKMS{keyID: keyID},
		ssm,
		unverified,
	)

	require.NoError(t, err)
	require.NotNil(t, established.dek)
	require.Len(t, established.secrets, len(stateOriginTestSecrets))
	root := mustStateRoot(t, ctx, ssm, keyID)
	written := fake.params[stateOriginReceiptParam(keyID)]
	require.NoError(t, verifyStateOriginReceipt(
		NewNSM(WithAttestationRoots(session.attestationRoots)),
		written,
		purposeStateOrigin,
		root,
		map[uint]string{0: hex.EncodeToString(pcr0)},
	))
	require.Equal(t, keyID, fake.params[kmsKeyIDParam()])
}

func TestEstablishLoadedStateCommitsGenesisKeyAfterReceipt(t *testing.T) {
	setStateOriginTestEnv(t)

	keyID := "key-genesis-failure"
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fake, ssm := stateOriginTestSSM(map[string]string{kmsKeyIDParam(): "UNSET"})
	fake.putErrs = map[string]error{
		stateOriginReceiptParam(keyID): errors.New("receipt write failed"),
	}
	session := newStatefulNSMSession(t, map[uint][]byte{0: pcr0})
	unverified, err := loadUnverifiedState(context.Background(), ssm)
	require.NoError(t, err)

	_, err = establishLoadedState(
		context.Background(),
		&nsmW{nsm: &fakeNSM{session: session}},
		&stateOriginTestKMS{keyID: keyID},
		ssm,
		unverified,
	)

	require.Error(t, err)
	require.Equal(t, "UNSET", fake.params[kmsKeyIDParam()])
}

func TestEstablishLoadedStateRejectsCiphertextSwapBeforeDecrypt(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	keyID := "key-resume"
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fake, ssm := stateOriginTestSSM(stateOriginParams(keyID))
	root := mustStateRoot(t, ctx, ssm, keyID)
	att := signedReceipt(t, map[uint][]byte{0: pcr0}, purposeStateOrigin, root)
	fake.params[stateOriginReceiptParam(keyID)] = att.docB64
	fake.params[secretCiphertextParam("alpha", keyID)] = base64.StdEncoding.EncodeToString(
		[]byte{0xff, 0xff, 0xff},
	)
	unverified, err := loadUnverifiedState(ctx, ssm)
	require.NoError(t, err)
	kms := &stateOriginTestKMS{keyID: keyID}
	_, err = establishLoadedState(
		ctx,
		&nsmW{nsm: &fakeNSM{
			session:     newStatefulNSMSession(t, map[uint][]byte{0: pcr0}),
			verifyRoots: att.roots,
		}},
		kms,
		ssm,
		unverified,
	)
	require.Error(t, err)
	require.Empty(t, kms.decryptCalls)
}

func TestEstablishLoadedStateMigration(t *testing.T) {
	setStateOriginTestEnv(t)

	ctx := context.Background()
	keyID := "key-migration"
	ownPCR0 := bytes.Repeat([]byte{0xab}, 48)
	prevPCR0 := bytes.Repeat([]byte{0x99}, 48)
	wrongPCR0 := bytes.Repeat([]byte{0x77}, 48)
	failedTargetPCR0 := bytes.Repeat([]byte{0x33}, 48)

	run := func(t *testing.T, prevPCR0Hex string, verifiedPCRs map[uint][]byte) (*fakeSSM, []byte, *x509.CertPool, error) {
		t.Helper()
		fake, ssm := stateOriginTestSSM(stateOriginParams(keyID))
		root := mustStateRoot(t, ctx, ssm, keyID)
		transition := signedReceipt(t, verifiedPCRs, purposeMigrationTransition, root)
		stateReceipt := signedReceipt(t, map[uint][]byte{0: ownPCR0}, purposeStateOrigin, root)
		fake.params[migrationStateOriginReceiptParam(keyID)] = transition.docB64
		fake.params[migrationPreviousPCR0Param()] = prevPCR0Hex
		fake.params[migrationPreviousPCR0AttestationParam()] = "previous-attestation"

		session := &fakeNSMSession{}
		session.responses = append(
			session.responses,
			attestationDocumentResponse(buildForgedAttestation(t, map[uint][]byte{0: ownPCR0})),
			attestationDocumentResponse(stateReceipt.doc),
		)
		nsm := &nsmW{nsm: &fakeNSM{
			session: session,
			verifyResult: verifyDocResult(
				verifiedPCRs,
				receiptPayload(t, purposeMigrationTransition, root),
			),
		}}
		unverified, err := loadUnverifiedState(ctx, ssm)
		require.NoError(t, err)

		_, err = establishLoadedState(
			ctx,
			nsm,
			&stateOriginTestKMS{keyID: keyID},
			ssm,
			unverified,
		)
		return fake, root, stateReceipt.roots, err
	}

	t.Run("accepts valid handoff", func(t *testing.T) {
		fake, root, roots, err := run(t, hex.EncodeToString(prevPCR0), map[uint][]byte{
			0:                 prevPCR0,
			migrationPCRIndex: pcrExtendFromZero(ownPCR0),
		})
		require.NoError(t, err)
		require.NoError(t, verifyStateOriginReceipt(
			NewNSM(WithAttestationRoots(roots)),
			fake.params[stateOriginReceiptParam(keyID)],
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

	t.Run("rollback onto self skips PCR31", func(t *testing.T) {
		_, _, _, err := run(t, hex.EncodeToString(ownPCR0), map[uint][]byte{
			0:                 ownPCR0,
			migrationPCRIndex: pcrExtendFromZero(failedTargetPCR0),
		})
		require.NoError(t, err)
	})

	t.Run("rollback still requires predecessor signer", func(t *testing.T) {
		_, _, _, err := run(t, hex.EncodeToString(ownPCR0), map[uint][]byte{
			0:                 wrongPCR0,
			migrationPCRIndex: pcrExtendFromZero(failedTargetPCR0),
		})
		require.Error(t, err)
	})
}
