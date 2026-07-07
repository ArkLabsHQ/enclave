package runtime

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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

func mustStateRoot(t *testing.T, ctx context.Context, ssm SSM, keyID string) []byte {
	t.Helper()
	enc, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	root, err := (&stateOrigin{ssm: ssm, secrets: stateOriginTestSecrets, enc: enc}).stateRoot(
		ctx,
		keyID,
	)
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

func TestClassifyStartState(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "state-origin")

	ctx := context.Background()
	keyID := "key-classify"
	prevPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0x99}, 48))

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
		genesis bool
		params  map[string]string
		want    StartState
		wantErr bool
	}{
		{
			name:    "genesis clean",
			genesis: true,
			params:  map[string]string{},
			want:    StartStateGenesis,
		},
		{
			name:    "genesis blocked by migration artifacts",
			genesis: true,
			params:  withMigration(map[string]string{}),
			wantErr: true,
		},
		{
			name:    "genesis blocked by partial migration artifacts",
			genesis: true,
			params: map[string]string{
				migrationPreviousPCR0Param(): prevPCR0,
			},
			wantErr: true,
		},
		{
			name:   "resume complete with receipt",
			params: withReceipt(stateOriginParams(keyID)),
			want:   StartStateResume,
		},
		{name: "complete without receipt fails", params: stateOriginParams(keyID), wantErr: true},
		{
			name:   "migration complete with transition receipt",
			params: withMigration(stateOriginParams(keyID)),
			want:   StartStateMigration,
		},
		{
			name: "migration artifacts without transition receipt fail",
			params: func() map[string]string {
				params := stateOriginParams(keyID)
				params[migrationPreviousPCR0Param()] = prevPCR0
				params[migrationPreviousPCR0AttestationParam()] = "attestation"
				return params
			}(),
			wantErr: true,
		},
		{name: "partial ciphertexts fail", params: func() map[string]string {
			params := withReceipt(stateOriginParams(keyID))
			delete(params, secretCiphertextParam("beta", keyID))
			return params
		}(), wantErr: true},
		{
			name:    "receipt without ciphertexts fails",
			params:  withReceipt(map[string]string{kmsKeyIDParam(): keyID}),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ssm := stateOriginTestSSM(tc.params)
			got, err := ClassifyStartState(
				ctx,
				&kmsW{keyID: keyID, genesis: tc.genesis},
				ssm,
				stateOriginTestSecrets,
			)

			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestVerifyStateOriginReceipt(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "state-origin")

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
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "state-origin")

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

func TestEstablishStateOriginGenesisWritesReceipt(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "state-origin")

	ctx := context.Background()
	keyID := "key-genesis"
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fake, ssm := stateOriginTestSSM(stateOriginParams(keyID))
	root := mustStateRoot(t, ctx, ssm, keyID)
	att := signedReceipt(t, map[uint][]byte{0: pcr0}, purposeStateOrigin, root)
	session := &fakeNSMSession{}
	session.responses = append(session.responses, attestationDocumentResponse(att.doc))
	nsm := &nsmW{nsm: &fakeNSM{session: session}}

	_, err := EstablishStateOrigin(
		ctx,
		nsm,
		&kmsW{keyID: keyID, genesis: true},
		ssm,
		stateOriginTestSecrets,
		StartStateGenesis,
	)

	require.NoError(t, err)
	written := fake.params[stateOriginReceiptParam(keyID)]
	require.NoError(t, verifyStateOriginReceipt(
		NewNSM(WithAttestationRoots(att.roots)),
		written,
		purposeStateOrigin,
		root,
		map[uint]string{0: hex.EncodeToString(pcr0)},
	))
}

func TestEstablishStateOriginResumeDetectsCiphertextSwap(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "state-origin")

	ctx := context.Background()
	keyID := "key-resume"
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fake, ssm := stateOriginTestSSM(stateOriginParams(keyID))
	root := mustStateRoot(t, ctx, ssm, keyID)
	att := signedReceipt(t, map[uint][]byte{0: pcr0}, purposeStateOrigin, root)
	fake.params[stateOriginReceiptParam(keyID)] = att.docB64
	payload := receiptPayload(t, purposeStateOrigin, root)

	session := &fakeNSMSession{}
	session.responses = append(
		session.responses,
		attestationDocumentResponse(buildForgedAttestation(t, map[uint][]byte{0: pcr0})),
	)
	nsm := &nsmW{nsm: &fakeNSM{
		session:      session,
		verifyResult: verifyDocResult(map[uint][]byte{0: pcr0}, payload),
	}}
	_, err := EstablishStateOrigin(
		ctx,
		nsm,
		&kmsW{keyID: keyID},
		ssm,
		stateOriginTestSecrets,
		StartStateResume,
	)
	require.NoError(t, err)

	fake.params[secretCiphertextParam("alpha", keyID)] = base64.StdEncoding.EncodeToString(
		[]byte{0xff, 0xff, 0xff},
	)
	session = &fakeNSMSession{}
	session.responses = append(
		session.responses,
		attestationDocumentResponse(buildForgedAttestation(t, map[uint][]byte{0: pcr0})),
	)
	nsm = &nsmW{nsm: &fakeNSM{
		session:      session,
		verifyResult: verifyDocResult(map[uint][]byte{0: pcr0}, payload),
	}}
	_, err = EstablishStateOrigin(
		ctx,
		nsm,
		&kmsW{keyID: keyID},
		ssm,
		stateOriginTestSecrets,
		StartStateResume,
	)
	require.Error(t, err)
}

func TestEstablishStateOriginMigration(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "state-origin")

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

		_, err := EstablishStateOrigin(
			ctx,
			nsm,
			&kmsW{keyID: keyID},
			ssm,
			stateOriginTestSecrets,
			StartStateMigration,
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
