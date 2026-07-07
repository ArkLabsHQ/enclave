package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
	"github.com/stretchr/testify/require"
)

func TestVerifyPredecessorCommitment_Genesis(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_PREVIOUS_PCR0", "genesis")

	ctx := context.Background()

	t.Run("no predecessor", func(t *testing.T) {
		err := VerifyPredecessorCommitment(ctx, nil, NewSSM(&fakeSSM{}))
		require.NoError(t, err)
	})

	t.Run("rejects SSM predecessor", func(t *testing.T) {
		errs := VerifyPredecessorCommitment(ctx, nil, NewSSM(&fakeSSM{params: map[string]string{
			migrationPreviousPCR0Param(): "abc123",
		}}))
		require.Error(t, errs)
	})
}

func TestVerifyPredecessorCommitment_Predecessor(t *testing.T) {
	prevPCR0Bytes := bytes.Repeat([]byte{0xab}, 48)
	currentPCR0Bytes := bytes.Repeat([]byte{0xcd}, 48)
	prevPCR0 := hex.EncodeToString(prevPCR0Bytes)
	attestation := base64.StdEncoding.EncodeToString([]byte("predecessor attestation"))

	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_PREVIOUS_PCR0", prevPCR0)

	ctx := context.Background()
	previousParam := migrationPreviousPCR0Param()
	attestationParam := migrationPreviousPCR0AttestationParam()

	t.Run("missing previous PCR0", func(t *testing.T) {
		err := VerifyPredecessorCommitment(ctx, nil, NewSSM(&fakeSSM{}))
		require.Error(t, err)
	})

	t.Run("mismatched previous PCR0", func(t *testing.T) {
		err := VerifyPredecessorCommitment(ctx, nil, NewSSM(&fakeSSM{params: map[string]string{
			previousParam: strings.Repeat("0", 96),
		}}))
		require.Error(t, err)
	})

	t.Run("requires attestation", func(t *testing.T) {
		cases := []struct {
			name   string
			params map[string]string
		}{
			{"missing", map[string]string{previousParam: prevPCR0}},
			{"unset", map[string]string{previousParam: prevPCR0, attestationParam: "UNSET"}},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := VerifyPredecessorCommitment(ctx, nil, NewSSM(&fakeSSM{params: tc.params}))
				require.Error(t, err)
			})
		}
	})

	t.Run("wrong PCR31", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, map[uint][]byte{
			0:                 prevPCR0Bytes,
			migrationPCRIndex: bytes.Repeat([]byte{0xef}, 48),
		})

		err := VerifyPredecessorCommitment(ctx, nsm, NewSSM(&fakeSSM{params: map[string]string{
			previousParam:    prevPCR0,
			attestationParam: attestation,
		}}))

		require.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, map[uint][]byte{
			0:                 prevPCR0Bytes,
			migrationPCRIndex: pcrExtendFromZero(currentPCR0Bytes),
		})

		err := VerifyPredecessorCommitment(ctx, nsm, NewSSM(&fakeSSM{params: map[string]string{
			previousParam:    strings.ToUpper(prevPCR0),
			attestationParam: attestation,
		}}))

		require.NoError(t, err)
	})
}

func TestMigratorPreviousPCR0Info(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")

	ctx := context.Background()

	t.Run("genesis", func(t *testing.T) {
		info, err := NewMigrator(nil, nil, NewSSM(&fakeSSM{}), nil, nil, nil).PreviousPCR0Info(ctx)

		require.NoError(t, err)
		require.Equal(t, &PreviousPCR0Info{PCR0: "genesis"}, info)
	})

	t.Run("recorded predecessor", func(t *testing.T) {
		info, err := NewMigrator(nil, nil, NewSSM(&fakeSSM{params: map[string]string{
			migrationPreviousPCR0Param():            "abc123",
			migrationPreviousPCR0AttestationParam(): "attestation",
		}}), nil, nil, nil).PreviousPCR0Info(ctx)

		require.NoError(t, err)
		require.Equal(t, &PreviousPCR0Info{PCR0: "abc123", Attestation: "attestation"}, info)
	})
}

func TestMigratorCooldownStatus(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "2m")

	ctx := context.Background()

	t.Run("none", func(t *testing.T) {
		status, err := NewMigrator(nil, nil, NewSSM(&fakeSSM{}), nil, nil, nil).CooldownStatus(ctx)

		require.NoError(t, err)
		require.Equal(t, &CooldownStatus{ConfiguredSeconds: 120}, status)
	})

	t.Run("pending", func(t *testing.T) {
		status, err := NewMigrator(nil, nil, NewSSM(&fakeSSM{params: map[string]string{
			migrationRequestedAtParam(): time.Now().UTC().Format(time.RFC3339),
		}}), nil, nil, nil).CooldownStatus(ctx)

		require.NoError(t, err)
		require.True(t, status.Pending)
		require.Equal(t, 120, status.ConfiguredSeconds)
		require.Greater(t, status.RemainingSeconds, 0)
		require.LessOrEqual(t, status.RemainingSeconds, 120)
	})

	t.Run("bad timestamp", func(t *testing.T) {
		_, err := NewMigrator(nil, nil, NewSSM(&fakeSSM{params: map[string]string{
			migrationRequestedAtParam(): "not-time",
		}}), nil, nil, nil).CooldownStatus(ctx)

		require.Error(t, err)
	})
}

func TestStartMigrationRequestValidate(t *testing.T) {
	validPCR0 := strings.Repeat("a", 96)

	for _, tc := range []struct {
		name    string
		request StartMigrationRequest
		wantErr bool
	}{
		{name: "missing", request: StartMigrationRequest{}, wantErr: true},
		{name: "short", request: StartMigrationRequest{NewPCR0: "abc"}, wantErr: true},
		{name: "bad hex", request: StartMigrationRequest{NewPCR0: strings.Repeat("z", 96)}, wantErr: true},
		{name: "valid", request: StartMigrationRequest{NewPCR0: validPCR0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.request.Validate()
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestStartMigration(t *testing.T) {
	const migrationKeyID = "fake-kms-key-1"

	oldPCR0 := bytes.Repeat([]byte{0xab}, 48)
	oldPCR0Hex := hex.EncodeToString(oldPCR0)
	newPCR0Bytes := bytes.Repeat([]byte{0xcd}, 48)
	newPCR0 := hex.EncodeToString(newPCR0Bytes)
	dekKey := bytes.Repeat([]byte{0x42}, 32)
	secretPlaintext := bytes.Repeat([]byte{0x11}, 32)
	secret := StaticSecret{
		StaticSecretMetadata: StaticSecretMetadata{Name: "signing_key"},
		Plaintext:            hex.EncodeToString(secretPlaintext),
	}
	secretMeta := []StaticSecretMetadata{secret.StaticSecretMetadata}

	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_PREVIOUS_PCR0", oldPCR0Hex)
	t.Setenv("ENCLAVE_KMS_KEY_LOCKED", "true")

	ctx := context.Background()
	setup := func(t *testing.T, opts ...func(*startMigrationFixture)) *startMigrationFixture {
		t.Helper()
		session := newStatefulNSMSession(t, map[uint][]byte{
			0:                 oldPCR0,
			migrationPCRIndex: make([]byte, 48),
		})
		nsm := &nsmW{nsm: &fakeNSM{session: session}}
		ssmf := &fakeSSM{params: map[string]string{}}
		ssm := NewSSM(ssmf)
		kmsf := newFakeKMS()
		sts := &fakeSTS{arn: testRoleARN}
		fx := &startMigrationFixture{
			session: session,
			ssmf:    ssmf,
			ssm:     ssm,
			kmsf:    kmsf,
		}

		for _, opt := range opts {
			opt(fx)
		}
		enc, err := cbor.CoreDetEncOptions().EncMode()
		require.NoError(t, err)

		fx.m = NewMigrator(
			nsm,
			&kmsW{nsm: nsm, kms: kmsf, sts: sts, keyID: "old-key"},
			fx.ssm,
			&dek{key: dekKey},
			&stateOrigin{nsm: nsm, ssm: ssm, secrets: secretMeta, enc: enc},
			[]StaticSecret{secret},
		).(*migrator)
		return fx
	}

	t.Run("happy path commits raw PCR0 and predecessor validates", func(t *testing.T) {
		fx := setup(t)

		got, err := fx.m.StartMigration(ctx, newPCR0)

		require.NoError(t, err)
		require.Equal(t, oldPCR0Hex, got.PCR0)
		require.Equal(t, []string{"signing_key"}, got.Exported)

		extend := requireExtendPCR(t, fx.session, migrationPCRIndex)
		require.Equal(t, newPCR0Bytes, extend.Data)
		require.Equal(t, pcrExtendFromZero(newPCR0Bytes), fx.session.pcrs[migrationPCRIndex])
		require.True(t, fx.session.locks[migrationPCRIndex])

		require.Equal(t, oldPCR0Hex, fx.ssmf.params[migrationPreviousPCR0Param()])
		require.NotEmpty(t, fx.ssmf.params[migrationPreviousPCR0AttestationParam()])
		require.Equal(t, migrationKeyID, fx.ssmf.params[kmsKeyIDParam()])
		require.NotEmpty(t, fx.ssmf.params[storageDEKCiphertextParam(migrationKeyID)])
		require.NotEmpty(t, fx.ssmf.params[migrationStateOriginReceiptParam(migrationKeyID)])
		requireKMSCiphertextPlaintext(t, fx.kmsf,
			fx.ssmf.params[secretCiphertextParam("signing_key", migrationKeyID)], secretPlaintext)
		require.NoError(t, VerifyKeyPolicyPosture(
			fx.kmsf.keyPolicy(migrationKeyID), []string{oldPCR0Hex, newPCR0}, true,
		))
		require.NotNil(t, fx.session.attestationRoots)

		newNSM := &nsmW{nsm: &fakeNSM{
			session:     newStatefulNSMSession(t, map[uint][]byte{0: newPCR0Bytes}),
			verifyRoots: fx.session.attestationRoots,
		}}
		require.NoError(t, VerifyPredecessorCommitment(ctx, newNSM, fx.ssm))
	})

	t.Run("rejects invalid new PCR0", func(t *testing.T) {
		fx := setup(t)

		_, err := fx.m.StartMigration(ctx, "not-hex")

		require.Error(t, err)
		require.Empty(t, fx.session.requests)
	})

	t.Run("fails when PCR31 already committed to another target", func(t *testing.T) {
		fx := setup(t)
		fx.session.pcrs[migrationPCRIndex] = pcrExtendFromZero(bytes.Repeat([]byte{0xee}, 48))

		_, err := fx.m.StartMigration(ctx, newPCR0)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to commit new PCR0")
	})

	t.Run("fails when migration KMS creation fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.kmsf.createKeyErr = errors.New("create failed")
		})

		_, err := fx.m.StartMigration(ctx, newPCR0)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create migration key")
	})

	t.Run("fails when secret export fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.kmsf.encryptErr = errors.New("encrypt failed")
		})

		_, err := fx.m.StartMigration(ctx, newPCR0)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to re-encrypt secret signing_key")
	})

	t.Run("fails when DEK export fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.ssmf.putErrs = map[string]error{
				storageDEKCiphertextParam(migrationKeyID): errors.New("set failed"),
			}
		})

		_, err := fx.m.StartMigration(ctx, newPCR0)

		require.Error(t, err)
		require.Contains(t, err.Error(), "DEK export failed")
	})

	t.Run("fails when transition receipt write fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.ssmf.putErrs = map[string]error{
				migrationStateOriginReceiptParam(migrationKeyID): errors.New("set failed"),
			}
		})

		_, err := fx.m.StartMigration(ctx, newPCR0)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to write migration-transition receipt")
	})

	t.Run("fails when KMSKeyID write fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.ssmf.putErrs = map[string]error{
				kmsKeyIDParam(): errors.New("set failed"),
			}
		})

		_, err := fx.m.StartMigration(ctx, newPCR0)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to update current KMS key ID")
	})
}

func predecessorNSM(t *testing.T, currentPCR0 []byte, predecessorPCRs map[uint][]byte) NSM {
	t.Helper()
	session := &fakeNSMSession{responses: []response.Response{
		attestationDocumentResponse(buildForgedAttestation(t, map[uint][]byte{0: currentPCR0})),
	}}
	return &nsmW{nsm: &fakeNSM{
		session:      session,
		verifyResult: attestationResult(predecessorPCRs, nil),
	}}
}

type startMigrationFixture struct {
	m       *migrator
	session *fakeNSMSession
	ssmf    *fakeSSM
	ssm     SSM
	kmsf    *fakeKMS
}

func requireKMSCiphertextPlaintext(
	t *testing.T,
	kmsf *fakeKMS,
	ciphertextB64 string,
	want []byte,
) {
	t.Helper()
	blob, err := base64.StdEncoding.DecodeString(ciphertextB64)
	require.NoError(t, err)

	kmsf.mu.Lock()
	got := append([]byte(nil), kmsf.blobs[string(blob)]...)
	kmsf.mu.Unlock()
	require.Equal(t, want, got)
}

func requireExtendPCR(
	t *testing.T,
	session *fakeNSMSession,
	index uint,
) *request.ExtendPCR {
	t.Helper()
	for _, req := range session.requests {
		extend, ok := req.(*request.ExtendPCR)
		if ok && uint(extend.Index) == index {
			return extend
		}
	}
	t.Fatalf("ExtendPCR(%d) was not requested", index)
	return nil
}
