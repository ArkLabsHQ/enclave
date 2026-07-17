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

	"github.com/hf/nitrite"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
	"github.com/stretchr/testify/require"
)

func TestVerifyPredecessorCommitment_Genesis(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_PREVIOUS_PCR0", "genesis")

	t.Run("no predecessor", func(t *testing.T) {
		err := verifyPredecessorCommitment(nil, unverifiedState{})
		require.NoError(t, err)
	})

	t.Run("rejects predecessor", func(t *testing.T) {
		errs := verifyPredecessorCommitment(nil, unverifiedState{
			predecessorPCR0:        "abc123",
			predecessorAttestation: "attestation",
		})
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

	t.Run("missing previous PCR0", func(t *testing.T) {
		err := verifyPredecessorCommitment(
			predecessorNSM(t, currentPCR0Bytes, nil),
			unverifiedState{},
		)
		require.Error(t, err)
	})

	t.Run("mismatched previous PCR0", func(t *testing.T) {
		err := verifyPredecessorCommitment(
			predecessorNSM(t, currentPCR0Bytes, nil),
			unverifiedState{
				predecessorPCR0:        strings.Repeat("0", 96),
				predecessorAttestation: attestation,
			},
		)
		require.Error(t, err)
	})

	t.Run("requires attestation", func(t *testing.T) {
		err := verifyPredecessorCommitment(
			predecessorNSM(t, currentPCR0Bytes, nil),
			unverifiedState{predecessorPCR0: prevPCR0},
		)
		require.Error(t, err)
	})

	t.Run("wrong PCR31", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, verifyDocResult(map[uint][]byte{
			0:                 prevPCR0Bytes,
			migrationPCRIndex: bytes.Repeat([]byte{0xef}, 48),
		}, nil))

		err := verifyPredecessorCommitment(nsm, unverifiedState{
			predecessorPCR0:        prevPCR0,
			predecessorAttestation: attestation,
		})

		require.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, verifyDocResult(map[uint][]byte{
			0:                 prevPCR0Bytes,
			migrationPCRIndex: pcrExtendFromZero(currentPCR0Bytes),
		}, nil))

		err := verifyPredecessorCommitment(nsm, unverifiedState{
			predecessorPCR0:        strings.ToUpper(prevPCR0),
			predecessorAttestation: attestation,
		})

		require.NoError(t, err)
	})

	t.Run("rollback-to-self ignores PCR31 target", func(t *testing.T) {
		failedTargetPCR0Bytes := bytes.Repeat([]byte{0xef}, 48)

		// The first arg is the fresh rollback boot PCR0; the map is the stored
		// predecessor attestation from the earlier v2 -> v3 migration attempt.
		nsm := predecessorNSM(t, currentPCR0Bytes, verifyDocResult(map[uint][]byte{
			0:                 currentPCR0Bytes,
			migrationPCRIndex: pcrExtendFromZero(failedTargetPCR0Bytes),
		}, nil))

		err := verifyPredecessorCommitment(nsm, unverifiedState{
			predecessorPCR0:        hex.EncodeToString(currentPCR0Bytes),
			predecessorAttestation: attestation,
		})

		require.NoError(t, err)
	})
}

func TestMigratorPreviousPCR0Info(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")

	ctx := context.Background()

	t.Run("genesis", func(t *testing.T) {
		m, err := NewMigrator(
			nil, nil, NewSSM(&fakeSSM{}), newFakeS3(), nil, nil, migrationIntentTestBucket,
		)
		require.NoError(t, err)
		info, err := m.PreviousPCR0Info(ctx)

		require.NoError(t, err)
		require.Equal(t, &PreviousPCR0Info{PCR0: "genesis"}, info)
	})

	t.Run("recorded predecessor", func(t *testing.T) {
		m, err := NewMigrator(nil, nil, NewSSM(&fakeSSM{params: map[string]string{
			migrationPreviousPCR0Param():            "abc123",
			migrationPreviousPCR0AttestationParam(): "attestation",
		}}), newFakeS3(), nil, nil, migrationIntentTestBucket)
		require.NoError(t, err)
		info, err := m.PreviousPCR0Info(ctx)

		require.NoError(t, err)
		require.Equal(t, &PreviousPCR0Info{PCR0: "abc123", Attestation: "attestation"}, info)
	})
}

func TestMigratorMigrationStatus(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "2m")

	ctx := context.Background()
	targetPCR0 := strings.Repeat("cd", 48)
	setup := func(t *testing.T) (*migrator, *migrationIntentFixture) {
		t.Helper()
		fx := newMigrationIntentFixture(t)
		return &migrator{nsm: fx.nsm, intent: fx.log}, fx
	}

	t.Run("none", func(t *testing.T) {
		m, fx := setup(t)
		status, err := m.MigrationStatus(ctx)

		require.NoError(t, err)
		require.Equal(t, &MigrationStatus{State: migrationStateNone, SourcePCR0: fx.source}, status)
	})

	t.Run("pending", func(t *testing.T) {
		m, _ := setup(t)
		_, err := m.HandleMigrationRequest(ctx, migrationIntentRequested, targetPCR0)
		require.NoError(t, err)
		status, err := m.MigrationStatus(ctx)

		require.NoError(t, err)
		require.Equal(t, migrationStateCoolingDown, status.State)
		require.Greater(t, status.RemainingSeconds, 0)
		require.LessOrEqual(t, status.RemainingSeconds, 120)
	})

	t.Run("aborted", func(t *testing.T) {
		m, _ := setup(t)
		_, err := m.HandleMigrationRequest(ctx, migrationIntentRequested, targetPCR0)
		require.NoError(t, err)
		_, err = m.HandleMigrationRequest(ctx, migrationIntentAborted, "")
		require.NoError(t, err)
		status, err := m.MigrationStatus(ctx)

		require.NoError(t, err)
		require.Equal(t, migrationStateAborted, status.State)
		require.Zero(t, status.RemainingSeconds)
	})

	t.Run("invalid cooldown fails before publication", func(t *testing.T) {
		t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "invalid")
		m, fx := setup(t)

		_, err := m.HandleMigrationRequest(ctx, migrationIntentRequested, targetPCR0)

		require.ErrorContains(t, err, "ENCLAVE_MIGRATION_COOLDOWN")
		require.Empty(t, fx.s3.objects)
	})
}

func TestMigrationStatusAt(t *testing.T) {
	now := time.Date(2026, time.July, 16, 12, 0, 0, 0, time.UTC)
	cooldown := 2 * time.Minute
	head := &migrationIntentHead{
		SourcePCR0:  strings.Repeat("ab", 48),
		TargetPCR0:  strings.Repeat("cd", 48),
		Action:      migrationIntentRequested,
		Sequence:    1,
		PublishedAt: now.Add(-cooldown),
	}

	status := migrationStatusAt(head, cooldown, now)
	require.Equal(t, migrationStateEligible, status.State)
	require.Zero(t, status.RemainingSeconds)
	require.Equal(t, now, *status.EligibleAt)

	status = migrationStatusAt(head, cooldown, now.Add(-time.Nanosecond))
	require.Equal(t, migrationStateCoolingDown, status.State)
	require.Equal(t, 1, status.RemainingSeconds)
}

func TestCompleteMigrationRequestValidate(t *testing.T) {
	validPCR0 := strings.Repeat("a", 96)

	for _, tc := range []struct {
		name    string
		request CompleteMigrationRequest
		wantErr bool
	}{
		{name: "missing", request: CompleteMigrationRequest{}, wantErr: true},
		{name: "short", request: CompleteMigrationRequest{NewPCR0: "abc"}, wantErr: true},
		{name: "bad hex", request: CompleteMigrationRequest{NewPCR0: strings.Repeat("z", 96)}, wantErr: true},
		{name: "valid", request: CompleteMigrationRequest{NewPCR0: validPCR0}},
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

func TestMigrationRequestValidate(t *testing.T) {
	validPCR0 := strings.Repeat("a", 96)

	for _, tc := range []struct {
		name    string
		request MigrationRequest
		wantErr bool
	}{
		{name: "missing action", request: MigrationRequest{}, wantErr: true},
		{name: "unknown action", request: MigrationRequest{Action: "replace"}, wantErr: true},
		{name: "requested without target", request: MigrationRequest{Action: migrationIntentRequested}, wantErr: true},
		{name: "requested with invalid target", request: MigrationRequest{Action: migrationIntentRequested, TargetPCR0: "abc"}, wantErr: true},
		{name: "requested", request: MigrationRequest{Action: migrationIntentRequested, TargetPCR0: validPCR0}},
		{name: "aborted", request: MigrationRequest{Action: migrationIntentAborted}},
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

func TestCompleteMigration(t *testing.T) {
	const migrationKeyID = "fake-kms-key-1"
	const migrationIntentBucketName = "migration-intent-bucket"

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

	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_PREVIOUS_PCR0", oldPCR0Hex)
	t.Setenv("ENCLAVE_KMS_KEY_LOCKED", "true")
	t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "0s")
	t.Setenv("ENCLAVE_SECRETS_CONFIG", `[{"name":"signing_key"}]`)

	ctx := context.Background()
	setup := func(t *testing.T, opts ...func(*startMigrationFixture)) *startMigrationFixture {
		t.Helper()
		session := newStatefulNSMSession(t, map[uint][]byte{
			0:                 oldPCR0,
			migrationPCRIndex: make([]byte, 48),
		})
		nsm := &nsmW{nsm: &fakeNSM{
			session:     session,
			verifyRoots: session.attestationSign.roots,
		}}
		ssmf := &fakeSSM{params: map[string]string{
			migrationIntentBucketParam(): migrationIntentBucketName,
		}}
		ssm := NewSSM(ssmf)
		s3f := newFakeS3()
		kmsf := newFakeKMS()
		sts := &fakeSTS{arn: testRoleARN}
		fx := &startMigrationFixture{
			session: session,
			ssmf:    ssmf,
			ssm:     ssm,
			s3f:     s3f,
			kmsf:    kmsf,
		}

		for _, opt := range opts {
			opt(fx)
		}
		m, err := NewMigrator(
			nsm,
			&kmsW{nsm: nsm, kms: kmsf, sts: sts, keyID: "old-key"},
			fx.ssm,
			s3f,
			&dek{key: dekKey},
			[]StaticSecret{secret},
			migrationIntentBucketName,
		)
		require.NoError(t, err)
		fx.m = m.(*migrator)
		return fx
	}
	request := func(t *testing.T, fx *startMigrationFixture, targetPCR0 string) {
		t.Helper()
		status, err := fx.m.HandleMigrationRequest(
			ctx, migrationIntentRequested, targetPCR0,
		)
		require.NoError(t, err)
		require.Equal(t, migrationStateEligible, status.State)
	}

	t.Run("happy path commits raw PCR0 and predecessor validates", func(t *testing.T) {
		fx := setup(t)
		fx.ssmf.params[migrationIntentBucketParam()] = "repointed-after-startup"
		request(t, fx, newPCR0)

		got, err := fx.m.CompleteMigration(ctx, newPCR0)

		require.NoError(t, err)
		require.Empty(t, fx.ssmf.calls, "migration must not read successor ciphertexts back")
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

		fx.ssmf.params[migrationIntentBucketParam()] = migrationIntentBucketName
		newNSM := &nsmW{nsm: &fakeNSM{
			session:     newStatefulNSMSession(t, map[uint][]byte{0: newPCR0Bytes}),
			verifyRoots: fx.session.attestationRoots,
		}}
		established, err := EstablishState(
			ctx,
			newNSM,
			fx.kmsf,
			&fakeSTS{},
			fx.ssm,
		)
		require.NoError(t, err)
		require.Equal(t, dekKey, established.dek.(*dek).key)
		require.Equal(t, secret.Plaintext, established.secrets[0].Plaintext)
		require.Equal(t, migrationIntentBucketName, established.migrationIntentBucketName)
		require.NotEmpty(t, fx.ssmf.params[stateOriginReceiptParam(migrationKeyID)])
	})

	t.Run("rejects invalid new PCR0", func(t *testing.T) {
		fx := setup(t)

		_, err := fx.m.CompleteMigration(ctx, "not-hex")

		require.Error(t, err)
		require.Empty(t, fx.session.requests)
	})

	t.Run("requires a published intent with zero cooldown", func(t *testing.T) {
		fx := setup(t)

		_, err := fx.m.CompleteMigration(ctx, newPCR0)

		require.ErrorIs(t, err, errMigrationIntentAbsent)
		requireNoMigrationSideEffects(t, fx)
	})

	t.Run("rejects active cooldown", func(t *testing.T) {
		t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "2m")
		fx := setup(t)
		status, err := fx.m.HandleMigrationRequest(ctx, migrationIntentRequested, newPCR0)
		require.NoError(t, err)
		require.Equal(t, migrationStateCoolingDown, status.State)

		_, err = fx.m.CompleteMigration(ctx, newPCR0)

		require.ErrorIs(t, err, errMigrationCooldownActive)
		requireNoMigrationSideEffects(t, fx)
	})

	t.Run("rejects aborted intent", func(t *testing.T) {
		fx := setup(t)
		request(t, fx, newPCR0)
		_, err := fx.m.HandleMigrationRequest(ctx, migrationIntentAborted, "")
		require.NoError(t, err)

		_, err = fx.m.CompleteMigration(ctx, newPCR0)

		require.ErrorIs(t, err, errMigrationIntentAborted)
		requireNoMigrationSideEffects(t, fx)
	})

	t.Run("rejects mismatched target", func(t *testing.T) {
		fx := setup(t)
		request(t, fx, strings.Repeat("ef", 48))

		_, err := fx.m.CompleteMigration(ctx, newPCR0)

		require.ErrorIs(t, err, errMigrationIntentTargetMismatch)
		requireNoMigrationSideEffects(t, fx)
	})

	t.Run("fails closed on intent store error", func(t *testing.T) {
		fx := setup(t)
		fx.m.intent.s3 = &migrationIntentS3Failure{
			fakeS3:  fx.s3f,
			listErr: errors.New("list failed"),
		}

		_, err := fx.m.CompleteMigration(ctx, newPCR0)

		require.ErrorContains(t, err, "list failed")
		requireNoMigrationSideEffects(t, fx)
	})

	t.Run("recovers intent after migrator restart", func(t *testing.T) {
		fx := setup(t)
		request(t, fx, newPCR0)
		restarted, err := NewMigrator(
			fx.m.nsm,
			fx.m.kms,
			fx.ssm,
			fx.s3f,
			fx.m.dek,
			fx.m.staticSecrets,
			migrationIntentBucketName,
		)
		require.NoError(t, err)

		_, err = restarted.CompleteMigration(ctx, newPCR0)

		require.NoError(t, err)
		require.Equal(t, migrationKeyID, fx.ssmf.params[kmsKeyIDParam()])
	})

	t.Run("serializes request and completion", func(t *testing.T) {
		fx := setup(t)
		request(t, fx, newPCR0)
		blocking := &blockingPrimaryKMS{
			PrimaryKMS: fx.m.kms,
			entered:    make(chan struct{}),
			release:    make(chan struct{}),
		}
		fx.m.kms = blocking

		completeDone := make(chan error, 1)
		go func() {
			_, err := fx.m.CompleteMigration(ctx, newPCR0)
			completeDone <- err
		}()
		<-blocking.entered

		requestDone := make(chan error, 1)
		go func() {
			_, err := fx.m.HandleMigrationRequest(
				ctx, migrationIntentRequested, strings.Repeat("ef", 48),
			)
			requestDone <- err
		}()

		select {
		case err := <-requestDone:
			t.Fatalf("request completed during finalisation: %v", err)
		case <-time.After(50 * time.Millisecond):
		}

		close(blocking.release)
		require.ErrorContains(t, <-completeDone, "blocked migration KMS creation")
		require.NoError(t, <-requestDone)
	})

	t.Run("fails when PCR31 already committed to another target", func(t *testing.T) {
		fx := setup(t)
		fx.session.pcrs[migrationPCRIndex] = pcrExtendFromZero(bytes.Repeat([]byte{0xee}, 48))
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx, newPCR0)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to commit new PCR0")
	})

	t.Run("fails when migration KMS creation fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.kmsf.createKeyErr = errors.New("create failed")
		})
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx, newPCR0)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create migration key")
	})

	t.Run("fails when secret export fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.kmsf.encryptErr = errors.New("encrypt failed")
		})
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx, newPCR0)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to re-encrypt secret signing_key")
	})

	t.Run("fails when DEK export fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.ssmf.putErrs = map[string]error{
				storageDEKCiphertextParam(migrationKeyID): errors.New("set failed"),
			}
		})
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx, newPCR0)

		require.Error(t, err)
		require.Contains(t, err.Error(), "DEK export failed")
	})

	t.Run("fails when transition receipt write fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.ssmf.putErrs = map[string]error{
				migrationStateOriginReceiptParam(migrationKeyID): errors.New("set failed"),
			}
		})
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx, newPCR0)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to write migration-transition receipt")
	})

	t.Run("fails when KMSKeyID write fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.ssmf.putErrs = map[string]error{
				kmsKeyIDParam(): errors.New("set failed"),
			}
		})
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx, newPCR0)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to update current KMS key ID")
	})
}

func predecessorNSM(t *testing.T, currentPCR0 []byte, verifyResult *nitrite.Result) NSM {
	t.Helper()
	session := &fakeNSMSession{responses: []response.Response{
		attestationDocumentResponse(buildForgedAttestation(t, map[uint][]byte{0: currentPCR0})),
	}}
	return &nsmW{nsm: &fakeNSM{
		session:      session,
		verifyResult: verifyResult,
	}}
}

type startMigrationFixture struct {
	m       *migrator
	session *fakeNSMSession
	ssmf    *fakeSSM
	ssm     SSM
	s3f     *fakeS3
	kmsf    *fakeKMS
}

type blockingPrimaryKMS struct {
	PrimaryKMS
	entered chan struct{}
	release chan struct{}
}

func (k *blockingPrimaryKMS) CreateMigrationKMS(
	context.Context,
	string,
) (KMS, error) {
	close(k.entered)
	<-k.release
	return nil, errors.New("blocked migration KMS creation")
}

func requireNoMigrationSideEffects(t *testing.T, fx *startMigrationFixture) {
	t.Helper()
	require.Equal(t, make([]byte, 48), fx.session.pcrs[migrationPCRIndex])
	require.False(t, fx.session.locks[migrationPCRIndex])

	fx.kmsf.mu.Lock()
	require.Empty(t, fx.kmsf.keys)
	require.Empty(t, fx.kmsf.blobs)
	fx.kmsf.mu.Unlock()

	require.Empty(t, fx.ssmf.params[kmsKeyIDParam()])
	require.Empty(t, fx.ssmf.params[migrationPreviousPCR0Param()])
	require.Empty(t, fx.ssmf.params[migrationPreviousPCR0AttestationParam()])
	for name := range fx.ssmf.params {
		require.NotContains(t, name, "/Ciphertext/")
		require.NotContains(t, name, "StateOriginReceipt/")
	}
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
