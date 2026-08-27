package runtime

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
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
			unverifiedState{currentPCR0: currentPCR0Bytes},
		)
		require.Error(t, err)
	})

	t.Run("mismatched previous PCR0", func(t *testing.T) {
		err := verifyPredecessorCommitment(
			predecessorNSM(t, currentPCR0Bytes, nil),
			unverifiedState{
				currentPCR0:            currentPCR0Bytes,
				predecessorPCR0:        strings.Repeat("0", 96),
				predecessorAttestation: attestation,
			},
		)
		require.Error(t, err)
	})

	t.Run("rejects an attestation from a different predecessor", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, verifyDocResult(map[uint][]byte{
			0:                 bytes.Repeat([]byte{0x77}, 48),
			migrationPCRIndex: pcrExtendFromZero(currentPCR0Bytes),
		}, nil))

		err := verifyPredecessorCommitment(nsm, unverifiedState{
			startState:             startStateMigration,
			currentPCR0:            currentPCR0Bytes,
			predecessorPCR0:        prevPCR0,
			predecessorAttestation: attestation,
		})

		require.Error(t, err)
	})

	t.Run("requires attestation", func(t *testing.T) {
		err := verifyPredecessorCommitment(
			predecessorNSM(t, currentPCR0Bytes, nil),
			unverifiedState{currentPCR0: currentPCR0Bytes, predecessorPCR0: prevPCR0},
		)
		require.Error(t, err)
	})

	t.Run("wrong PCR31", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, verifyDocResult(map[uint][]byte{
			0:                 prevPCR0Bytes,
			migrationPCRIndex: bytes.Repeat([]byte{0xef}, 48),
		}, nil))

		err := verifyPredecessorCommitment(nsm, unverifiedState{
			currentPCR0:            currentPCR0Bytes,
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
			currentPCR0:            currentPCR0Bytes,
			predecessorPCR0:        strings.ToUpper(prevPCR0),
			predecessorAttestation: attestation,
		})

		require.NoError(t, err)
	})

	t.Run("rejects self as predecessor", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, verifyDocResult(map[uint][]byte{
			0:                 currentPCR0Bytes,
			migrationPCRIndex: pcrExtendFromZero(currentPCR0Bytes),
		}, nil))

		err := verifyPredecessorCommitment(nsm, unverifiedState{
			currentPCR0:            currentPCR0Bytes,
			predecessorPCR0:        hex.EncodeToString(currentPCR0Bytes),
			predecessorAttestation: attestation,
		})

		require.ErrorContains(t, err, "cannot be its own predecessor")
	})
}

func TestMigratorPreviousPCR0Info(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_MIGRATION_INTENT_RETENTION", "87600h")

	ctx := context.Background()
	infoPCR0Bytes := bytes.Repeat([]byte{0x5a}, 48)
	infoPCR0 := hex.EncodeToString(infoPCR0Bytes)

	t.Run("genesis", func(t *testing.T) {
		m, err := NewMigrator(
			kmsTestNSMWithPCR0(t, infoPCR0Bytes), NewSSM(&fakeSSM{}),
			newFakeS3(), migrationIntentTestBucket,
		)
		require.NoError(t, err)
		info, err := m.PreviousPCR0Info(ctx)

		require.NoError(t, err)
		require.Equal(t, &PreviousPCR0Info{PCR0: "genesis"}, info)
	})

	t.Run("recorded predecessor", func(t *testing.T) {
		m, err := NewMigrator(
			kmsTestNSMWithPCR0(t, infoPCR0Bytes), NewSSM(&fakeSSM{params: map[string]string{
				migrationPreviousPCR0Param(infoPCR0):            "abc123",
				migrationPreviousPCR0AttestationParam(infoPCR0): "attestation",
			}}), newFakeS3(), migrationIntentTestBucket)
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
		return &migrator{
			nsm: fx.nsm, intent: fx.log, ssm: NewSSM(&fakeSSM{}), ready: true,
		}, fx
	}
	request := func(t *testing.T, m *migrator, fx *migrationIntentFixture) error {
		t.Helper()
		_, err := requestMigrationTo(t, ctx, m, fx.signer, targetPCR0)
		return err
	}

	t.Run("none", func(t *testing.T) {
		m, fx := setup(t)
		status, err := m.MigrationStatus(ctx)

		require.NoError(t, err)
		require.Equal(t, &MigrationStatus{State: migrationStateNone, SourcePCR0: fx.source}, status)
	})

	t.Run("pending", func(t *testing.T) {
		m, fx := setup(t)
		require.NoError(t, request(t, m, fx))
		status, err := m.MigrationStatus(ctx)

		require.NoError(t, err)
		require.Equal(t, migrationStateCoolingDown, status.State)
		require.Greater(t, status.RemainingSeconds, 0)
		require.LessOrEqual(t, status.RemainingSeconds, 120)
	})

	t.Run("aborted", func(t *testing.T) {
		m, fx := setup(t)
		require.NoError(t, request(t, m, fx))
		_, err := m.handleMigrationRequest(ctx, migrationIntentAborted, "")
		require.NoError(t, err)
		status, err := m.MigrationStatus(ctx)

		require.NoError(t, err)
		require.Equal(t, migrationStateAborted, status.State)
		require.Zero(t, status.RemainingSeconds)
	})

	t.Run("invalid cooldown fails before publication", func(t *testing.T) {
		t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "invalid")
		m, fx := setup(t)

		err := request(t, m, fx)

		require.ErrorContains(t, err, "ENCLAVE_MIGRATION_COOLDOWN")
		require.Empty(t, fx.s3.objects)
	})
}

func TestMigrationStatusAt(t *testing.T) {
	now := time.Date(2026, time.July, 16, 12, 0, 0, 0, time.UTC)
	cooldown := 2 * time.Minute
	head := &migrationIntent{
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

	head.PublishedAt = now.Add(time.Second)
	status = migrationStatusAt(head, 0, now)
	require.Equal(t, migrationStateEligible, status.State)
	require.Zero(t, status.RemainingSeconds)
	require.Equal(t, head.PublishedAt, *status.EligibleAt)
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
	t.Setenv("ENCLAVE_MIGRATION_INTENT_RETENTION", "87600h")
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
			kmsKeyIDParam(oldPCR0Hex):    "old-key",
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
		m, err := newMigrator(nsm, fx.ssm, s3f, migrationIntentBucketName)
		require.NoError(t, err)
		m.Promote(
			&kmsW{nsm: nsm, kms: kmsf, sts: sts, keyID: "old-key"},
			&dek{key: dekKey},
			[]StaticSecret{secret},
		)
		fx.m = m
		return fx
	}
	request := func(t *testing.T, fx *startMigrationFixture, targetPCR0 string) {
		t.Helper()
		status, err := requestMigrationTo(t, ctx, fx.m, fx.session.attestationSign, targetPCR0)
		require.NoError(t, err)
		require.Equal(t, migrationStateEligible, status.State)
	}

	t.Run("happy path commits raw PCR0 and predecessor validates", func(t *testing.T) {
		fx := setup(t)
		fx.ssmf.params[migrationIntentBucketParam()] = "repointed-after-startup"
		request(t, fx, newPCR0)
		// Scope the read assertion below to finalise alone; initiation has its
		// own SSM traffic.
		fx.ssmf.calls = nil

		got, err := fx.m.CompleteMigration(ctx)

		require.NoError(t, err)
		require.Equal(
			t, []string{kmsKeyIDParam(newPCR0)}, fx.ssmf.calls,
			"finalise reads only the successor's commit pointer, never ciphertexts back",
		)
		require.Equal(t, oldPCR0Hex, got.PCR0)
		require.Equal(t, []string{"signing_key"}, got.Exported)

		extend := requireExtendPCR(t, fx.session, migrationPCRIndex)
		require.Equal(t, newPCR0Bytes, extend.Data)
		require.Equal(t, pcrExtendFromZero(newPCR0Bytes), fx.session.pcrs[migrationPCRIndex])
		require.True(t, fx.session.locks[migrationPCRIndex])

		require.Equal(t, oldPCR0Hex, fx.ssmf.params[migrationPreviousPCR0Param(newPCR0)])
		require.NotEmpty(t, fx.ssmf.params[migrationPreviousPCR0AttestationParam(newPCR0)])
		require.Equal(t, migrationKeyID, fx.ssmf.params[kmsKeyIDParam(newPCR0)])
		require.Equal(
			t, "old-key", fx.ssmf.params[kmsKeyIDParam(oldPCR0Hex)],
			"the predecessor's own commit pointer must survive the handoff",
		)
		require.NotEmpty(t, fx.ssmf.params[storageDEKCiphertextParam(migrationKeyID)])
		require.NotEmpty(t, fx.ssmf.params[migrationStateOriginReceiptParam(migrationKeyID)])
		requireKMSCiphertextPlaintext(t, fx.kmsf,
			fx.ssmf.params[secretCiphertextParam("signing_key", migrationKeyID)], secretPlaintext)
		require.NoError(t, VerifyKeyPolicyPosture(
			fx.kmsf.keyPolicy(migrationKeyID), []string{newPCR0}, true,
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
		newReceipt := stateOriginReceiptParam(migrationKeyID, newPCR0)
		require.NotEmpty(t, fx.ssmf.params[newReceipt])

		// The predecessor never adopts the migration key: it has no receipt
		// under it, and the key's policy does not admit its PCR0.
		require.Empty(t, fx.ssmf.params[stateOriginReceiptParam(migrationKeyID, oldPCR0Hex)])
		require.Error(t, VerifyKeyPolicyPosture(
			fx.kmsf.keyPolicy(migrationKeyID), []string{oldPCR0Hex}, true,
		))
		require.NotEmpty(t, fx.ssmf.params[newReceipt])
	})

	t.Run("refuses to re-finalise onto an existing target pointer", func(t *testing.T) {
		fx := setup(t)
		fx.ssmf.params[kmsKeyIDParam(newPCR0)] = "already-committed"
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx)

		require.ErrorIs(t, err, errMigrationAlreadyFinalised)
		require.NotContains(t, err.Error(), "delete")
		// The guard runs before PCR31 and before any key is minted, so a refusal
		// leaves the successor's committed generation exactly as it was.
		require.Equal(t, "already-committed", fx.ssmf.params[kmsKeyIDParam(newPCR0)])
		require.Equal(t, make([]byte, 48), fx.session.pcrs[migrationPCRIndex])
		fx.kmsf.mu.Lock()
		require.Empty(t, fx.kmsf.keys)
		fx.kmsf.mu.Unlock()
	})

	t.Run("losing a cross-process commit race cannot replace the winner", func(t *testing.T) {
		fx := setup(t)
		request(t, fx, newPCR0)
		winner := "key-committed-by-another-predecessor"
		fx.m.ssm = &losingCommitSSM{
			SSM:    fx.ssm,
			key:    kmsKeyIDParam(newPCR0),
			winner: winner,
		}

		_, err := fx.m.CompleteMigration(ctx)

		require.ErrorIs(t, err, errMigrationAlreadyFinalised)
		require.Equal(t, winner, fx.ssmf.params[kmsKeyIDParam(newPCR0)])
		require.NotEqual(t, migrationKeyID, fx.ssmf.params[kmsKeyIDParam(newPCR0)])
	})

	t.Run("predecessor cannot read back what it wrote under the migration key",
		func(t *testing.T) {
			fx := setup(t)
			request(t, fx, newPCR0)

			_, err := fx.m.CompleteMigration(ctx)
			require.NoError(t, err)

			predecessorOnMigrationKey := &kmsW{
				nsm:   fx.m.nsm,
				kms:   fx.kmsf,
				keyID: migrationKeyID,
			}
			_, err = predecessorOnMigrationKey.Decrypt(
				ctx, fx.ssmf.params[storageDEKCiphertextParam(migrationKeyID)],
			)
			require.ErrorContains(t, err, "AccessDenied")
		})

	t.Run("requires a published intent with zero cooldown", func(t *testing.T) {
		fx := setup(t)

		_, err := fx.m.CompleteMigration(ctx)

		require.ErrorIs(t, err, errMigrationIntentAbsent)
		requireNoMigrationSideEffects(t, fx, newPCR0)
	})

	t.Run("rejects active cooldown", func(t *testing.T) {
		t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "2m")
		fx := setup(t)
		status, err := requestMigrationTo(t, ctx, fx.m, fx.session.attestationSign, newPCR0)
		require.NoError(t, err)
		require.Equal(t, migrationStateCoolingDown, status.State)

		_, err = fx.m.CompleteMigration(ctx)

		require.ErrorIs(t, err, errMigrationCooldownActive)
		requireNoMigrationSideEffects(t, fx, newPCR0)
	})

	t.Run("rejects aborted intent", func(t *testing.T) {
		fx := setup(t)
		request(t, fx, newPCR0)
		_, err := fx.m.handleMigrationRequest(ctx, migrationIntentAborted, "")
		require.NoError(t, err)

		_, err = fx.m.CompleteMigration(ctx)

		require.ErrorIs(t, err, errMigrationIntentAborted)
		requireNoMigrationSideEffects(t, fx, newPCR0)
	})

	t.Run("fails closed on intent store error", func(t *testing.T) {
		fx := setup(t)
		fx.s3f.listErr = errors.New("list failed")

		_, err := fx.m.CompleteMigration(ctx)

		require.ErrorContains(t, err, "list failed")
		requireNoMigrationSideEffects(t, fx, newPCR0)
	})

	t.Run("recovers intent after migrator restart", func(t *testing.T) {
		fx := setup(t)
		request(t, fx, newPCR0)
		restarted, err := newMigrator(fx.m.nsm, fx.ssm, fx.s3f, migrationIntentBucketName)
		require.NoError(t, err)
		restarted.Promote(fx.m.kms, fx.m.dek, fx.m.staticSecrets)

		_, err = restarted.CompleteMigration(ctx)

		require.NoError(t, err)
		require.Equal(t, migrationKeyID, fx.ssmf.params[kmsKeyIDParam(newPCR0)])
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
			_, err := fx.m.CompleteMigration(ctx)
			completeDone <- err
		}()
		<-blocking.entered

		requestDone := make(chan error, 1)
		go func() {
			_, err := fx.m.handleMigrationRequest(ctx, migrationIntentAborted, "")
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

		_, err := fx.m.CompleteMigration(ctx)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to commit new PCR0")
	})

	t.Run("fails when migration KMS creation fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.kmsf.createKeyErr = errors.New("create failed")
		})
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create migration key")
	})

	t.Run("fails when secret export fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.kmsf.encryptErr = errors.New("encrypt failed")
		})
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx)

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

		_, err := fx.m.CompleteMigration(ctx)

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

		_, err := fx.m.CompleteMigration(ctx)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to write migration-transition receipt")
	})

	t.Run("fails when KMSKeyID write fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.ssmf.putErrs = map[string]error{
				kmsKeyIDParam(newPCR0): errors.New("set failed"),
			}
		})
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to commit successor KMS key ID")
	})
}

func TestVerifySuccessorAttestation(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x11}, 32)

	t.Run("derives the target PCR0 from the document", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		doc, err := fx.successor.buildSuccessorAttestation(challenge)
		require.NoError(t, err)

		got, err := fx.predecessor.verifySuccessorAttestation(doc, challenge)

		require.NoError(t, err)
		require.Equal(t, fx.targetPCR0, got)
	})

	t.Run("rejects a document answering a different challenge", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		// The essential replay case: a document that was valid for an earlier
		// exchange must not authorise a later one.
		doc, err := fx.successor.buildSuccessorAttestation(bytes.Repeat([]byte{0x22}, 32))
		require.NoError(t, err)

		_, err = fx.predecessor.verifySuccessorAttestation(doc, challenge)

		require.ErrorContains(t, err, "does not answer the issued challenge")
	})

	t.Run("rejects a claim for another deployment", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		t.Setenv("ENCLAVE_DEPLOYMENT", "other-deployment")
		doc, err := fx.successor.buildSuccessorAttestation(challenge)
		require.NoError(t, err)

		t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
		_, err = fx.predecessor.verifySuccessorAttestation(doc, challenge)

		require.ErrorContains(t, err, "user data")
	})

	t.Run("rejects a claim with the wrong schema", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		enc, err := cbor.CoreDetEncOptions().EncMode()
		require.NoError(t, err)
		payload, err := enc.Marshal(successorClaimV1{
			Schema:     "enclave.successor_claim.v2",
			Deployment: "prod",
		})
		require.NoError(t, err)
		raw, _, err := fx.successor.nsm.BuildAttestationDocument(
			WithNonce(challenge), WithUserData(payload),
		)
		require.NoError(t, err)

		_, err = fx.predecessor.verifySuccessorAttestation(
			base64.StdEncoding.EncodeToString(raw), challenge,
		)

		require.ErrorContains(t, err, "user data")
	})

	t.Run("rejects a document signed by an unrelated root", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		now := time.Now()
		stranger := successorMigrator(t, newTestAttestationSigner(
			t, now.Add(-time.Hour), now.Add(time.Hour),
		), bytes.Repeat([]byte{0xcd}, 48))
		doc, err := stranger.buildSuccessorAttestation(challenge)
		require.NoError(t, err)

		_, err = fx.predecessor.verifySuccessorAttestation(doc, challenge)

		require.Error(t, err)
	})

	t.Run("rejects a malformed document", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		_, err := fx.predecessor.verifySuccessorAttestation("not base64", challenge)

		require.Error(t, err)
	})

	t.Run("requires both a document and a challenge", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		_, err := fx.predecessor.verifySuccessorAttestation("", challenge)
		require.ErrorContains(t, err, "successor attestation is required")

		doc, err := fx.successor.buildSuccessorAttestation(challenge)
		require.NoError(t, err)
		_, err = fx.predecessor.verifySuccessorAttestation(doc, nil)
		require.ErrorContains(t, err, "challenge is required")

		_, err = fx.successor.buildSuccessorAttestation(nil)
		require.ErrorContains(t, err, "challenge is required")
	})
}

func TestChallengeRotationRetiresOldAnswers(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "0s")

	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	ssmf := &fakeSSM{}
	m := &migrator{nsm: fx.nsm, intent: fx.log, ssm: NewSSM(ssmf), ready: true}
	target := strings.Repeat("cd", 48)

	own, err := m.ownPCR0()
	require.NoError(t, err)
	require.NoError(t, m.publishChallenge(ctx, own))
	stale, err := m.ssm.MayGet(ctx, migrationChallengeParam(own))
	require.NoError(t, err)

	candidate := successorMigrator(t, fx.signer, mustDecodeHex(t, target))
	doc, err := candidate.buildSuccessorAttestation(mustDecodeHex(t, stale))
	require.NoError(t, err)

	// Force rotation, as the control loop does once the challenge ages out.
	m.mu.Lock()
	m.challengeAt = time.Now().Add(-2 * migrationChallengeRotate)
	m.mu.Unlock()
	require.NoError(t, m.publishChallenge(ctx, own))

	// The answer to the retired challenge is now inert, so no intent is recorded.
	require.NoError(t, m.ssm.Set(
		ctx, successorAttestationParam(own, target), doc, WithAdvancedTier(),
	))
	require.NoError(t, m.adoptCandidate(ctx, own))

	status, err := m.MigrationStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, migrationStateNone, status.State)
	require.Empty(t, fx.s3.objects, "a stale answer must publish no intent")
}

func TestAdoptCandidateRefusesWhileAmbiguous(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "0s")

	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	m := &migrator{nsm: fx.nsm, intent: fx.log, ssm: NewSSM(&fakeSSM{}), ready: true}

	own, err := m.ownPCR0()
	require.NoError(t, err)
	require.NoError(t, m.publishChallenge(ctx, own))
	challenge, err := m.ssm.MayGet(ctx, migrationChallengeParam(own))
	require.NoError(t, err)

	// Two live candidates answer the same challenge. Nobody intended that, so
	// the predecessor keeps serving rather than picking one.
	for _, target := range []string{strings.Repeat("cd", 48), strings.Repeat("ee", 48)} {
		candidate := successorMigrator(t, fx.signer, mustDecodeHex(t, target))
		doc, err := candidate.buildSuccessorAttestation(mustDecodeHex(t, challenge))
		require.NoError(t, err)
		require.NoError(t, m.ssm.Set(
			ctx, successorAttestationParam(own, target), doc, WithAdvancedTier(),
		))
	}

	err = m.adoptCandidate(ctx, own)

	require.ErrorIs(t, err, errMigrationSuccessorAmbiguous)
	require.Empty(t, fx.s3.objects, "an ambiguous round must publish no intent")
}

func TestHandleMigrationRequestDerivesTargetFromAttestation(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "0s")

	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	m := &migrator{nsm: fx.nsm, intent: fx.log, ssm: NewSSM(&fakeSSM{}), ready: true}
	attested := strings.Repeat("cd", 48)

	status, err := requestMigrationTo(t, ctx, m, fx.signer, attested)

	require.NoError(t, err)
	// The recorded target is the successor's own measurement. Nothing the caller
	// sent could have named it.
	require.Equal(t, attested, status.TargetPCR0)
}

func TestCandidateRefusesStateOperations(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "0s")

	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	m := &migrator{nsm: fx.nsm, intent: fx.log, ssm: NewSSM(&fakeSSM{})}

	require.False(t, m.Ready())

	_, err := m.handleMigrationRequest(ctx, migrationIntentRequested, strings.Repeat("cd", 48))
	require.ErrorIs(t, err, errMigrationCandidate)
	require.Empty(t, fx.s3.objects, "a candidate must publish no intent")

	// A candidate can still prove who it is: that is the whole point of the mode.
	doc, err := m.buildSuccessorAttestation(bytes.Repeat([]byte{0x11}, 32))
	require.NoError(t, err)
	require.NotEmpty(t, doc)
}

func TestInboundIntentIsReportedButNeverTrusted(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "0s")

	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	m := &migrator{nsm: fx.nsm, intent: fx.log, ssm: NewSSM(&fakeSSM{}), ready: true}
	target := strings.Repeat("cd", 48)

	_, err := requestMigrationTo(t, ctx, m, fx.signer, target)
	require.NoError(t, err)

	t.Run("a candidate can see who is offering it a handoff", func(t *testing.T) {
		inbound, err := fx.log.InboundIntent(ctx, target)

		require.NoError(t, err)
		require.NotNil(t, inbound)
		require.Equal(t, fx.source, inbound.SourcePCR0)
		require.Equal(t, target, inbound.TargetPCR0)
	})

	t.Run("intents aimed elsewhere are not reported", func(t *testing.T) {
		inbound, err := fx.log.InboundIntent(ctx, strings.Repeat("ee", 48))

		require.NoError(t, err)
		require.Nil(t, inbound)
	})

	t.Run("an inbound intent does not make an enclave adoptable", func(t *testing.T) {
		// The intent log is host-writable, so a record naming us proves nothing.
		// Only the commit pointer may end candidacy.
		setStateOriginTestEnv(t)
		t.Setenv("ENCLAVE_PREVIOUS_PCR0", strings.Repeat("99", 48))

		_, ssm := stateOriginTestSSM(nil)
		_, err := loadUnverifiedState(ctx, ssm, mustDecodeHex(t, target))

		require.ErrorIs(t, err, errAwaitingHandoff)
	})
}

func TestEstablishStateAwaitingHandoffDoesNotRetryFatalErrors(t *testing.T) {
	setStateOriginTestEnv(t)

	// A deployment whose intent bucket is unreadable is broken, not pending: the
	// boot must die rather than spin forever looking like a candidate.
	_, ssm := stateOriginTestSSM(map[string]string{migrationIntentBucketParam(): "UNSET"})
	pcr0 := bytes.Repeat([]byte{0xab}, 48)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := establishStateAwaitingHandoff(
		ctx,
		&nsmW{nsm: &fakeNSM{session: newStatefulNSMSession(t, map[uint][]byte{0: pcr0})}},
		newFakeKMS(),
		&fakeSTS{arn: testRoleARN},
		ssm,
	)

	require.ErrorContains(t, err, "migration intent bucket")
	require.NotErrorIs(t, err, context.DeadlineExceeded)
}

func TestMigrationControlCommitsAndAborts(t *testing.T) {
	const bucketName = "migration-intent-bucket"

	oldPCR0 := bytes.Repeat([]byte{0xab}, 48)
	oldPCR0Hex := hex.EncodeToString(oldPCR0)
	newPCR0 := strings.Repeat("cd", 48)

	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_KMS_KEY_LOCKED", "true")
	t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "0s")
	t.Setenv("ENCLAVE_MIGRATION_INTENT_RETENTION", "87600h")
	t.Setenv("ENCLAVE_SECRETS_CONFIG", `[]`)

	ctx := context.Background()
	setup := func(t *testing.T) (*migrator, *fakeSSM, *fakeNSMSession) {
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
			migrationIntentBucketParam(): bucketName,
			kmsKeyIDParam(oldPCR0Hex):    "old-key",
		}}
		kmsf := newFakeKMS()
		m, err := newMigrator(nsm, NewSSM(ssmf), newFakeS3(), bucketName)
		require.NoError(t, err)
		m.Promote(
			&kmsW{nsm: nsm, kms: kmsf, sts: &fakeSTS{arn: testRoleARN}, keyID: "old-key"},
			&dek{key: bytes.Repeat([]byte{0x42}, 32)},
			nil,
		)
		return m, ssmf, session
	}

	// Standing in for a candidate publishing its answer to the live challenge.
	answer := func(t *testing.T, m *migrator, session *fakeNSMSession, target string) {
		t.Helper()
		challenge, err := m.ssm.MayGet(ctx, migrationChallengeParam(oldPCR0Hex))
		require.NoError(t, err)
		require.NotEmpty(t, challenge, "predecessor must publish a challenge")

		candidate := successorMigrator(t, session.attestationSign, mustDecodeHex(t, target))
		doc, err := candidate.buildSuccessorAttestation(mustDecodeHex(t, challenge))
		require.NoError(t, err)
		require.NoError(t, m.ssm.Set(
			ctx, successorAttestationParam(oldPCR0Hex, target), doc, WithAdvancedTier(),
		))
	}

	t.Run("a candidate answering is the whole trigger", func(t *testing.T) {
		m, ssmf, session := setup(t)

		// Round one publishes a challenge; nobody has answered yet.
		require.NoError(t, m.advanceMigration(ctx))
		require.Empty(t, ssmf.params[kmsKeyIDParam(newPCR0)])

		answer(t, m, session, newPCR0)

		// Round two adopts the answer, round three commits once eligible.
		require.NoError(t, m.advanceMigration(ctx))
		require.NoError(t, m.advanceMigration(ctx))

		require.NotEmpty(t, ssmf.params[kmsKeyIDParam(newPCR0)],
			"the successor's commit pointer must appear")
		require.Equal(t, "old-key", ssmf.params[kmsKeyIDParam(oldPCR0Hex)],
			"the predecessor's own pointer must survive")
	})

	t.Run("an operator abort stops the commit", func(t *testing.T) {
		m, ssmf, session := setup(t)

		require.NoError(t, m.advanceMigration(ctx))
		answer(t, m, session, newPCR0)
		require.NoError(t, m.advanceMigration(ctx))

		// Written before the cooldown elapses; this is the only operator control.
		ssmf.params[migrationAbortParam(oldPCR0Hex)] = newPCR0

		require.NoError(t, m.advanceMigration(ctx))

		require.Empty(t, ssmf.params[kmsKeyIDParam(newPCR0)],
			"an aborted handoff must not commit")
		status, err := m.MigrationStatus(ctx)
		require.NoError(t, err)
		require.Equal(t, migrationStateAborted, status.State)
	})

	t.Run("an abort naming a different target does not apply", func(t *testing.T) {
		m, ssmf, session := setup(t)

		require.NoError(t, m.advanceMigration(ctx))
		answer(t, m, session, newPCR0)
		require.NoError(t, m.advanceMigration(ctx))

		ssmf.params[migrationAbortParam(oldPCR0Hex)] = strings.Repeat("ee", 48)

		require.NoError(t, m.advanceMigration(ctx))

		require.NotEmpty(t, ssmf.params[kmsKeyIDParam(newPCR0)])
	})
}

func TestCandidateAnswersPublishedChallenges(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_MIGRATION_INTENT_RETENTION", "87600h")

	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	ssmf := &fakeSSM{params: map[string]string{}}
	m := &migrator{nsm: fx.nsm, intent: fx.log, ssm: NewSSM(ssmf)}

	predecessor := strings.Repeat("11", 48)
	ssmf.params[migrationChallengeParam(predecessor)] = strings.Repeat("ab", 32)

	require.NoError(t, m.answerChallenges(ctx))

	// The candidate publishes under the challenging enclave's prefix, so a
	// predecessor finds only answers to its own challenge.
	doc := ssmf.params[successorAttestationParam(predecessor, fx.source)]
	require.NotEmpty(t, doc)

	target, err := m.verifySuccessorAttestation(
		doc, mustDecodeHex(t, strings.Repeat("ab", 32)),
	)
	require.NoError(t, err)
	require.Equal(t, fx.source, target)
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

// losingCommitSSM simulates another predecessor winning after this process's
// initial MayGet but before its final create-only write.
type losingCommitSSM struct {
	SSM
	key    string
	winner string
}

func (s *losingCommitSSM) SetIfAbsent(
	ctx context.Context,
	key, val string,
	opts ...SSMSetOption,
) (bool, error) {
	if key != s.key {
		return s.SSM.SetIfAbsent(ctx, key, val, opts...)
	}
	if err := s.SSM.Set(ctx, key, s.winner); err != nil {
		return false, err
	}
	return false, nil
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

func requireNoMigrationSideEffects(
	t *testing.T,
	fx *startMigrationFixture,
	targetPCR0 string,
) {
	t.Helper()
	require.Equal(t, make([]byte, 48), fx.session.pcrs[migrationPCRIndex])
	require.False(t, fx.session.locks[migrationPCRIndex])

	fx.kmsf.mu.Lock()
	require.Empty(t, fx.kmsf.keys)
	require.Empty(t, fx.kmsf.blobs)
	fx.kmsf.mu.Unlock()

	require.Empty(t, fx.ssmf.params[kmsKeyIDParam(targetPCR0)])
	require.Empty(t, fx.ssmf.params[migrationPreviousPCR0Param(targetPCR0)])
	require.Empty(t, fx.ssmf.params[migrationPreviousPCR0AttestationParam(targetPCR0)])
	for name := range fx.ssmf.params {
		require.NotContains(t, name, "/Ciphertext/")
		require.NotContains(t, name, "StateOriginReceipt/")
	}
}

// successorMigrator stands in for a live candidate. It signs with the
// predecessor's test root, mirroring production where every enclave chains to
// the same AWS Nitro root — otherwise the predecessor could not verify any
// document but its own, and the exchange would be untestable for the wrong
// reason. Only m.nsm is populated, which is all the claim methods reach for.
func successorMigrator(t *testing.T, signer *testAttestationSigner, pcr0 []byte) *migrator {
	t.Helper()
	return &migrator{nsm: &nsmW{nsm: &fakeNSM{session: &fakeNSMSession{
		t:                t,
		pcrs:             map[uint][]byte{0: append([]byte(nil), pcr0...)},
		locks:            map[uint]bool{},
		attestationSign:  signer,
		attestationRoots: x509.NewCertPool(),
	}}}}
}

// requestMigrationTo drives the real initiation exchange through SSM: the
// predecessor publishes a challenge, a candidate answers it, and the predecessor
// adopts that answer. Nothing here names the target to the predecessor.
func requestMigrationTo(
	t *testing.T,
	ctx context.Context,
	m *migrator,
	predecessorSigner *testAttestationSigner,
	targetPCR0 string,
) (*MigrationStatus, error) {
	t.Helper()

	own, err := m.ownPCR0()
	require.NoError(t, err)
	require.NoError(t, m.publishChallenge(ctx, own))

	challenge, err := m.ssm.MayGet(ctx, migrationChallengeParam(own))
	require.NoError(t, err)

	candidate := successorMigrator(t, predecessorSigner, mustDecodeHex(t, targetPCR0))
	doc, err := candidate.buildSuccessorAttestation(mustDecodeHex(t, challenge))
	require.NoError(t, err)
	require.NoError(t, m.ssm.Set(
		ctx, successorAttestationParam(own, targetPCR0), doc, WithAdvancedTier(),
	))

	if err := m.adoptCandidate(ctx, own); err != nil {
		return nil, err
	}
	return m.MigrationStatus(ctx)
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(s)
	require.NoError(t, err)
	return decoded
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

// successorTestFixture pairs a predecessor with a would-be successor signing
// under the same root, as real enclaves share the AWS Nitro root.
type successorTestFixture struct {
	predecessor *migrator
	signer      *testAttestationSigner
	successor   *migrator
	targetPCR0  string
}

func newSuccessorTestFixture(t *testing.T) *successorTestFixture {
	t.Helper()
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")

	session := newStatefulNSMSession(t, map[uint][]byte{0: bytes.Repeat([]byte{0xab}, 48)})
	predecessor := &migrator{nsm: &nsmW{nsm: &fakeNSM{
		session:     session,
		verifyRoots: session.attestationSign.roots,
	}}}
	target := bytes.Repeat([]byte{0xcd}, 48)

	return &successorTestFixture{
		predecessor: predecessor,
		signer:      session.attestationSign,
		successor:   successorMigrator(t, session.attestationSign, target),
		targetPCR0:  hex.EncodeToString(target),
	}
}
