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

func TestMigrationBootVerifiesPredecessor(t *testing.T) {
	prevPCR0Bytes := bytes.Repeat([]byte{0xab}, 48)
	currentPCR0Bytes := bytes.Repeat([]byte{0xcd}, 48)
	prevPCR0 := hex.EncodeToString(prevPCR0Bytes)
	attestation := base64.StdEncoding.EncodeToString([]byte("predecessor attestation"))

	t.Run("SSM predecessor must match the PCR0 baked into the EIF", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, verifyDocResult(map[uint][]byte{
			0:                 prevPCR0Bytes,
			migrationPCRIndex: pcrExtendFromZero(currentPCR0Bytes),
		}, nil))

		err := (&migrationBoot{}).verify(nsm, &bootState{
			cfg:                    testConfigWithPreviousPCR0(prevPCR0),
			currentPCR0:            currentPCR0Bytes,
			kmsKeyID:               "migration-key",
			predecessorPCR0:        strings.Repeat("0", 96),
			predecessorAttestation: attestation,
			migrationReceipt:       "transition",
		})

		require.Error(t, err)
	})

	t.Run("attested PCR0 must match the claimed predecessor", func(t *testing.T) {
		claimedPCR0Bytes := bytes.Repeat([]byte{0xef}, 48)
		claimedPCR0 := hex.EncodeToString(claimedPCR0Bytes)
		nsm := predecessorNSM(t, currentPCR0Bytes, verifyDocResult(map[uint][]byte{
			0:                 prevPCR0Bytes,
			migrationPCRIndex: pcrExtendFromZero(currentPCR0Bytes),
		}, nil))

		err := (&migrationBoot{}).verify(nsm, &bootState{
			cfg:                    testConfigWithPreviousPCR0(claimedPCR0),
			currentPCR0:            currentPCR0Bytes,
			kmsKeyID:               "migration-key",
			predecessorPCR0:        claimedPCR0,
			predecessorAttestation: attestation,
			migrationReceipt:       "transition",
		})

		require.Error(t, err)
	})

	t.Run("wrong PCR31", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, verifyDocResult(map[uint][]byte{
			0:                 prevPCR0Bytes,
			migrationPCRIndex: bytes.Repeat([]byte{0xef}, 48),
		}, nil))

		err := (&migrationBoot{}).verify(nsm, &bootState{
			cfg:                    testConfigWithPreviousPCR0(prevPCR0),
			currentPCR0:            currentPCR0Bytes,
			kmsKeyID:               "migration-key",
			predecessorPCR0:        prevPCR0,
			predecessorAttestation: attestation,
			migrationReceipt:       "transition",
		})

		require.Error(t, err)
	})

	t.Run("non-empty user data", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, verifyDocResult(map[uint][]byte{
			0:                 prevPCR0Bytes,
			migrationPCRIndex: pcrExtendFromZero(currentPCR0Bytes),
		}, []byte("unexpected")))

		err := (&migrationBoot{}).verify(nsm, &bootState{
			cfg:                    testConfigWithPreviousPCR0(prevPCR0),
			currentPCR0:            currentPCR0Bytes,
			kmsKeyID:               "migration-key",
			predecessorPCR0:        prevPCR0,
			predecessorAttestation: attestation,
			migrationReceipt:       "transition",
		})

		require.ErrorContains(t, err, "attested user data does not match")
	})

	t.Run("success", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, verifyDocResult(map[uint][]byte{
			0:                 prevPCR0Bytes,
			migrationPCRIndex: pcrExtendFromZero(currentPCR0Bytes),
		}, nil))

		err := (&migrationBoot{}).verify(nsm, &bootState{
			cfg:                    testConfigWithPreviousPCR0(prevPCR0),
			currentPCR0:            currentPCR0Bytes,
			kmsKeyID:               "migration-key",
			predecessorPCR0:        strings.ToUpper(prevPCR0),
			predecessorAttestation: attestation,
			migrationReceipt:       "transition",
		})

		require.NoError(t, err)
	})

	t.Run("rejects self as predecessor", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, verifyDocResult(map[uint][]byte{
			0:                 currentPCR0Bytes,
			migrationPCRIndex: pcrExtendFromZero(currentPCR0Bytes),
		}, nil))

		err := (&migrationBoot{}).verify(nsm, &bootState{
			cfg:                    testConfigWithPreviousPCR0(prevPCR0),
			currentPCR0:            currentPCR0Bytes,
			kmsKeyID:               "migration-key",
			predecessorPCR0:        hex.EncodeToString(currentPCR0Bytes),
			predecessorAttestation: attestation,
			migrationReceipt:       "transition",
		})

		require.ErrorContains(t, err, "cannot be its own predecessor")
	})
}

func TestMigratorPreviousPCR0Info(t *testing.T) {
	ctx := context.Background()
	infoPCR0Bytes := bytes.Repeat([]byte{0x5a}, 48)
	infoPCR0 := hex.EncodeToString(infoPCR0Bytes)

	t.Run("genesis", func(t *testing.T) {
		m, err := NewMigrator(
			testCfg,
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
			testCfg,
			kmsTestNSMWithPCR0(t, infoPCR0Bytes), NewSSM(&fakeSSM{params: map[string]string{
				testCfg.migrationPreviousPCR0Param(infoPCR0):            "abc123",
				testCfg.migrationPreviousPCR0AttestationParam(infoPCR0): "attestation",
			}}), newFakeS3(), migrationIntentTestBucket,
		)
		require.NoError(t, err)
		info, err := m.PreviousPCR0Info(ctx)

		require.NoError(t, err)
		require.Equal(t, &PreviousPCR0Info{PCR0: "abc123", Attestation: "attestation"}, info)
	})
}

func TestMigratorMigrationStatus(t *testing.T) {
	ctx := context.Background()
	targetPCR0 := strings.Repeat("cd", 48)
	setup := func(t *testing.T) (*migrator, *migrationIntentFixture) {
		t.Helper()
		fx := newMigrationIntentFixture(t)
		// An explicit cooldown rather than a posture's: this test is about the
		// status machine, not about which value the config picks.
		cfg := newTestConfig("prod", "app", false)
		cfg.MigrationCooldown = 2 * time.Minute
		return &migrator{
			cfg: cfg, nsm: fx.nsm, intent: fx.log, ssm: NewSSM(&fakeSSM{}), ready: true,
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

func migrationTestCfg() *Config {
	cfg := newTestConfig("prod", "app", false)
	cfg.MigrationCooldown = 0
	return cfg
}

func successorTestCfg(prev string) *Config {
	cfg := migrationTestCfg()
	cfg.PreviousPCR0 = prev
	return cfg
}

func TestCompleteMigration(t *testing.T) {
	const migrationKeyID = "fake-kms-key-1"
	migrationIntentBucketName := migrationIntentBucketName(testCfg, fakeSTSAccountID)

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
			testCfg.kmsKeyIDParam(oldPCR0Hex): "old-key",
		}}
		ssm := NewSSM(ssmf)
		s3f := newFakeS3()
		genesis, err := newGenesisLog(testCfg, s3f, nsm, migrationIntentBucketName)
		require.NoError(t, err)
		_, err = genesis.CommitGenesis(ctx, oldPCR0Hex)
		require.NoError(t, err)
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
		m, err := newMigrator(migrationTestCfg(), nsm, fx.ssm, s3f, migrationIntentBucketName)
		require.NoError(t, err)
		m.Promote(
			&kmsW{cfg: testCfg, nsm: nsm, kms: kmsf, sts: sts, keyID: "old-key"},
			&dek{key: dekKey},
			[]StaticSecret{secret},
			newTestTLSKey(t),
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
		request(t, fx, newPCR0)
		// Scope the read assertion below to finalise alone; initiation has its
		// own SSM traffic.
		fx.ssmf.calls = nil

		got, err := fx.m.CompleteMigration(ctx)

		require.NoError(t, err)
		require.Equal(
			t, []string{testCfg.kmsKeyIDParam(newPCR0)}, fx.ssmf.calls,
			"finalise reads only the successor's commit pointer, never ciphertexts back",
		)
		require.Equal(t, oldPCR0Hex, got.PCR0)
		require.Equal(t, []string{"signing_key"}, got.Exported)

		extend := requireExtendPCR(t, fx.session, migrationPCRIndex)
		require.Equal(t, newPCR0Bytes, extend.Data)
		require.Equal(t, pcrExtendFromZero(newPCR0Bytes), fx.session.pcrs[migrationPCRIndex])
		require.True(t, fx.session.locks[migrationPCRIndex])

		require.Equal(t, oldPCR0Hex, fx.ssmf.params[testCfg.migrationPreviousPCR0Param(newPCR0)])
		require.Equal(
			t, "old-key", fx.ssmf.params[testCfg.migrationPreviousKMSKeyIDParam(newPCR0)],
		)
		require.NotEmpty(t, fx.ssmf.params[testCfg.migrationPreviousPCR0AttestationParam(newPCR0)])
		require.Equal(t, migrationKeyID, fx.ssmf.params[testCfg.kmsKeyIDParam(newPCR0)])
		require.Equal(
			t, "old-key", fx.ssmf.params[testCfg.kmsKeyIDParam(oldPCR0Hex)],
			"the predecessor's own commit pointer must survive the handoff",
		)
		require.NotEmpty(t, fx.ssmf.params[testCfg.storageDEKCiphertextParam(migrationKeyID)])
		require.NotEmpty(
			t,
			fx.ssmf.params[testCfg.migrationStateOriginReceiptParam(migrationKeyID, newPCR0)],
		)
		require.Empty(
			t,
			fx.ssmf.params["/prod/app/MigrationStateOriginReceipt/"+migrationKeyID],
			"the receipt must move to the PCR0-scoped path, not merely exist",
		)
		requireKMSCiphertextPlaintext(
			t,
			fx.kmsf,
			fx.ssmf.params[testCfg.secretCiphertextParam("signing_key", migrationKeyID)],
			secretPlaintext,
		)
		require.NoError(t, VerifyKeyPolicyPosture(
			fx.kmsf.keyPolicy(migrationKeyID), []string{newPCR0}, true,
		))
		require.NotNil(t, fx.session.attestationRoots)

		newNSM := &nsmW{nsm: &fakeNSM{
			session:     newStatefulNSMSession(t, map[uint][]byte{0: newPCR0Bytes}),
			verifyRoots: fx.session.attestationRoots,
		}}
		newBoot, err := NewBoot(
			successorTestCfg(oldPCR0Hex), newNSM, fx.kmsf, &fakeSTS{}, fx.ssm, fx.s3f,
		)
		require.NoError(t, err)
		established, err := newBoot.Boot(ctx)
		require.NoError(t, err)
		require.Equal(t, dekKey, established.dek.(*dek).key)
		require.Equal(t, secret.Plaintext, established.secrets[0].Plaintext)
		require.Equal(t, migrationIntentBucketName, established.migrationIntentBucketName)
		newReceipt := testCfg.stateOriginReceiptParam(migrationKeyID, newPCR0)
		require.NotEmpty(t, fx.ssmf.params[newReceipt])

		// The predecessor never adopts the migration key: it has no receipt
		// under it, and the key's policy does not admit its PCR0.
		require.Empty(
			t,
			fx.ssmf.params[testCfg.stateOriginReceiptParam(migrationKeyID, oldPCR0Hex)],
		)
		require.Error(t, VerifyKeyPolicyPosture(
			fx.kmsf.keyPolicy(migrationKeyID), []string{oldPCR0Hex}, true,
		))
		require.NotEmpty(t, fx.ssmf.params[newReceipt])
	})

	t.Run("refuses to re-finalise onto an existing target pointer", func(t *testing.T) {
		fx := setup(t)
		fx.ssmf.params[testCfg.kmsKeyIDParam(newPCR0)] = "already-committed"
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx)

		require.ErrorIs(t, err, errMigrationAlreadyFinalised)
		require.NotContains(t, err.Error(), "delete")
		// The guard runs before PCR31 and before any key is minted, so a refusal
		// leaves the successor's committed generation exactly as it was.
		require.Equal(t, "already-committed", fx.ssmf.params[testCfg.kmsKeyIDParam(newPCR0)])
		require.Equal(t, make([]byte, 48), fx.session.pcrs[migrationPCRIndex])
		fx.kmsf.mu.Lock()
		require.Empty(t, fx.kmsf.keys)
		fx.kmsf.mu.Unlock()
	})

	t.Run("predecessor cannot read back what it wrote under the migration key",
		func(t *testing.T) {
			fx := setup(t)
			request(t, fx, newPCR0)

			_, err := fx.m.CompleteMigration(ctx)
			require.NoError(t, err)

			predecessorOnMigrationKey := &kmsW{
				cfg:   testCfg,
				nsm:   fx.m.nsm,
				kms:   fx.kmsf,
				keyID: migrationKeyID,
			}
			_, err = predecessorOnMigrationKey.Decrypt(
				ctx, fx.ssmf.params[testCfg.storageDEKCiphertextParam(migrationKeyID)],
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
		fx := setup(t)
		fx.m.cfg.MigrationCooldown = 2 * time.Minute
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
		// A fresh migrator would resolve the production cooldown; this test is
		// about recovering the intent across a restart, not about waiting one out.
		restarted, err := newMigrator(
			migrationTestCfg(), fx.m.nsm, fx.ssm, fx.s3f, migrationIntentBucketName,
		)
		require.NoError(t, err)
		restarted.Promote(fx.m.kms, fx.m.dek, fx.m.staticSecrets, fx.m.tlsKey)

		_, err = restarted.CompleteMigration(ctx)

		require.NoError(t, err)
		require.Equal(t, migrationKeyID, fx.ssmf.params[testCfg.kmsKeyIDParam(newPCR0)])
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
				testCfg.storageDEKCiphertextParam(migrationKeyID): errors.New("set failed"),
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
				testCfg.migrationStateOriginReceiptParam(migrationKeyID, newPCR0): errors.New(
					"set failed",
				),
			}
		})
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to write migration-transition receipt")
	})

	// The create-only commit is what elects a winner among concurrent
	// finalisers. The read guard above cannot: it is a separate round trip, so
	// a peer can commit inside the window between the read and the write.
	t.Run("loses the commit race to a concurrent finaliser", func(t *testing.T) {
		fx := setup(t)
		pointer := testCfg.kmsKeyIDParam(newPCR0)
		fx.ssmf.beforePut = func(name string) {
			if name == pointer {
				// A peer predecessor commits its own generation after we passed
				// the guard and just as our commit lands.
				fx.ssmf.params[pointer] = "peer-key"
			}
		}
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx)

		require.ErrorIs(t, err, errMigrationAlreadyFinalised)
		require.Equal(
			t, "peer-key", fx.ssmf.params[pointer],
			"the loser must not overwrite the winner's committed generation",
		)
		// The loser's artifacts live under a key ID only it minted, so they are
		// orphans rather than corruption: nothing enumerates that subtree.
		require.NotEmpty(
			t,
			fx.ssmf.params[testCfg.migrationStateOriginReceiptParam(migrationKeyID, newPCR0)],
		)
	})

	t.Run("transition receipt is immutable once written", func(t *testing.T) {
		fx := setup(t)
		request(t, fx, newPCR0)
		_, err := fx.m.CompleteMigration(ctx)
		require.NoError(t, err)

		param := testCfg.migrationStateOriginReceiptParam(migrationKeyID, newPCR0)
		first := fx.ssmf.params[param]
		require.NotEmpty(t, first)

		err = WriteTransitionReceipt(ctx, testCfg, fx.m.nsm, fx.ssm, bootSnapshot{
			kmsKeyID:            migrationKeyID,
			ownerPCR0:           newPCR0,
			predecessorPCR0:     oldPCR0Hex,
			predecessorKMSKeyID: "old-key",
			staticSecrets: map[StaticSecretMetadata]string{
				secret.StaticSecretMetadata: fx.ssmf.params[testCfg.secretCiphertextParam(
					"signing_key", migrationKeyID,
				)],
			},
			storageDEK:                fx.ssmf.params[testCfg.storageDEKCiphertextParam(migrationKeyID)],
			tlsKeyCiphertext:          fx.ssmf.params[testCfg.tlsKeyCiphertextParam(migrationKeyID)],
			migrationIntentBucketName: migrationIntentBucketName,
		})

		require.Error(t, err)
		require.True(t, isParameterAlreadyExists(err))
		require.Equal(t, first, fx.ssmf.params[param], "a published receipt must not change")
	})

	// Keeping the key ID in the receipt path is what makes this recoverable:
	// the retry mints a new key, so its receipt lands on a path that has never
	// existed and the create-only write cannot collide with the dead attempt's.
	t.Run("retries cleanly after the commit fails post-receipt", func(t *testing.T) {
		fx := setup(t)
		pointer := testCfg.kmsKeyIDParam(newPCR0)
		fx.ssmf.putErrs = map[string]error{pointer: errors.New("throttled")}
		request(t, fx, newPCR0)

		_, err := fx.m.CompleteMigration(ctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to commit successor KMS key ID")
		require.NotEmpty(
			t,
			fx.ssmf.params[testCfg.migrationStateOriginReceiptParam(migrationKeyID, newPCR0)],
		)

		fx.ssmf.putErrs = nil
		_, err = fx.m.CompleteMigration(ctx)
		require.NoError(t, err)

		retryKeyID := fx.ssmf.params[pointer]
		require.NotEmpty(t, retryKeyID)
		require.NotEqual(
			t, migrationKeyID, retryKeyID,
			"the retry must commit a freshly minted key, not the dead attempt's",
		)
		require.NotEmpty(
			t,
			fx.ssmf.params[testCfg.migrationStateOriginReceiptParam(retryKeyID, newPCR0)],
		)
		require.NotEmpty(
			t,
			fx.ssmf.params[testCfg.migrationStateOriginReceiptParam(migrationKeyID, newPCR0)],
			"the dead attempt's receipt survives as an unreachable orphan",
		)

		// The successor adopts the retry's generation and recovers its state.
		newNSM := &nsmW{nsm: &fakeNSM{
			session:     newStatefulNSMSession(t, map[uint][]byte{0: newPCR0Bytes}),
			verifyRoots: fx.session.attestationRoots,
		}}
		newBoot, err := NewBoot(
			successorTestCfg(oldPCR0Hex), newNSM, fx.kmsf, &fakeSTS{}, fx.ssm, fx.s3f,
		)
		require.NoError(t, err)
		established, err := newBoot.Boot(ctx)
		require.NoError(t, err)
		require.Equal(t, dekKey, established.dek.(*dek).key)
		require.Equal(t, secret.Plaintext, established.secrets[0].Plaintext)
	})

	t.Run("refuses to commit when aborted during the handoff", func(t *testing.T) {
		fx := setup(t)
		request(t, fx, newPCR0)
		receiptParam := testCfg.migrationStateOriginReceiptParam(migrationKeyID, newPCR0)
		fx.ssmf.beforePut = func(name string) {
			if name != receiptParam {
				return
			}
			// An operator aborts on a peer while this handoff is mid-flight.
			_, err := fx.m.intent.Abort(ctx, oldPCR0Hex)
			require.NoError(t, err)
		}

		_, err := fx.m.CompleteMigration(ctx)

		require.ErrorIs(t, err, errMigrationIntentAborted)
		require.Empty(
			t, fx.ssmf.params[testCfg.kmsKeyIDParam(newPCR0)],
			"an aborted handoff must leave the successor uncommitted",
		)
	})

	t.Run("fails closed when the intent store is unreadable at commit", func(t *testing.T) {
		fx := setup(t)
		request(t, fx, newPCR0)
		receiptParam := testCfg.migrationStateOriginReceiptParam(migrationKeyID, newPCR0)
		fx.ssmf.beforePut = func(name string) {
			if name == receiptParam {
				fx.s3f.listErr = errors.New("s3 unavailable")
			}
		}

		_, err := fx.m.CompleteMigration(ctx)

		require.Error(t, err)
		require.ErrorContains(t, err, "verify migration intent")
		require.Empty(t, fx.ssmf.params[testCfg.kmsKeyIDParam(newPCR0)])
	})

	// Adoption is a one-time event. Once the successor has written its own
	// state-origin receipt it resumes from that, so a later abort — which the
	// log accepts at any time — cannot invalidate a running generation.
	t.Run("successor restart is not revalidated against the intent log", func(t *testing.T) {
		fx := setup(t)
		request(t, fx, newPCR0)
		_, err := fx.m.CompleteMigration(ctx)
		require.NoError(t, err)

		session := newStatefulNSMSession(t, map[uint][]byte{0: newPCR0Bytes})
		successor := func(roots *x509.CertPool) (*Boot, error) {
			return NewBoot(
				successorTestCfg(oldPCR0Hex),
				&nsmW{nsm: &fakeNSM{session: session, verifyRoots: roots}},
				fx.kmsf, &fakeSTS{}, fx.ssm, fx.s3f,
			)
		}
		// Adopting verifies the predecessor's receipt; restarting verifies the
		// successor's own, which this session signed during adoption.
		first, err := successor(fx.session.attestationRoots)
		require.NoError(t, err)
		_, err = first.Boot(ctx)
		require.NoError(t, err)

		_, err = fx.m.intent.Abort(ctx, oldPCR0Hex)
		require.NoError(t, err)

		restarted, err := successor(session.attestationRoots)
		require.NoError(t, err)
		established, err := restarted.Boot(ctx)
		require.NoError(t, err, "a committed generation must survive a later abort")
		require.Equal(t, dekKey, established.dek.(*dek).key)
	})

	t.Run("fails when KMSKeyID write fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.ssmf.putErrs = map[string]error{
				testCfg.kmsKeyIDParam(newPCR0): errors.New("set failed"),
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

		fx.successor.cfg = newTestConfig("other-deployment", "app", false)
		doc, err := fx.successor.buildSuccessorAttestation(challenge)
		require.NoError(t, err)

		_, err = fx.predecessor.verifySuccessorAttestation(doc, challenge)

		require.ErrorContains(t, err, "user data")
	})

	t.Run("rejects a claim with the wrong schema", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		enc, err := cbor.CoreDetEncOptions().EncMode()
		require.NoError(t, err)
		payload, err := enc.Marshal(successorClaimV1{
			Schema:     "enclave.successor_claim.v2",
			Deployment: fx.predecessor.cfg.Deployment,
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
		stranger := successorMigrator(t, testCfg, newTestAttestationSigner(
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
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	m := &migrator{
		cfg: migrationTestCfg(), nsm: fx.nsm, intent: fx.log, ssm: NewSSM(&fakeSSM{}), ready: true,
	}
	target := strings.Repeat("cd", 48)

	own, err := m.sourcePCR0()
	require.NoError(t, err)
	require.NoError(t, m.publishChallenge(ctx, own))
	stale, err := m.ssm.MayGet(ctx, m.cfg.migrationChallengeParam(own))
	require.NoError(t, err)

	candidate := successorMigrator(t, m.cfg, fx.signer, mustDecodeHex(t, target))
	doc, err := candidate.buildSuccessorAttestation(mustDecodeHex(t, stale))
	require.NoError(t, err)

	// Force rotation, as the control loop does once the challenge ages out.
	m.mu.Lock()
	m.challengeAt = time.Now().Add(-2 * migrationChallengeRotate)
	m.mu.Unlock()
	require.NoError(t, m.publishChallenge(ctx, own))

	// The answer to the retired challenge is now inert, so no intent is recorded.
	require.NoError(t, m.ssm.Set(
		ctx, m.cfg.successorAttestationParam(own, target), doc, WithAdvancedTier(),
	))
	require.NoError(t, m.adoptCandidate(ctx, own))

	status, err := m.MigrationStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, migrationStateNone, status.State)
	require.Empty(t, fx.s3.objects, "a stale answer must publish no intent")
}

func TestAdoptCandidateRefusesWhileAmbiguous(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	m := &migrator{
		cfg: migrationTestCfg(), nsm: fx.nsm, intent: fx.log, ssm: NewSSM(&fakeSSM{}), ready: true,
	}

	own, err := m.sourcePCR0()
	require.NoError(t, err)
	require.NoError(t, m.publishChallenge(ctx, own))
	challenge, err := m.ssm.MayGet(ctx, m.cfg.migrationChallengeParam(own))
	require.NoError(t, err)

	// Two live candidates answer the same challenge. Nobody intended that, so
	// the predecessor keeps serving rather than picking one.
	for _, target := range []string{strings.Repeat("cd", 48), strings.Repeat("ee", 48)} {
		candidate := successorMigrator(t, m.cfg, fx.signer, mustDecodeHex(t, target))
		doc, err := candidate.buildSuccessorAttestation(mustDecodeHex(t, challenge))
		require.NoError(t, err)
		require.NoError(t, m.ssm.Set(
			ctx, m.cfg.successorAttestationParam(own, target), doc, WithAdvancedTier(),
		))
	}

	err = m.adoptCandidate(ctx, own)

	require.ErrorIs(t, err, errMigrationSuccessorAmbiguous)
	require.Empty(t, fx.s3.objects, "an ambiguous round must publish no intent")
}

func TestHandleMigrationRequestDerivesTargetFromAttestation(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	m := &migrator{
		cfg: migrationTestCfg(), nsm: fx.nsm, intent: fx.log, ssm: NewSSM(&fakeSSM{}), ready: true,
	}
	attested := strings.Repeat("cd", 48)

	status, err := requestMigrationTo(t, ctx, m, fx.signer, attested)

	require.NoError(t, err)
	// The recorded target is the successor's own measurement. Nothing the caller
	// sent could have named it.
	require.Equal(t, attested, status.TargetPCR0)
}

func TestCandidateRefusesStateOperations(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	m := &migrator{cfg: migrationTestCfg(), nsm: fx.nsm, intent: fx.log, ssm: NewSSM(&fakeSSM{})}

	require.False(t, m.Ready())

	_, err := m.handleMigrationRequest(ctx, migrationIntentRequested, strings.Repeat("cd", 48))
	require.ErrorIs(t, err, errMigrationCandidate)
	require.Empty(t, fx.s3.objects, "a candidate must publish no intent")

	_, err = m.CompleteMigration(ctx)
	require.ErrorIs(t, err, errMigrationCandidate)

	// A candidate can still prove who it is: that is the whole point of the mode.
	doc, err := m.buildSuccessorAttestation(bytes.Repeat([]byte{0x11}, 32))
	require.NoError(t, err)
	require.NotEmpty(t, doc)
}

func TestInboundIntentIsReported(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	m := &migrator{
		cfg: migrationTestCfg(), nsm: fx.nsm, intent: fx.log, ssm: NewSSM(&fakeSSM{}), ready: true,
	}
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

	t.Run("an aborted intent is not reported", func(t *testing.T) {
		_, err := m.handleMigrationRequest(ctx, migrationIntentAborted, "")
		require.NoError(t, err)

		inbound, err := fx.log.InboundIntent(ctx, target)

		require.NoError(t, err)
		require.Nil(t, inbound)
	})
}

func TestMigrationControlCommitsAndAborts(t *testing.T) {
	migrationIntentBucketName := migrationIntentBucketName(testCfg, fakeSTSAccountID)

	oldPCR0 := bytes.Repeat([]byte{0xab}, 48)
	oldPCR0Hex := hex.EncodeToString(oldPCR0)
	newPCR0 := strings.Repeat("cd", 48)

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
			testCfg.kmsKeyIDParam(oldPCR0Hex): "old-key",
		}}
		m, err := newMigrator(
			migrationTestCfg(), nsm, NewSSM(ssmf), newFakeS3(), migrationIntentBucketName,
		)
		require.NoError(t, err)
		m.Promote(
			&kmsW{
				cfg: testCfg, nsm: nsm, kms: newFakeKMS(), sts: &fakeSTS{arn: testRoleARN},
				keyID: "old-key",
			},
			&dek{key: bytes.Repeat([]byte{0x42}, 32)},
			nil,
			newTestTLSKey(t),
		)
		return m, ssmf, session
	}

	// Standing in for a candidate publishing its answer to the live challenge.
	answer := func(t *testing.T, m *migrator, session *fakeNSMSession, target string) {
		t.Helper()
		challenge, err := m.ssm.MayGet(ctx, m.cfg.migrationChallengeParam(oldPCR0Hex))
		require.NoError(t, err)
		require.NotEmpty(t, challenge, "predecessor must publish a challenge")

		candidate := successorMigrator(t, m.cfg, session.attestationSign, mustDecodeHex(t, target))
		doc, err := candidate.buildSuccessorAttestation(mustDecodeHex(t, challenge))
		require.NoError(t, err)
		require.NoError(t, m.ssm.Set(
			ctx, m.cfg.successorAttestationParam(oldPCR0Hex, target), doc, WithAdvancedTier(),
		))
	}

	t.Run("a candidate answering is the whole trigger", func(t *testing.T) {
		m, ssmf, session := setup(t)

		// Round one publishes a challenge; nobody has answered yet.
		require.NoError(t, m.advanceMigration(ctx))
		require.Empty(t, ssmf.params[testCfg.kmsKeyIDParam(newPCR0)])

		answer(t, m, session, newPCR0)

		// Round two adopts the answer, round three commits once eligible.
		require.NoError(t, m.advanceMigration(ctx))
		require.NoError(t, m.advanceMigration(ctx))

		require.NotEmpty(t, ssmf.params[testCfg.kmsKeyIDParam(newPCR0)],
			"the successor's commit pointer must appear")
		require.Equal(t, "old-key", ssmf.params[testCfg.kmsKeyIDParam(oldPCR0Hex)],
			"the predecessor's own pointer must survive")
	})

	t.Run("an operator abort stops the commit", func(t *testing.T) {
		m, ssmf, session := setup(t)

		require.NoError(t, m.advanceMigration(ctx))
		answer(t, m, session, newPCR0)
		require.NoError(t, m.advanceMigration(ctx))

		// Written before the cooldown elapses; this is the only operator control.
		ssmf.params[m.cfg.migrationAbortParam(oldPCR0Hex)] = newPCR0

		require.NoError(t, m.advanceMigration(ctx))

		require.Empty(t, ssmf.params[testCfg.kmsKeyIDParam(newPCR0)],
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

		ssmf.params[m.cfg.migrationAbortParam(oldPCR0Hex)] = strings.Repeat("ee", 48)

		require.NoError(t, m.advanceMigration(ctx))

		require.NotEmpty(t, ssmf.params[testCfg.kmsKeyIDParam(newPCR0)])
	})
}

func TestCandidateAnswersPublishedChallenges(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	ssmf := &fakeSSM{params: map[string]string{}}
	m := &migrator{cfg: migrationTestCfg(), nsm: fx.nsm, intent: fx.log, ssm: NewSSM(ssmf)}

	predecessor := strings.Repeat("11", 48)
	m.cfg.PreviousPCR0 = predecessor
	ssmf.params[m.cfg.migrationChallengeParam(predecessor)] = strings.Repeat("ab", 32)

	require.NoError(t, m.answerChallenges(ctx))

	// The candidate publishes under the challenging enclave's prefix, so a
	// predecessor finds only answers to its own challenge.
	doc := ssmf.params[m.cfg.successorAttestationParam(predecessor, fx.source)]
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

	require.Empty(t, fx.ssmf.params[testCfg.kmsKeyIDParam(targetPCR0)])
	require.Empty(t, fx.ssmf.params[testCfg.migrationPreviousPCR0Param(targetPCR0)])
	require.Empty(t, fx.ssmf.params[testCfg.migrationPreviousKMSKeyIDParam(targetPCR0)])
	require.Empty(t, fx.ssmf.params[testCfg.migrationPreviousPCR0AttestationParam(targetPCR0)])
	for name := range fx.ssmf.params {
		require.NotContains(t, name, "/Ciphertext/")
		require.NotContains(t, name, "StateOriginReceipt/")
	}
}

// successorMigrator stands in for a live candidate. It signs with the
// predecessor's test root, mirroring production where every enclave chains to
// the same AWS Nitro root — otherwise the predecessor could not verify any
// document but its own, and the exchange would be untestable for the wrong
// reason. Only cfg and nsm are populated, which is all the claim methods reach for.
func successorMigrator(
	t *testing.T, cfg *Config, signer *testAttestationSigner, pcr0 []byte,
) *migrator {
	t.Helper()
	return &migrator{cfg: cfg, nsm: &nsmW{nsm: &fakeNSM{session: &fakeNSMSession{
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

	own, err := m.sourcePCR0()
	require.NoError(t, err)
	require.NoError(t, m.publishChallenge(ctx, own))

	challenge, err := m.ssm.MayGet(ctx, m.cfg.migrationChallengeParam(own))
	require.NoError(t, err)

	candidate := successorMigrator(t, m.cfg, predecessorSigner, mustDecodeHex(t, targetPCR0))
	doc, err := candidate.buildSuccessorAttestation(mustDecodeHex(t, challenge))
	require.NoError(t, err)
	require.NoError(t, m.ssm.Set(
		ctx, m.cfg.successorAttestationParam(own, targetPCR0), doc, WithAdvancedTier(),
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

// successorTestFixture pairs a predecessor with a would-be successor signing
// under the same root, as real enclaves share the AWS Nitro root.
type successorTestFixture struct {
	predecessor *migrator
	successor   *migrator
	targetPCR0  string
}

func newSuccessorTestFixture(t *testing.T) *successorTestFixture {
	t.Helper()
	session := newStatefulNSMSession(t, map[uint][]byte{0: bytes.Repeat([]byte{0xab}, 48)})
	predecessor := &migrator{cfg: testCfg, nsm: &nsmW{nsm: &fakeNSM{
		session:     session,
		verifyRoots: session.attestationSign.roots,
	}}}
	target := bytes.Repeat([]byte{0xcd}, 48)

	return &successorTestFixture{
		predecessor: predecessor,
		successor:   successorMigrator(t, testCfg, session.attestationSign, target),
		targetPCR0:  hex.EncodeToString(target),
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

func TestCandidateIgnoresUnrelatedAndCommittedChallenges(t *testing.T) {
	for _, previous := range []string{"", "genesis", strings.Repeat("11", 48)} {
		for _, committed := range []bool{false, true} {
			fx := newMigrationIntentFixture(t)
			ssmf := &fakeSSM{params: map[string]string{}}
			cfg := migrationTestCfg()
			cfg.PreviousPCR0 = previous
			m := &migrator{cfg: cfg, nsm: fx.nsm, intent: fx.log, ssm: NewSSM(ssmf)}
			unrelated := strings.Repeat("22", 48)
			ssmf.params[cfg.migrationChallengeParam(unrelated)] = strings.Repeat("ab", 32)
			if committed {
				ssmf.params[cfg.kmsKeyIDParam(fx.source)] = "existing-key"
				ssmf.params[cfg.migrationChallengeParam(previous)] = strings.Repeat("ab", 32)
			}
			require.NoError(t, m.answerChallenges(context.Background()))
			require.Empty(t, ssmf.params[cfg.successorAttestationParam(unrelated, fx.source)])
			require.Empty(t, ssmf.params[cfg.successorAttestationParam(previous, fx.source)])
		}
	}
}
