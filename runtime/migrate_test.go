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
		m := &migrator{
			cfg: cfg, nsm: fx.nsm, pcr0: fx.source, intent: fx.log,
			ssm: NewSSM(&fakeSSM{}),
		}
		return m, fx
	}
	request := func(t *testing.T, m *migrator, fx *migrationIntentFixture) error {
		t.Helper()
		_, err := requestMigrationTo(t, ctx, m, fx.signer, targetPCR0)
		return err
	}
	// seed publishes a pending intent whose S3 version is dated publishedAt.
	seed := func(t *testing.T, fx *migrationIntentFixture, publishedAt time.Time) {
		t.Helper()
		fx.s3.putRawObjectAt(
			migrationIntentObjectKey(fx.source, 1),
			fx.object(
				t, 1, migrationIntentRequested, targetPCR0, migrationIntentTestBucket, fx.pcr0,
			),
			publishedAt,
		)
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
		_, err := m.intent.Abort(ctx, fx.source)
		require.NoError(t, err)
		status, err := m.MigrationStatus(ctx)

		require.NoError(t, err)
		require.Equal(t, migrationStateAborted, status.State)
		require.Zero(t, status.RemainingSeconds)
	})

	t.Run("eligible once the cooldown has elapsed", func(t *testing.T) {
		m, fx := setup(t)
		published := time.Now().UTC().Add(-3 * time.Minute)
		seed(t, fx, published)
		status, err := m.MigrationStatus(ctx)

		require.NoError(t, err)
		require.Equal(t, migrationStateEligible, status.State)
		require.Zero(t, status.RemainingSeconds)
		require.Equal(t, published.Add(2*time.Minute), *status.EligibleAt)
	})

	t.Run("a partial second left still counts as one", func(t *testing.T) {
		m, fx := setup(t)
		// Just under a second of the two-minute cooldown is left.
		seed(t, fx, time.Now().UTC().Add(-2*time.Minute+999*time.Millisecond))
		status, err := m.MigrationStatus(ctx)

		require.NoError(t, err)
		require.Equal(t, migrationStateCoolingDown, status.State)
		require.Equal(t, 1, status.RemainingSeconds)
	})

	t.Run("zero cooldown is eligible even ahead of the clock", func(t *testing.T) {
		m, fx := setup(t)
		m.cfg.MigrationCooldown = 0
		published := time.Now().UTC().Add(time.Minute)
		seed(t, fx, published)
		status, err := m.MigrationStatus(ctx)

		require.NoError(t, err)
		require.Equal(t, migrationStateEligible, status.State)
		require.Zero(t, status.RemainingSeconds)
		require.Equal(t, published, *status.EligibleAt)
	})
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

func TestHandOffToSuccessor(t *testing.T) {
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

	successorCfg := successorTestCfg(oldPCR0Hex)
	successorCfg.StaticSecretConfig = `[{"name":"signing_key"}]`

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
		m.kms = &kmsW{cfg: testCfg, nsm: nsm, kms: kmsf, sts: sts, keyID: "old-key"}
		m.dek = &dek{key: dekKey}
		m.staticSecrets = []StaticSecret{secret}
		m.tlsKey = newTestTLSKey(t)
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

		err := fx.m.handOffToSuccessor(ctx)

		require.NoError(t, err)
		require.Equal(
			t, []string{testCfg.kmsKeyIDParam(newPCR0)}, fx.ssmf.calls,
			"finalise reads only the successor's commit pointer, never ciphertexts back",
		)

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
		requireKeyPolicyPosture(t, fx.kmsf.keyPolicy(migrationKeyID), newPCR0, true)
		require.NotNil(t, fx.session.attestationRoots)

		newNSM := &nsmW{nsm: &fakeNSM{
			session:     newStatefulNSMSession(t, map[uint][]byte{0: newPCR0Bytes}),
			verifyRoots: fx.session.attestationRoots,
		}}
		newBoot, err := NewBoot(
			successorCfg,
			newNSM,
			fx.kmsf,
			&fakeSTS{arn: testRoleARN},
			fx.ssm,
			fx.s3f,
		)
		require.NoError(t, err)
		established, err := newBoot.Boot(ctx)
		require.NoError(t, err)
		require.Equal(t, dekKey, established.dek.(*dek).key)
		require.Equal(t, secret.Plaintext, established.secrets.Static[0].Plaintext)
		require.Equal(t, migrationIntentBucketName, established.migrationIntentBucketName)
		newReceipt := testCfg.stateOriginReceiptParam(migrationKeyID, newPCR0)
		require.NotEmpty(t, fx.ssmf.params[newReceipt])

		// The predecessor never adopts the migration key: it has no receipt
		// under it, and the key's policy does not admit its PCR0.
		require.Empty(
			t,
			fx.ssmf.params[testCfg.stateOriginReceiptParam(migrationKeyID, oldPCR0Hex)],
		)
		require.Error(
			t,
			verifyKeyPolicyPosture(t, fx.kmsf.keyPolicy(migrationKeyID), oldPCR0Hex, true),
		)
		require.NotEmpty(t, fx.ssmf.params[newReceipt])
	})

	t.Run("refuses to re-finalise onto an existing target pointer", func(t *testing.T) {
		fx := setup(t)
		fx.ssmf.params[testCfg.kmsKeyIDParam(newPCR0)] = "already-committed"
		request(t, fx, newPCR0)

		err := fx.m.handOffToSuccessor(ctx)

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

			err := fx.m.handOffToSuccessor(ctx)
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

		err := fx.m.handOffToSuccessor(ctx)

		require.ErrorIs(t, err, errMigrationIntentAbsent)
		requireNoMigrationSideEffects(t, fx, newPCR0)
	})

	t.Run("rejects active cooldown", func(t *testing.T) {
		fx := setup(t)
		fx.m.cfg.MigrationCooldown = 2 * time.Minute
		status, err := requestMigrationTo(t, ctx, fx.m, fx.session.attestationSign, newPCR0)
		require.NoError(t, err)
		require.Equal(t, migrationStateCoolingDown, status.State)

		err = fx.m.handOffToSuccessor(ctx)

		require.ErrorIs(t, err, errMigrationCooldownActive)
		requireNoMigrationSideEffects(t, fx, newPCR0)
	})

	t.Run("rejects aborted intent", func(t *testing.T) {
		fx := setup(t)
		request(t, fx, newPCR0)
		_, err := fx.m.intent.Abort(ctx, oldPCR0Hex)
		require.NoError(t, err)

		err = fx.m.handOffToSuccessor(ctx)

		require.ErrorIs(t, err, errMigrationIntentAborted)
		requireNoMigrationSideEffects(t, fx, newPCR0)
	})

	t.Run("fails closed on intent store error", func(t *testing.T) {
		fx := setup(t)
		fx.s3f.listErr = errors.New("list failed")

		err := fx.m.handOffToSuccessor(ctx)

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
		restarted.kms, restarted.dek = fx.m.kms, fx.m.dek
		restarted.staticSecrets, restarted.tlsKey = fx.m.staticSecrets, fx.m.tlsKey

		err = restarted.handOffToSuccessor(ctx)

		require.NoError(t, err)
		require.Equal(t, migrationKeyID, fx.ssmf.params[testCfg.kmsKeyIDParam(newPCR0)])
	})

	t.Run("fails when PCR31 already committed to another target", func(t *testing.T) {
		fx := setup(t)
		fx.session.pcrs[migrationPCRIndex] = pcrExtendFromZero(bytes.Repeat([]byte{0xee}, 48))
		request(t, fx, newPCR0)

		err := fx.m.handOffToSuccessor(ctx)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to commit new PCR0")
	})

	t.Run("fails when migration KMS creation fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.kmsf.createKeyErr = errors.New("create failed")
		})
		request(t, fx, newPCR0)

		err := fx.m.handOffToSuccessor(ctx)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create migration key")
	})

	t.Run("fails when secret export fails", func(t *testing.T) {
		fx := setup(t, func(fx *startMigrationFixture) {
			fx.kmsf.encryptErr = errors.New("encrypt failed")
		})
		request(t, fx, newPCR0)

		err := fx.m.handOffToSuccessor(ctx)

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

		err := fx.m.handOffToSuccessor(ctx)

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

		err := fx.m.handOffToSuccessor(ctx)

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

		err := fx.m.handOffToSuccessor(ctx)

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
		err := fx.m.handOffToSuccessor(ctx)
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

		err := fx.m.handOffToSuccessor(ctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to commit successor KMS key ID")
		require.NotEmpty(
			t,
			fx.ssmf.params[testCfg.migrationStateOriginReceiptParam(migrationKeyID, newPCR0)],
		)

		fx.ssmf.putErrs = nil
		err = fx.m.handOffToSuccessor(ctx)
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
			successorCfg,
			newNSM,
			fx.kmsf,
			&fakeSTS{arn: testRoleARN},
			fx.ssm,
			fx.s3f,
		)
		require.NoError(t, err)
		established, err := newBoot.Boot(ctx)
		require.NoError(t, err)
		require.Equal(t, dekKey, established.dek.(*dek).key)
		require.Equal(t, secret.Plaintext, established.secrets.Static[0].Plaintext)
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

		err := fx.m.handOffToSuccessor(ctx)

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

		err := fx.m.handOffToSuccessor(ctx)

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
		err := fx.m.handOffToSuccessor(ctx)
		require.NoError(t, err)

		session := newStatefulNSMSession(t, map[uint][]byte{0: newPCR0Bytes})
		successor := func(roots *x509.CertPool) (*Boot, error) {
			return NewBoot(
				successorCfg,
				&nsmW{nsm: &fakeNSM{session: session, verifyRoots: roots}},
				fx.kmsf, &fakeSTS{arn: testRoleARN}, fx.ssm, fx.s3f,
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

		err := fx.m.handOffToSuccessor(ctx)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to commit successor KMS key ID")
	})
}

func TestVerifySuccessorAttestation(t *testing.T) {
	ctx := context.Background()
	challenge := bytes.Repeat([]byte{0x11}, 32)
	// Verify one response against the supplied challenge.
	verify := func(t *testing.T, fx *successorTestFixture, doc string, issued []byte) string {
		t.Helper()
		m := fx.predecessor
		m.pcr0 = strings.Repeat("ab", 48)
		var challenge *migrationChallenge
		if issued != nil {
			challenge = &migrationChallenge{Nonce: issued, IssuedAt: time.Now()}
		}
		m.ssm = NewSSM(&fakeSSM{params: map[string]string{
			m.cfg.migrationResponseParam(m.pcr0, fx.targetPCR0): doc,
		}})
		responses, err := m.ssm.ListParams(ctx, m.cfg.migrationResponseParam(m.pcr0, ""))
		require.NoError(t, err)
		target, err := m.verifyChallengeResponses(ctx, challenge, responses)
		require.NoError(t, err)
		return target
	}

	t.Run("derives the target PCR0 from the document", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		doc, err := successorAttestation(fx.successor, challenge)
		require.NoError(t, err)

		require.Equal(t, fx.targetPCR0, verify(t, fx, doc, challenge))
	})

	t.Run("rejects a document answering a different challenge", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		// Reject replay from an earlier exchange.
		doc, err := successorAttestation(fx.successor, bytes.Repeat([]byte{0x22}, 32))
		require.NoError(t, err)

		require.Empty(t, verify(t, fx, doc, challenge))
	})

	t.Run("rejects a claim for another app", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		fx.successor.cfg = newTestConfig(fx.predecessor.cfg.Deployment, "other-app", false)
		doc, err := successorAttestation(fx.successor, challenge)
		require.NoError(t, err)

		require.Empty(t, verify(t, fx, doc, challenge))
	})

	t.Run("rejects a claim with another lock posture", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		fx.successor.cfg = newTestConfig(
			fx.predecessor.cfg.Deployment, fx.predecessor.cfg.AppName, false,
		)
		fx.successor.cfg.KMSLocked = false
		doc, err := successorAttestation(fx.successor, challenge)
		require.NoError(t, err)

		require.Empty(t, verify(t, fx, doc, challenge))
	})

	t.Run("rejects a claim for another deployment", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		fx.successor.cfg = newTestConfig("other-deployment", "app", false)
		doc, err := successorAttestation(fx.successor, challenge)
		require.NoError(t, err)

		require.Empty(t, verify(t, fx, doc, challenge))
	})

	t.Run("rejects a claim with the wrong schema", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		enc, err := cbor.CoreDetEncOptions().EncMode()
		require.NoError(t, err)
		payload, err := enc.Marshal(migrationClaimV1{
			Schema:     "enclave.successor_claim.v2",
			Deployment: fx.predecessor.cfg.Deployment,
			AppName:    fx.predecessor.cfg.AppName,
			Lock:       fx.predecessor.cfg.lockSegment(),
		})
		require.NoError(t, err)
		raw, _, err := fx.successor.nsm.BuildAttestationDocument(
			WithNonce(challenge), WithUserData(payload),
		)
		require.NoError(t, err)

		require.Empty(t, verify(t, fx, base64.StdEncoding.EncodeToString(raw), challenge))
	})

	t.Run("rejects a document signed by an unrelated root", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		now := time.Now()
		stranger := successorMigrator(t, testCfg, newTestAttestationSigner(
			t, now.Add(-time.Hour), now.Add(time.Hour),
		), bytes.Repeat([]byte{0xcd}, 48))
		doc, err := successorAttestation(stranger, challenge)
		require.NoError(t, err)

		require.Empty(t, verify(t, fx, doc, challenge))
	})

	t.Run("rejects a malformed document", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		require.Empty(t, verify(t, fx, "not base64", challenge))
	})

	t.Run("requires both a document and a challenge", func(t *testing.T) {
		fx := newSuccessorTestFixture(t)

		require.Empty(t, verify(t, fx, "", challenge))

		doc, err := successorAttestation(fx.successor, challenge)
		require.NoError(t, err)
		require.Empty(t, verify(t, fx, doc, nil))
	})
}

func TestChallengeRotationRetiresOldAnswers(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	m := &migrator{
		cfg: migrationTestCfg(), nsm: fx.nsm, pcr0: fx.source, intent: fx.log,
		ssm: NewSSM(&fakeSSM{}),
	}
	target := strings.Repeat("cd", 48)

	own := m.pcr0
	challenge, err := m.mayPublishChallenge(ctx)
	require.NoError(t, err)
	candidate := successorMigrator(t, m.cfg, fx.signer, mustDecodeHex(t, target))
	doc, err := successorAttestation(candidate, challenge.Nonce)
	require.NoError(t, err)

	// Standing in for the challenge aging past its rotation.
	expired := attestedChallenge(
		t, m.cfg, fx.signer, fx.pcr0, challenge.Nonce,
		time.Now().Add(-2*migrationChallengeRotate),
	)
	require.NoError(t, m.ssm.Set(ctx, m.cfg.migrationChallengeParam(own), expired))
	rotated, err := m.mayPublishChallenge(ctx)
	require.NoError(t, err)
	require.NotEqual(t, challenge.Nonce, rotated.Nonce)

	// The answer to the retired challenge is now inert, so no intent is recorded.
	require.NoError(t, m.ssm.Set(
		ctx, m.cfg.migrationResponseParam(own, target), doc, WithAdvancedTier(),
	))
	require.NoError(t, advanceMigrationForTest(t, ctx, m))

	status, err := m.MigrationStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, migrationStateNone, status.State)
	require.Empty(t, fx.s3.objects, "a stale answer must publish no intent")
}

func TestFailedChallengeRotationRecordsNoIntent(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	ssmf := &fakeSSM{}
	m := &migrator{
		cfg: migrationTestCfg(), nsm: fx.nsm, pcr0: fx.source, intent: fx.log,
		ssm: NewSSM(ssmf),
	}
	target := strings.Repeat("cd", 48)

	challenge, err := m.mayPublishChallenge(ctx)
	require.NoError(t, err)
	candidate := successorMigrator(t, m.cfg, fx.signer, mustDecodeHex(t, target))
	answer, err := successorAttestation(candidate, challenge.Nonce)
	require.NoError(t, err)
	require.NoError(t, m.ssm.Set(
		ctx, m.cfg.migrationResponseParam(m.pcr0, target), answer, WithAdvancedTier(),
	))

	ssmf.putErrs = map[string]error{
		m.cfg.migrationChallengeParam(m.pcr0): errors.New("throttled"),
	}
	require.Error(t, advanceMigrationForTest(t, ctx, m))

	// An intent recorded here would outlive its still-live challenge.
	status, err := m.MigrationStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, migrationStateNone, status.State)
	require.Empty(t, fx.s3.objects)

	// The answer still matches the unrotated challenge, so the next round adopts it.
	ssmf.putErrs = nil
	require.NoError(t, advanceMigrationForTest(t, ctx, m))
	status, err = m.MigrationStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, target, status.TargetPCR0)
}

func TestPredecessorIgnoresChallengeFromAnotherMeasurement(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	m := &migrator{
		cfg: migrationTestCfg(), nsm: fx.nsm, pcr0: fx.source, intent: fx.log,
		ssm: NewSSM(&fakeSSM{}),
	}
	target := strings.Repeat("cd", 48)
	otherPCR0 := bytes.Repeat([]byte{0x22}, 48)
	nonce := bytes.Repeat([]byte{0x11}, 32)

	candidate := successorMigrator(t, m.cfg, fx.signer, mustDecodeHex(t, target))
	answer, err := successorAttestation(candidate, nonce)
	require.NoError(t, err)
	require.NoError(t, m.ssm.Set(
		ctx, m.cfg.migrationResponseParam(m.pcr0, target), answer, WithAdvancedTier(),
	))
	require.NoError(t, m.ssm.Set(
		ctx, m.cfg.migrationChallengeParam(m.pcr0),
		attestedChallenge(t, m.cfg, fx.signer, otherPCR0, nonce, time.Now()),
	))

	require.NoError(t, advanceMigrationForTest(t, ctx, m))

	status, err := m.MigrationStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, migrationStateNone, status.State)
	require.Empty(t, fx.s3.objects, "an answer to a foreign challenge must publish no intent")
}

func TestMigrationLeaseAdmitsOnePredecessorReplica(t *testing.T) {
	ctx := context.Background()
	cfg := migrationTestCfg()
	pcr0 := strings.Repeat("ab", 48)
	s3f := newFakeS3()
	nsm := newMigrationIntentFixture(t).nsm
	ssm := NewSSM(&fakeSSM{params: map[string]string{cfg.leaseBucketParam(): testLeaseBucket}})
	first := &migrator{cfg: cfg, nsm: nsm, pcr0: pcr0, s3: s3f, ssm: ssm}
	second := &migrator{cfg: cfg, nsm: nsm, pcr0: pcr0, s3: s3f, ssm: ssm}

	firstLease, err := first.tryAcquireMigrationLease(ctx)
	require.NoError(t, err)
	require.NotNil(t, firstLease)
	challenge, err := first.mayPublishChallenge(ctx)
	require.NoError(t, err)

	secondLease, err := second.tryAcquireMigrationLease(ctx)
	require.NoError(t, err)
	require.Nil(t, secondLease)

	require.NoError(t, firstLease.Release(ctx))
	secondLease, err = second.tryAcquireMigrationLease(ctx)
	require.NoError(t, err)
	require.NotNil(t, secondLease)
	t.Cleanup(func() { _ = secondLease.Release(context.Background()) })
	shared, err := second.mayPublishChallenge(ctx)
	require.NoError(t, err)
	require.Equal(t, challenge.Nonce, shared.Nonce)
	require.True(t, challenge.IssuedAt.Equal(shared.IssuedAt))
}

func TestMayRecordMigrationTakesTheFirstValidAnswer(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*migrator, *migrationIntentFixture, string, []byte) {
		t.Helper()
		fx := newMigrationIntentFixture(t)
		m := &migrator{
			cfg: migrationTestCfg(), nsm: fx.nsm, pcr0: fx.source, intent: fx.log,
			ssm: NewSSM(&fakeSSM{}),
		}
		own := m.pcr0
		challenge, err := m.mayPublishChallenge(ctx)
		require.NoError(t, err)
		return m, fx, own, challenge.Nonce
	}
	answer := func(
		t *testing.T, m *migrator, fx *migrationIntentFixture,
		own, target string, challenge []byte,
	) {
		t.Helper()
		candidate := successorMigrator(t, m.cfg, fx.signer, mustDecodeHex(t, target))
		doc, err := successorAttestation(candidate, challenge)
		require.NoError(t, err)
		require.NoError(t, m.ssm.Set(
			ctx, m.cfg.migrationResponseParam(own, target), doc, WithAdvancedTier(),
		))
	}

	t.Run("an invalid answer does not block a valid one", func(t *testing.T) {
		m, fx, own, challenge := setup(t)
		live := strings.Repeat("cd", 48)
		answer(t, m, fx, own, strings.Repeat("ee", 48), bytes.Repeat([]byte{0x22}, 32))
		answer(t, m, fx, own, live, challenge)

		require.NoError(t, advanceMigrationForTest(t, ctx, m))

		status, err := m.MigrationStatus(ctx)
		require.NoError(t, err)
		require.Equal(t, live, status.TargetPCR0)
	})

	t.Run("two valid answers record exactly one intent", func(t *testing.T) {
		m, fx, own, challenge := setup(t)
		candidates := []string{strings.Repeat("cd", 48), strings.Repeat("ee", 48)}
		for _, target := range candidates {
			answer(t, m, fx, own, target, challenge)
		}

		require.NoError(t, advanceMigrationForTest(t, ctx, m))

		status, err := m.MigrationStatus(ctx)
		require.NoError(t, err)
		require.Contains(t, candidates, status.TargetPCR0)
		require.Equal(t, uint64(1), status.Sequence)
	})
}

func TestMayRecordMigrationTargetsTheAttestedPCR0(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	m := &migrator{
		cfg: migrationTestCfg(), nsm: fx.nsm, pcr0: fx.source, intent: fx.log,
		ssm: NewSSM(&fakeSSM{}),
	}
	attested := strings.Repeat("cd", 48)

	status, err := requestMigrationTo(t, ctx, m, fx.signer, attested)

	require.NoError(t, err)
	// The recorded target is the successor's own measurement. Nothing the caller
	// sent could have named it.
	require.Equal(t, attested, status.TargetPCR0)
}

func TestInboundIntentIsReported(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	m := &migrator{
		cfg: migrationTestCfg(), nsm: fx.nsm, pcr0: fx.source, intent: fx.log,
		ssm: NewSSM(&fakeSSM{}),
	}
	target := strings.Repeat("cd", 48)

	_, err := requestMigrationTo(t, ctx, m, fx.signer, target)
	require.NoError(t, err)

	candidate := func(pcr0, previous string) *migrator {
		return &migrator{cfg: successorTestCfg(previous), pcr0: pcr0, intent: fx.log}
	}

	t.Run("a candidate can see who is offering it a handoff", func(t *testing.T) {
		info, err := candidate(target, fx.source).CandidateInfo(ctx)

		require.NoError(t, err)
		require.NotNil(t, info)
		require.Equal(t, fx.source, info.AwaitingHandoffFrom)
	})

	t.Run("intents aimed elsewhere are not reported", func(t *testing.T) {
		info, err := candidate(strings.Repeat("ee", 48), fx.source).CandidateInfo(ctx)

		require.NoError(t, err)
		require.Nil(t, info)
	})

	t.Run("only the predecessor the image names is read", func(t *testing.T) {
		info, err := candidate(target, strings.Repeat("ee", 48)).CandidateInfo(ctx)

		require.NoError(t, err)
		require.Nil(t, info)
	})

	t.Run("an aborted intent is not reported", func(t *testing.T) {
		_, err := m.intent.Abort(ctx, fx.source)
		require.NoError(t, err)

		info, err := candidate(target, fx.source).CandidateInfo(ctx)

		require.NoError(t, err)
		require.Nil(t, info)
	})
}

func TestPredecessorHandoffCommitsAndAborts(t *testing.T) {
	migrationIntentBucketName := migrationIntentBucketName(testCfg, fakeSTSAccountID)

	oldPCR0 := bytes.Repeat([]byte{0xab}, 48)
	oldPCR0Hex := hex.EncodeToString(oldPCR0)
	newPCR0 := strings.Repeat("cd", 48)

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
		m.kms = &kmsW{
			cfg: testCfg, nsm: nsm, kms: newFakeKMS(), sts: &fakeSTS{arn: testRoleARN},
			keyID: "old-key",
		}
		m.dek = &dek{key: bytes.Repeat([]byte{0x42}, 32)}
		m.tlsKey = newTestTLSKey(t)
		return m, ssmf, session
	}

	// Standing in for a candidate publishing its answer to the live challenge.
	answer := func(t *testing.T, m *migrator, session *fakeNSMSession, target string) {
		t.Helper()
		published, err := m.ssm.MayGet(ctx, m.cfg.migrationChallengeParam(oldPCR0Hex))
		require.NoError(t, err)
		require.NotEmpty(t, published, "predecessor must publish a challenge")
		challenge, err := m.verifyMigrationChallenge(published, oldPCR0Hex)
		require.NoError(t, err)

		candidate := successorMigrator(t, m.cfg, session.attestationSign, mustDecodeHex(t, target))
		doc, err := successorAttestation(candidate, challenge.Nonce)
		require.NoError(t, err)
		require.NoError(t, m.ssm.Set(
			ctx, m.cfg.migrationResponseParam(oldPCR0Hex, target), doc, WithAdvancedTier(),
		))
	}

	t.Run("a candidate answering is the whole trigger", func(t *testing.T) {
		m, ssmf, session := setup(t)

		// Round one publishes a challenge; nobody has answered yet.
		require.NoError(t, advanceMigrationForTest(t, ctx, m))
		require.Empty(t, ssmf.params[testCfg.kmsKeyIDParam(newPCR0)])

		answer(t, m, session, newPCR0)

		// Round two records the migration, round three hands off once eligible.
		require.NoError(t, advanceMigrationForTest(t, ctx, m))
		require.NoError(t, advanceMigrationForTest(t, ctx, m))

		require.NotEmpty(t, ssmf.params[testCfg.kmsKeyIDParam(newPCR0)],
			"the successor's commit pointer must appear")
		require.Equal(t, "old-key", ssmf.params[testCfg.kmsKeyIDParam(oldPCR0Hex)],
			"the predecessor's own pointer must survive")
	})

	t.Run("an operator abort stops the commit", func(t *testing.T) {
		m, ssmf, session := setup(t)

		require.NoError(t, advanceMigrationForTest(t, ctx, m))
		answer(t, m, session, newPCR0)
		require.NoError(t, advanceMigrationForTest(t, ctx, m))

		// Written before the cooldown elapses; this is the only operator control.
		ssmf.params[m.cfg.migrationResponseParam(oldPCR0Hex, migrationAbortResponse)] = newPCR0

		require.NoError(t, advanceMigrationForTest(t, ctx, m))

		require.Empty(t, ssmf.params[testCfg.kmsKeyIDParam(newPCR0)],
			"an aborted handoff must not commit")
		status, err := m.MigrationStatus(ctx)
		require.NoError(t, err)
		require.Equal(t, migrationStateAborted, status.State)

		// The parameter stays: a new answer gets the candidate adopted again, and
		// aborted again before it can commit.
		require.NoError(t, advanceMigrationForTest(t, ctx, m))
		answer(t, m, session, newPCR0)
		require.NoError(t, advanceMigrationForTest(t, ctx, m))
		require.NoError(t, advanceMigrationForTest(t, ctx, m))

		require.Empty(t, ssmf.params[testCfg.kmsKeyIDParam(newPCR0)])
		status, err = m.MigrationStatus(ctx)
		require.NoError(t, err)
		require.Equal(t, migrationStateAborted, status.State)
	})

	t.Run("an abort is recorded while still cooling down", func(t *testing.T) {
		m, ssmf, session := setup(t)
		m.cfg.MigrationCooldown = 2 * time.Minute

		require.NoError(t, advanceMigrationForTest(t, ctx, m))
		answer(t, m, session, newPCR0)
		require.NoError(t, advanceMigrationForTest(t, ctx, m))
		status, err := m.MigrationStatus(ctx)
		require.NoError(t, err)
		require.Equal(t, migrationStateCoolingDown, status.State)

		ssmf.params[m.cfg.migrationResponseParam(oldPCR0Hex, migrationAbortResponse)] = newPCR0
		require.NoError(t, advanceMigrationForTest(t, ctx, m))

		status, err = m.MigrationStatus(ctx)
		require.NoError(t, err)
		require.Equal(t, migrationStateAborted, status.State)
	})

	t.Run("an abort after the commit is not recorded", func(t *testing.T) {
		m, ssmf, session := setup(t)

		require.NoError(t, advanceMigrationForTest(t, ctx, m))
		answer(t, m, session, newPCR0)
		require.NoError(t, advanceMigrationForTest(t, ctx, m))
		require.NoError(t, advanceMigrationForTest(t, ctx, m))
		require.NotEmpty(t, ssmf.params[testCfg.kmsKeyIDParam(newPCR0)])

		// Too late: the successor holds the state, so the log must not claim the
		// handoff was aborted.
		ssmf.params[m.cfg.migrationResponseParam(oldPCR0Hex, migrationAbortResponse)] = newPCR0
		require.NoError(t, advanceMigrationForTest(t, ctx, m))

		status, err := m.MigrationStatus(ctx)
		require.NoError(t, err)
		require.Equal(t, migrationStateEligible, status.State)
	})

	t.Run("an abort naming a different target does not apply", func(t *testing.T) {
		m, ssmf, session := setup(t)

		require.NoError(t, advanceMigrationForTest(t, ctx, m))
		answer(t, m, session, newPCR0)
		require.NoError(t, advanceMigrationForTest(t, ctx, m))

		abort := m.cfg.migrationResponseParam(oldPCR0Hex, migrationAbortResponse)
		ssmf.params[abort] = strings.Repeat("ee", 48)

		require.NoError(t, advanceMigrationForTest(t, ctx, m))

		require.NotEmpty(t, ssmf.params[testCfg.kmsKeyIDParam(newPCR0)])
	})
}

func TestCandidateAnswersPublishedChallenges(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	ssmf := &fakeSSM{params: map[string]string{}}
	m := &migrator{
		cfg: migrationTestCfg(), nsm: fx.nsm, pcr0: fx.source, intent: fx.log,
		ssm: NewSSM(ssmf),
	}

	predecessor := strings.Repeat("11", 48)
	m.cfg.PreviousPCR0 = predecessor
	issuer := successorMigrator(t, m.cfg, fx.signer, mustDecodeHex(t, predecessor))
	issuer.pcr0, issuer.ssm = predecessor, m.ssm
	challenge, err := issuer.issueMigrationChallenge(ctx)
	require.NoError(t, err)

	require.NoError(t, m.respondToChallenge(ctx))

	// The candidate publishes under the challenging enclave's prefix, so a
	// predecessor finds only answers to its own challenge.
	doc := ssmf.params[m.cfg.migrationResponseParam(predecessor, fx.source)]
	require.NotEmpty(t, doc)

	// The predecessor that issued the challenge adopts the candidate from it.
	responses, err := issuer.ssm.ListParams(
		ctx, issuer.cfg.migrationResponseParam(issuer.pcr0, ""),
	)
	require.NoError(t, err)
	target, err := issuer.verifyChallengeResponses(ctx, challenge, responses)
	require.NoError(t, err)
	require.Equal(t, fx.source, target)

	// An unchanged challenge is not answered again; a new one is.
	response := m.cfg.migrationResponseParam(predecessor, fx.source)
	delete(ssmf.params, response)
	require.NoError(t, m.respondToChallenge(ctx))
	require.Empty(t, ssmf.params[response])

	_, err = issuer.issueMigrationChallenge(ctx)
	require.NoError(t, err)
	require.NoError(t, m.respondToChallenge(ctx))
	require.NotEmpty(t, ssmf.params[response])
}

func TestCandidateAnswersOnlyItsPredecessorsChallenge(t *testing.T) {
	fx := newMigrationIntentFixture(t)
	ssmf := &fakeSSM{params: map[string]string{}}
	cfg := migrationTestCfg()
	cfg.PreviousPCR0 = strings.Repeat("11", 48)
	m := &migrator{
		cfg: cfg, nsm: fx.nsm, pcr0: fx.source, intent: fx.log, ssm: NewSSM(ssmf),
	}
	otherPCR0 := bytes.Repeat([]byte{0x22}, 48)
	nonce := bytes.Repeat([]byte{0xab}, 32)
	ssmf.params[cfg.migrationChallengeParam(cfg.PreviousPCR0)] = attestedChallenge(
		t, cfg, fx.signer, otherPCR0, nonce, time.Now(),
	)

	require.Error(t, m.respondToChallenge(context.Background()))
	require.Empty(t, ssmf.params[cfg.migrationResponseParam(cfg.PreviousPCR0, fx.source)])
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
	}, verifyRoots: signer.roots}}}
}

// attestedChallenge builds the challenge an enclave measuring pcr0 publishes.
func attestedChallenge(
	t *testing.T,
	cfg *Config,
	signer *testAttestationSigner,
	pcr0, nonce []byte,
	issuedAt time.Time,
) string {
	t.Helper()
	payload, err := (&migrator{cfg: cfg}).attestationPayload(migrationChallengeSchemaV1)
	require.NoError(t, err)
	return signer.buildWithNonce(t, map[uint][]byte{0: pcr0}, issuedAt, payload, nonce).docB64
}

// successorAttestation builds a candidate response.
func successorAttestation(m *migrator, challenge []byte) (string, error) {
	payload, err := m.attestationPayload(successorClaimSchemaV1)
	if err != nil {
		return "", err
	}
	doc, _, err := m.nsm.BuildAttestationDocument(WithNonce(challenge), WithUserData(payload))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(doc), nil
}

// requestMigrationTo drives the real initiation exchange through SSM: the
// predecessor publishes a challenge, a candidate answers it, and the predecessor
// records the migration to it. Nothing here names the target to the predecessor.
func requestMigrationTo(
	t *testing.T,
	ctx context.Context,
	m *migrator,
	predecessorSigner *testAttestationSigner,
	targetPCR0 string,
) (*MigrationStatus, error) {
	t.Helper()

	own := m.pcr0
	challenge, err := m.mayPublishChallenge(ctx)
	require.NoError(t, err)

	candidate := successorMigrator(t, m.cfg, predecessorSigner, mustDecodeHex(t, targetPCR0))
	doc, err := successorAttestation(candidate, challenge.Nonce)
	require.NoError(t, err)
	require.NoError(t, m.ssm.Set(
		ctx, m.cfg.migrationResponseParam(own, targetPCR0), doc, WithAdvancedTier(),
	))

	if err := advanceMigrationForTest(t, ctx, m); err != nil {
		return nil, err
	}
	return m.MigrationStatus(ctx)
}

func advanceMigrationForTest(t *testing.T, ctx context.Context, m *migrator) error {
	t.Helper()
	m.s3 = newFakeS3()
	if err := m.ssm.Set(ctx, m.cfg.leaseBucketParam(), testLeaseBucket); err != nil {
		return err
	}
	return m.advanceMigration(ctx)
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
			m := &migrator{
				cfg: cfg, nsm: fx.nsm, pcr0: fx.source, intent: fx.log, ssm: NewSSM(ssmf),
			}
			unrelated := strings.Repeat("22", 48)
			ssmf.params[cfg.migrationChallengeParam(unrelated)] = strings.Repeat("ab", 32)
			if committed {
				ssmf.params[cfg.kmsKeyIDParam(fx.source)] = "existing-key"
				ssmf.params[cfg.migrationChallengeParam(previous)] = strings.Repeat("ab", 32)
			}
			require.NoError(t, m.respondToChallenge(context.Background()))
			require.Empty(t, ssmf.params[cfg.migrationResponseParam(unrelated, fx.source)])
			require.Empty(t, ssmf.params[cfg.migrationResponseParam(previous, fx.source)])
		}
	}
}

// handoffPredecessorPCR0 created the deployment the candidate fixtures join.
var handoffPredecessorPCR0 = strings.Repeat("ab", 48)

// newCandidateMigrator creates an uncommitted successor.
func newCandidateMigrator(t *testing.T) (*genesisFixture, *migrator) {
	t.Helper()
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xcd}, 48))
	seedGenesisRecord(t, fx.s3f, handoffPredecessorPCR0)
	fx.nsm = seededGenesisNSM{NSM: fx.nsm}
	fx.ssmf.params[testCfg.kmsKeyIDParam(handoffPredecessorPCR0)] = "predecessor-key"

	m, err := newMigrator(
		testConfigWithPreviousPCR0(handoffPredecessorPCR0),
		fx.nsm, fx.ssm, fx.s3f, stateOriginTestMigrationIntentBucket(),
	)
	require.NoError(t, err)
	return fx, m
}

func contextFor(t *testing.T, timeout time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	return ctx
}

// A candidate waits for commit while answering its predecessor.
func TestAwaitCandidateHandoffWaitsAndAnswersItsPredecessor(t *testing.T) {
	fx, m := newCandidateMigrator(t)
	issuer := successorMigrator(t, m.cfg, fx.signer, mustDecodeHex(t, handoffPredecessorPCR0))
	issuer.pcr0, issuer.ssm = handoffPredecessorPCR0, m.ssm
	issued, err := issuer.issueMigrationChallenge(context.Background())
	require.NoError(t, err)

	err = m.AwaitCandidateHandoff(contextFor(t, 50*time.Millisecond))

	require.ErrorIs(t, err, context.DeadlineExceeded)
	// The predecessor verifies the candidate's answer.
	responses, err := issuer.ssm.ListParams(
		context.Background(), issuer.cfg.migrationResponseParam(issuer.pcr0, ""),
	)
	require.NoError(t, err)
	target, err := issuer.verifyChallengeResponses(context.Background(), issued, responses)
	require.NoError(t, err)
	require.Equal(t, fx.pcr0Hex, target)

	fx.ssmf.params[fx.keyIDParam()] = "successor-key"
	require.NoError(t, m.AwaitCandidateHandoff(contextFor(t, 5*time.Second)))
}

// Existing generations and fresh deployments do not wait.
func TestAwaitCandidateHandoffReturnsWhenThereIsNothingToWaitFor(t *testing.T) {
	t.Run("committed key", func(t *testing.T) {
		fx, m := newCandidateMigrator(t)
		fx.ssmf.params[fx.keyIDParam()] = "committed-key"
		challenge := m.cfg.migrationChallengeParam(handoffPredecessorPCR0)
		fx.ssmf.params[challenge] = strings.Repeat("ab", 32)

		require.NoError(t, m.AwaitCandidateHandoff(contextFor(t, 5*time.Second)))
		require.Empty(
			t,
			fx.ssmf.params[m.cfg.migrationResponseParam(handoffPredecessorPCR0, fx.pcr0Hex)],
			"an enclave with a committed key answers no challenge",
		)
	})

	t.Run("fresh deployment", func(t *testing.T) {
		fx := newGenesisFixture(t, bytes.Repeat([]byte{0xcd}, 48))
		m, err := newMigrator(
			testConfigWithPreviousPCR0(handoffPredecessorPCR0),
			fx.nsm, fx.ssm, fx.s3f, stateOriginTestMigrationIntentBucket(),
		)
		require.NoError(t, err)

		require.NoError(t, m.AwaitCandidateHandoff(contextFor(t, 5*time.Second)))
	})
}

// Partial artifacts do not end candidacy; the final pointer does.
func TestCandidateWaitsForPartiallyWrittenHandoff(t *testing.T) {
	fx, m := newCandidateMigrator(t)
	attestation := testCfg.migrationPreviousPCR0AttestationParam(fx.pcr0Hex)
	fx.ssmf.params[attestation] = "handoff-in-progress"

	err := m.AwaitCandidateHandoff(contextFor(t, 50*time.Millisecond))
	require.ErrorIs(t, err, context.DeadlineExceeded)

	fx.ssmf.params[fx.keyIDParam()] = "successor-key"
	require.NoError(t, m.AwaitCandidateHandoff(contextFor(t, 5*time.Second)))

	boot, err := NewBoot(
		testConfigWithPreviousPCR0(handoffPredecessorPCR0),
		fx.nsm, fx.kmsf, fx.sts, fx.ssm, fx.s3f,
	)
	require.NoError(t, err)
	_, err = boot.Boot(context.Background())
	require.ErrorContains(t, err, "inconsistent migration predecessor artifacts")
}

// An intent alone cannot end candidacy.
func TestInboundIntentDoesNotEndCandidacy(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)
	target := strings.Repeat("cd", 48)

	_, err := fx.log.Request(ctx, fx.source, target)
	require.NoError(t, err)
	info, err := (&migrator{
		cfg: testConfigWithPreviousPCR0(fx.source), pcr0: target, intent: fx.log,
	}).CandidateInfo(ctx)
	require.NoError(t, err)
	require.NotNil(t, info)

	seedGenesisRecord(t, fx.s3, fx.source)
	_, ssm := stateOriginTestSSM(map[string]string{
		testCfg.kmsKeyIDParam(fx.source): "predecessor-key",
	})
	session := newStatefulNSMSession(t, map[uint][]byte{0: mustDecodeHex(t, target)})
	m, err := newMigrator(
		testConfigWithPreviousPCR0(fx.source),
		seededGenesisNSM{NSM: &nsmW{nsm: &fakeNSM{session: session}}},
		ssm, fx.s3, migrationIntentTestBucket,
	)
	require.NoError(t, err)

	err = m.AwaitCandidateHandoff(contextFor(t, 50*time.Millisecond))

	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// State read failures are fatal.
func TestAwaitCandidateHandoffDoesNotRetryFatalErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(*genesisFixture)
		want string
	}{
		{
			name: "commit pointer unreadable",
			fail: func(fx *genesisFixture) { fx.ssmf.err = errors.New("ssm unavailable") },
			want: "ssm unavailable",
		},
		{
			name: "genesis record unreadable",
			fail: func(fx *genesisFixture) { fx.s3f.listErr = errors.New("s3 unavailable") },
			want: "s3 unavailable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx, m := newCandidateMigrator(t)
			tc.fail(fx)

			err := m.AwaitCandidateHandoff(contextFor(t, 5*time.Second))

			require.ErrorContains(t, err, tc.want)
			require.NotErrorIs(t, err, context.DeadlineExceeded)
		})
	}
}
