package runtime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	kmscmd "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestMigrationStateOriginReceiptParamIsPCRScoped(t *testing.T) {
	pcr0 := strings.Repeat("AB", 48)
	require.Equal(
		t,
		"/prod/app/enclave/MigrationStateOriginReceipt/key-1/"+strings.ToLower(pcr0),
		testCfg.migrationStateOriginReceiptParam("key-1", pcr0),
	)
}

// requireNoGenerationSSMReads proves a boot took nothing about its generation
// from SSM: only configuration and inherited secrets may be read there.
func requireNoGenerationSSMReads(t *testing.T, fake *fakeSSM) {
	t.Helper()
	for _, name := range fake.calls {
		for _, marker := range []string{
			"/KMSKeyID/", "/Ciphertext/", "/Migration", "/StateOriginReceipt/",
		} {
			require.NotContains(t, name, marker)
		}
	}
}

// A boot decides from its own published state first; without it, only the
// measured ENCLAVE_PREVIOUS_PCR0 chooses between genesis and adopting a handoff.
func TestBootPlansFromItsOwnSnapshot(t *testing.T) {
	own := bytes.Repeat([]byte{0xab}, 48)
	ownHex := hex.EncodeToString(own)
	prevHex := hex.EncodeToString(bytes.Repeat([]byte{0x99}, 48))
	const keyID = "key-plan"
	handoffBase := handoffParams(t, testCfg, newFakeKMS(), keyID)
	handoff := func(params map[string]string) {
		maps.Copy(params, handoffBase)
		params[testCfg.migrationPreviousPCR0Param(ownHex)] = prevHex
		params[testCfg.migrationPreviousKMSKeyIDParam(ownHex)] = "previous-key"
		params[testCfg.migrationStateOriginReceiptParam(keyID, ownHex)] = "transition"
	}
	published := func(t *testing.T, fx *snapshotTestFixture) {
		fx.seed(t, own, fx.body(t, testGenerationSnapshot(own, nil, keyID), nil), time.Now())
	}

	for _, tc := range []struct {
		name     string
		previous string
		params   func(map[string]string)
		s3       func(*testing.T, *snapshotTestFixture)
		want     bootMode
		wantErr  string
		wantIs   error
	}{
		{name: "genesis image without state", previous: genesisPreviousPCR0, want: &genesisBoot{}},
		{
			name: "genesis image never adopts a handoff", previous: genesisPreviousPCR0,
			params: handoff, want: &genesisBoot{},
		},
		{
			name: "genesis image resumes its state", previous: genesisPreviousPCR0,
			s3: published, want: &resumeBoot{},
		},
		{
			name: "successor resumes its state, whatever SSM holds", previous: prevHex,
			s3: published, params: handoff, want: &resumeBoot{},
		},
		{name: "successor adopts the handoff", previous: prevHex, params: handoff, want: &migrationBoot{}},
		{name: "successor without state or handoff", previous: prevHex, wantErr: "holds no handoff"},
		{
			name: "partial predecessor artifacts", previous: prevHex,
			params: func(p map[string]string) {
				handoff(p)
				delete(p, testCfg.migrationPreviousKMSKeyIDParam(ownHex))
			},
			wantErr: "inconsistent migration predecessor artifacts",
		},
		{
			name: "handoff naming no predecessor", previous: prevHex,
			params: func(p map[string]string) {
				handoff(p)
				delete(p, testCfg.migrationPreviousPCR0Param(ownHex))
				delete(p, testCfg.migrationPreviousKMSKeyIDParam(ownHex))
			},
			wantErr: "no predecessor to migrate from",
		},
		{
			name: "handoff without a transition receipt", previous: prevHex,
			params: func(p map[string]string) {
				handoff(p)
				delete(p, testCfg.migrationStateOriginReceiptParam(keyID, ownHex))
			},
			wantErr: "no migration transition receipt",
		},
		{
			name: "handoff naming the enclave as its own predecessor", previous: prevHex,
			params: func(p map[string]string) {
				handoff(p)
				p[testCfg.migrationPreviousPCR0Param(ownHex)] = ownHex
			},
			wantErr: "cannot be its own predecessor",
		},
		{
			name: "unverifiable state is not an absence", previous: genesisPreviousPCR0,
			s3: func(_ *testing.T, fx *snapshotTestFixture) {
				fx.s3f.putRawObject(snapshotObjectKey(ownHex), []byte("garbage"))
			},
			wantIs: errSnapshotUnverifiable,
		},
		{
			name: "unreadable store fails closed", previous: genesisPreviousPCR0,
			s3:     func(_ *testing.T, fx *snapshotTestFixture) { fx.s3f.listErr = errors.New("down") },
			wantIs: errSnapshotStoreUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newSnapshotTestFixture(t)
			if tc.s3 != nil {
				tc.s3(t, fx)
			}
			params := map[string]string{}
			if tc.params != nil {
				tc.params(params)
			}
			fake, ssm := stateOriginTestSSM(params)
			cfg := stateOriginTestConfig()
			cfg.PreviousPCR0 = tc.previous
			boot := &Boot{
				cfg: cfg, nsm: &nsmW{nsm: &fakeNSM{verifyRoots: fx.signer.roots}},
				ssm: ssm, s3: fx.s3f, sts: &fakeSTS{}, pcr0: own,
				secretsMetadata: SecretsMetadata{Static: stateOriginTestSecrets},
			}

			// A migration reads its handoff when it builds the snapshot.
			planned, err := boot.plan(t.Context())
			var handoff Snapshot
			if err == nil {
				if migration, ok := planned.mode.(*migrationBoot); ok {
					handoff, err = migration.buildSnapshot(t.Context(), boot, &planned.config)
				}
			}

			switch {
			case tc.wantIs != nil:
				require.ErrorIs(t, err, tc.wantIs)
			case tc.wantErr != "":
				require.ErrorContains(t, err, tc.wantErr)
			default:
				require.NoError(t, err)
				require.IsType(t, tc.want, planned.mode)
				if _, adopting := planned.mode.(*migrationBoot); adopting {
					require.Equal(t, "transition", handoff.transitionReceipt)
					require.Equal(t, prevHex, handoff.predecessorPCR0)
				} else {
					requireNoGenerationSSMReads(t, fake)
				}
			}
		})
	}
}

func TestNewBootRejectsInvalidPCR0BeforeStateReads(t *testing.T) {
	for _, tc := range []struct {
		size    int
		wantErr string
	}{
		{0, "empty PCR0"},
		{47, "PCR0 must be exactly 48 bytes"},
		{49, "PCR0 must be exactly 48 bytes"},
	} {
		t.Run(fmt.Sprintf("%d bytes", tc.size), func(t *testing.T) {
			fake, ssm := stateOriginTestSSM(nil)
			session := newStatefulNSMSession(
				t,
				map[uint][]byte{0: bytes.Repeat([]byte{0xaa}, tc.size)},
			)

			boot, err := NewBoot(
				stateOriginTestConfig(),
				&nsmW{nsm: &fakeNSM{session: session}},
				nil,
				nil,
				ssm,
				nil,
			)

			require.ErrorContains(t, err, tc.wantErr)
			require.Nil(t, boot)
			require.Empty(t, fake.calls)
		})
	}
}

func TestVerifyStateOriginReceipt(t *testing.T) {
	stateRoot := []byte("state-root-commitment")
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	pcr0Hex := hex.EncodeToString(pcr0)
	snapshot := Snapshot{ownerPCR0: pcr0Hex, kmsKeyID: "key"}
	att := signedOriginReceipt(t, map[uint][]byte{0: pcr0}, stateRoot, snapshot)
	verifier := NewNSM(WithAttestationRoots(att.roots))

	require.NoError(t, snapshot.verifyOriginReceipt(verifier, att.docB64, stateRoot))

	cases := []struct {
		name     string
		receipt  string
		root     []byte
		snapshot Snapshot
	}{
		{
			name: "wrong PCR0", receipt: att.docB64, root: stateRoot,
			snapshot: Snapshot{
				ownerPCR0: hex.EncodeToString(bytes.Repeat([]byte{0x22}, 48)), kmsKeyID: "key",
			},
		},
		{
			name: "wrong KMS key", receipt: att.docB64, root: stateRoot,
			snapshot: Snapshot{ownerPCR0: pcr0Hex, kmsKeyID: "other-key"},
		},
		{
			name: "wrong state root", receipt: att.docB64,
			root: []byte("other-root"), snapshot: snapshot,
		},
		{
			name: "forged receipt",
			receipt: base64.StdEncoding.EncodeToString(
				buildForgedAttestation(t, map[uint][]byte{0: pcr0}),
			),
			root: stateRoot, snapshot: snapshot,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.snapshot.verifyOriginReceipt(verifier, tc.receipt, tc.root)
			require.Error(t, err)
		})
	}
}

func TestVerifyStateOriginReceiptMigrationPCR31(t *testing.T) {
	prevPCR0 := bytes.Repeat([]byte{0x99}, 48)
	ownPCR0 := bytes.Repeat([]byte{0xab}, 48)
	stateRoot := []byte("successor-state-root")
	pcr31 := pcrExtendFromZero(ownPCR0)
	att := signedReceipt(t, map[uint][]byte{
		0:                 prevPCR0,
		migrationPCRIndex: pcr31,
	}, purposeMigrationTransition, stateRoot)
	verifier := NewNSM(WithAttestationRoots(att.roots))

	require.NoError(t, verifyStateReceipt(
		verifier, att.docB64, purposeMigrationTransition, stateRoot,
		transitionPCRs(hex.EncodeToString(prevPCR0), ownPCR0),
	))
	require.Error(t, verifyStateReceipt(
		verifier, att.docB64, purposeMigrationTransition, stateRoot,
		transitionPCRs(hex.EncodeToString(prevPCR0), bytes.Repeat([]byte{0x33}, 48)),
	))
}

// Genesis publishes its whole state in one create-only write and touches SSM
// for nothing but configuration.
func TestGenesisPublishesItsSnapshotAndNothingToSSM(t *testing.T) {
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))
	before := maps.Clone(fx.ssmf.params)

	result, err := fx.establish(t.Context())

	require.NoError(t, err)
	require.Equal(t, before, fx.ssmf.params, "genesis must write nothing to SSM")
	requireNoGenerationSSMReads(t, fx.ssmf)
	state := fx.published(t)
	require.Equal(t, result.snapshot, *state)
	require.Equal(t, result.kms.KeyID(), state.kmsKeyID)
	require.Empty(t, state.predecessorPCR0)
	require.Empty(t, state.transitionReceipt)
	require.Len(t, fx.s3f.objects[snapshotObjectKey(fx.pcr0Hex)], 1)
	require.NotContains(t, fx.s3f.objects, "deployment-genesis")
	require.Equal(t, stateOriginTestMigrationIntentBucket(), result.migrationIntentBucketName)
	wantSigningKey, err := deriveResponseSigningKey(
		result.masterSeed,
		mustDecodeHexString(fx.pcr0Hex),
	)
	require.NoError(t, err)
	require.Equal(t, wantSigningKey, result.responseSigningKey)
}

// A live peer lease must stop genesis before any KMS key is minted
func TestBootGenesisBlocksOnPeerLease(t *testing.T) {
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))
	writeLeaseDoc(t, fx.s3f, leaseObjectKey(testCfg, genesisLeaseName), time.Now().Add(time.Hour))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := fx.establish(ctx)

	require.ErrorContains(t, err, "genesis did not complete")
	require.Empty(t, fx.kmsf.keys, "no KMS key may be minted while a peer holds genesis")
	require.Empty(t, fx.s3f.objects[snapshotObjectKey(fx.pcr0Hex)])
}

// A second enclave arriving after a peer's genesis resumes against the published
// state and derives the identical keys, rather than minting its own.
func TestBootResumesAfterPeerGenesis(t *testing.T) {
	ctx := context.Background()
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))
	parentEnv := os.Environ()

	first, err := fx.establish(ctx)
	require.NoError(t, err)
	require.Len(t, fx.kmsf.keys, 1)

	second, err := fx.establish(ctx)
	require.NoError(t, err)

	require.Len(t, fx.kmsf.keys, 1, "the second boot must not mint a key")
	require.Len(t, fx.s3f.objects[snapshotObjectKey(fx.pcr0Hex)], 1, "nor publish again")
	require.Equal(t, first.kms.KeyID(), second.kms.KeyID())
	require.Equal(t, first.snapshot, second.snapshot)
	require.Equal(t, first.dek.(*dek).key, second.dek.(*dek).key, "fleet must share one DEK")
	require.Equal(t, first.secrets, second.secrets)
	require.Equal(t, first.acmeAccountKey, second.acmeAccountKey)
	require.NotEmpty(t, first.responseSigningKey)
	require.Equal(t, first.responseSigningKey, second.responseSigningKey)
	require.Equal(t, parentEnv, os.Environ(), "boot must not export keys to the parent environment")

	internalKeys := [][]byte{
		second.masterSeed, second.dek.(*dek).key,
		second.responseSigningKey, second.responseSigningKey.Seed(),
	}
	for _, key := range []*ecdsa.PrivateKey{
		second.tlsKey.(*ecdsa.PrivateKey), second.acmeAccountKey.(*ecdsa.PrivateKey),
	} {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		internalKeys = append(internalKeys, der, key.D.FillBytes(make([]byte, 32)))
	}
	env := strings.Join(appEnv(*stateOriginTestConfig(), "token", second.secrets), "\n")
	for _, key := range internalKeys {
		require.NotContains(t, env, hex.EncodeToString(key))
		require.NotContains(t, env, base64.StdEncoding.EncodeToString(key))
		require.NotContains(t, env, string(key))
	}
}

// Resumed state is read once, at plan time: nothing establish does can be
// steered by what the host changes afterwards.
func TestEstablishResumeUsesThePlannedSnapshot(t *testing.T) {
	ctx := t.Context()
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))
	first, err := fx.establish(ctx)
	require.NoError(t, err)
	boot, err := NewBoot(stateOriginTestConfig(), fx.nsm, fx.kmsf, fx.sts, fx.ssm, fx.s3f)
	require.NoError(t, err)
	planned, err := boot.plan(ctx)
	require.NoError(t, err)
	require.IsType(t, &resumeBoot{}, planned.mode)

	fx.s3f.listErr, fx.s3f.getErr = errors.New("s3 down"), errors.New("s3 down")
	fx.ssmf.err = errors.New("ssm down")
	resumed, err := boot.establish(ctx, planned)

	require.NoError(t, err)
	require.Equal(t, first.masterSeed, resumed.masterSeed)
	require.Equal(t, first.responseSigningKey, resumed.responseSigningKey)
}

// The lease is released once genesis commits, so it never wedges later boots.
func TestBootReleasesGenesisLease(t *testing.T) {
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))

	_, err := fx.establish(context.Background())
	require.NoError(t, err)

	require.Empty(t, fx.s3f.currentETag(leaseObjectKey(testCfg, genesisLeaseName)))
}

// Losers must not queue on the lease. Once a peer has published, a waiting
// enclave resumes immediately instead of winning the lock just to find the work
// already done.
func TestAwaitGenesisSkipsLeaseWhenPeerCommitted(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)

	_, err := fx.establish(context.Background())
	require.NoError(t, err)

	// A peer still holds the genesis lease, but the work is already published.
	writeLeaseDoc(t, fx.s3f, leaseObjectKey(testCfg, genesisLeaseName), time.Now().Add(time.Hour))

	// Far shorter than leasePollInterval: passing proves we never waited on it.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	boot := fx.boot()
	lease, err := boot.awaitGenesisLease(ctx, fx.config())

	require.NoError(t, err)
	require.Nil(t, lease, "a published genesis needs no lease")

	planned, err := boot.plan(ctx)
	require.NoError(t, err)
	require.IsType(t, &resumeBoot{}, planned.mode, "a peer's published genesis leaves us resuming")
}

// A peer can publish between our poll and our winning the lease. Winning proves
// nobody else is running genesis, not that genesis has not already happened, so
// the lease must be given straight back rather than used to redo the work.
func TestAwaitGenesisLeaseReleasesWhenPeerCommitsAfterWin(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)
	fx.s3f.beforePut = fx.publishByPeerBefore(t, leaseObjectKey(testCfg, genesisLeaseName))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	lease, err := fx.boot().awaitGenesisLease(ctx, fx.config())

	require.NoError(t, err)
	require.Nil(t, lease, "a genesis completed under us must not leave us holding the lease")
	require.Empty(t, fx.s3f.currentETag(leaseObjectKey(testCfg, genesisLeaseName)),
		"the lease must be released, not held through the resume path")
}

// A holder that died mid-genesis must not wedge the deployment forever - not
// even against its own restart. Once the lease lapses the lock is reclaimable.
func TestAwaitGenesisReclaimsLapsedLock(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)

	// A previous boot died mid-genesis: lock left behind, nothing published.
	writeLeaseDoc(t, fx.s3f, leaseObjectKey(testCfg, genesisLeaseName), time.Now().Add(-time.Hour))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	boot := fx.boot()
	lease, err := boot.awaitGenesisLease(ctx, fx.config())

	require.NoError(t, err)
	require.NotNil(t, lease, "a lapsed lock must be reclaimable")

	planned, err := boot.plan(ctx)
	require.NoError(t, err)
	require.IsType(t, &genesisBoot{}, planned.mode,
		"holding the lease means genesis is still ours to do")
	require.NoError(t, lease.Release(context.Background()))
}

// A live holder is still never displaced.
func TestAwaitGenesisWaitsOnLiveHolder(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	fx := newGenesisFixture(t, pcr0)

	writeLeaseDoc(t, fx.s3f, leaseObjectKey(testCfg, genesisLeaseName), time.Now().Add(time.Hour))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	lease, err := fx.boot().awaitGenesisLease(ctx, fx.config())

	require.Nil(t, lease)
	require.ErrorContains(t, err, "genesis did not complete")
	require.Empty(t, fx.kmsf.keys, "a live holder's genesis must not be duplicated")
}

func TestEstablishGenesisWithoutLeasePublishesNothing(t *testing.T) {
	ctx := t.Context()
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))
	planned, err := fx.boot().plan(ctx)
	require.NoError(t, err)

	_, err = fx.boot().establish(ctx, planned)

	require.ErrorContains(t, err, "refusing to commit genesis without lease")
	require.Empty(t, fx.s3f.objects[snapshotObjectKey(fx.pcr0Hex)])
}

// Losing the lock mid-genesis must stop the publication rather than let it
// race whoever took over.
func TestEstablishGenesisRefusesToPublishAfterLosingTheLease(t *testing.T) {
	ctx := context.Background()
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))
	lease, err := AcquireLease(ctx, testCfg, fx.s3f, testLeaseBucket, genesisLeaseName, leaseTTL)
	require.NoError(t, err)
	planned, err := fx.boot().plan(ctx)
	require.NoError(t, err)
	planned.mode.(*genesisBoot).lease = lease

	// A peer takes the lock over while this enclave is mid-genesis.
	writeLeaseDoc(t, fx.s3f, leaseObjectKey(testCfg, genesisLeaseName), time.Now().Add(time.Hour))

	_, err = fx.boot().establish(ctx, planned)

	require.ErrorContains(t, err, "refusing to commit genesis")
	require.ErrorIs(t, err, ErrLeaseLost)
	require.Empty(t, fx.s3f.objects[snapshotObjectKey(fx.pcr0Hex)])
}

// A replica of the same image that published first wins. Its state differs from
// ours, so ours is never adopted, and the next boot resumes onto the winner.
func TestGenesisLosesToAPeerThatPublishedFirst(t *testing.T) {
	ctx := t.Context()
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))
	lease, err := TryAcquireLease(ctx, testCfg, fx.s3f, testLeaseBucket, genesisLeaseName, leaseTTL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = lease.Release(context.Background()) })
	planned, err := fx.boot().plan(ctx)
	require.NoError(t, err)
	planned.mode.(*genesisBoot).lease = lease
	fx.s3f.beforePut = fx.publishByPeerBefore(t, snapshotObjectKey(fx.pcr0Hex))

	_, err = fx.boot().establish(ctx, planned)

	require.ErrorIs(t, err, errSnapshotConflict)
	state := fx.published(t)
	require.Equal(t, "peer-key", state.kmsKeyID)
}

// Only a measured genesis image may start a lineage: a successor without state
// or a handoff waits, it never genesises.
func TestSuccessorImageNeverGenesises(t *testing.T) {
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xcd}, 48))
	cfg := stateOriginTestConfig()
	cfg.PreviousPCR0 = hex.EncodeToString(bytes.Repeat([]byte{0xab}, 48))
	boot, err := NewBoot(cfg, fx.nsm, fx.kmsf, fx.sts, fx.ssm, fx.s3f)
	require.NoError(t, err)

	_, err = boot.Boot(t.Context())

	require.ErrorContains(t, err, "holds no handoff")
	require.Empty(t, fx.kmsf.keys)
	require.Empty(t, fx.s3f.objects[snapshotObjectKey(fx.pcr0Hex)])
}

// Generation parameters left in SSM, however corrupted, are never consulted.
func TestResumeIgnoresSSMGenerationParams(t *testing.T) {
	ctx := t.Context()
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))
	first, err := fx.establish(ctx)
	require.NoError(t, err)
	keyID := first.kms.KeyID()
	garbage := base64.StdEncoding.EncodeToString([]byte("corrupted"))
	for _, name := range []string{
		testCfg.kmsKeyIDParam(fx.pcr0Hex),
		testCfg.masterSeedCiphertextParam(keyID),
		testCfg.tlsKeyCiphertextParam(keyID),
		testCfg.migrationPreviousPCR0Param(fx.pcr0Hex),
		testCfg.migrationPreviousKMSKeyIDParam(fx.pcr0Hex),
		testCfg.migrationStateOriginReceiptParam(keyID, fx.pcr0Hex),
		testCfg.namespace() + "/StateOriginReceipt/" + keyID + "/" + fx.pcr0Hex,
	} {
		fx.ssmf.params[name] = garbage
	}
	fx.ssmf.calls = nil

	resumed, err := fx.establish(ctx)

	require.NoError(t, err)
	require.Equal(t, first.masterSeed, resumed.masterSeed)
	require.Equal(t, first.snapshot, resumed.snapshot)
	requireNoGenerationSSMReads(t, fx.ssmf)
}

// The intent bucket is measured, never read from SSM. A host that can write the
// application's SSM namespace could otherwise aim the state lookup at an empty
// bucket and have a second generation created beside the live one.
func TestIntentBucketIsMeasuredNotReadFromSSM(t *testing.T) {
	ctx := context.Background()
	fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))
	fx.ssmf.params["/prod/state-origin/enclave/MigrationIntentBucketName"] = "attacker-empty-bucket"

	result, err := fx.establish(ctx)

	require.NoError(t, err)
	require.Equal(t, stateOriginTestMigrationIntentBucket(), result.migrationIntentBucketName)
	require.NotContains(t, fx.ssmf.calls, "/prod/state-origin/enclave/MigrationIntentBucketName")
}

func TestGenesisSnapshotSecretInventory(t *testing.T) {
	for _, count := range []int{0, 2, 15} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			fx := newGenesisFixture(t, mustDecodeHexString(stateOriginTestPCR0Hex()))
			var declarations []StaticSecretMetadata
			for i := 0; i < count; i++ {
				declarations = append(declarations, StaticSecretMetadata{
					Name: fmt.Sprintf("key%d", i), EnvVar: fmt.Sprintf("KEY%d", i),
				})
			}
			snapshot, err := (&genesisBoot{}).buildSnapshot(t.Context(), fx.boot(), &bootConfig{
				cfg: testCfg, secretsMetadata: SecretsMetadata{Static: declarations},
				currentPCR0: mustDecodeHexString(stateOriginTestPCR0Hex()),
			})
			require.NoError(t, err)
			require.EqualValues(t, 1, fx.kmsf.generateCalls,
				"exactly one attested seed generation regardless of declarations")
			require.NotEmpty(t, snapshot.masterSeedCiphertext)
			require.NotEmpty(t, snapshot.tlsKeyCiphertext)
		})
	}
}

func TestBootRejectsInvalidMaterialBeforeCommit(t *testing.T) {
	wrongCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	wrongCurveDER, err := x509.MarshalPKCS8PrivateKey(wrongCurve)
	require.NoError(t, err)
	for _, tc := range []struct {
		name      string
		seed, tls []byte
		wantErr   string
	}{
		{name: "empty seed", seed: []byte{}, wantErr: "seed must be 32 bytes"},
		{name: "short seed", seed: make([]byte, 31), wantErr: "seed must be 32 bytes"},
		{name: "long seed", seed: make([]byte, 33), wantErr: "seed must be 32 bytes"},
		{name: "empty TLS", tls: []byte{}, wantErr: "failed to parse TLS key"},
		{name: "malformed TLS", tls: []byte("not PKCS8"), wantErr: "failed to parse TLS key"},
		{name: "wrong TLS curve", tls: wrongCurveDER, wantErr: "TLS key must be an ECDSA P-256"},
	} {
		for _, mode := range []string{"genesis", "resume"} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				fx := newGenesisFixture(t, bytes.Repeat([]byte{0xab}, 48))
				fx.kmsf.dataKey, fx.kmsf.encrypted = tc.seed, tc.tls
				before := maps.Clone(fx.ssmf.params)
				boot := fx.boot()
				planned, err := boot.plan(t.Context())
				require.NoError(t, err)
				if mode == "resume" {
					snapshot, err := planned.mode.buildSnapshot(t.Context(), boot, &planned.config)
					require.NoError(t, err)
					planned.mode = &resumeBoot{snapshot: snapshot}
				}

				result, err := boot.establish(t.Context(), planned)

				require.ErrorContains(t, err, tc.wantErr)
				require.Equal(t, bootState{}, result)
				require.Equal(t, before, fx.ssmf.params)
				require.Empty(t, fx.s3f.objects, "invalid material must never be published")
				require.Len(t, fx.kmsf.keys, 1, "a resume mints no key of its own")
				require.EqualValues(t, 1, fx.kmsf.generateCalls)
			})
		}
	}
}

// A successor adopts a handoff only when the transition receipt, its
// predecessor's live intent and the predecessor baked into its own image all
// agree; otherwise nothing decrypts and nothing is published.
func TestMigrationBootAdoptsOnlyAnAuthorizedHandoff(t *testing.T) {
	const keyID = "key-migration"
	current := bytes.Repeat([]byte{0xab}, 48)
	prev := bytes.Repeat([]byte{0x99}, 48)
	other := bytes.Repeat([]byte{0x77}, 48)
	currentHex, prevHex, otherHex := hex.EncodeToString(current), hex.EncodeToString(prev),
		hex.EncodeToString(other)
	bootAt := time.Now()

	type intentSeed struct {
		source   []byte
		action   string
		target   string
		sequence uint64
		at       time.Time
		weaken   func(*fakeS3Object)
	}
	requested := func(source []byte, target string) []intentSeed {
		return []intentSeed{{
			source: source, action: migrationIntentRequested, target: target,
			sequence: 1, at: bootAt.Add(-time.Minute),
		}}
	}
	type adoption struct {
		predecessor     string // named by the SSM handoff
		eif             string // ENCLAVE_PREVIOUS_PCR0
		pcrs            map[uint][]byte
		intents         []intentSeed
		tamper          func(map[string]string)
		beforeEstablish func(*fakeS3)
	}
	valid := func() adoption {
		return adoption{
			predecessor: prevHex, eif: prevHex,
			pcrs:    map[uint][]byte{0: prev, migrationPCRIndex: pcrExtendFromZero(current)},
			intents: requested(prev, currentHex),
		}
	}
	type outcome struct {
		ssm    *fakeSSM
		before map[string]string
		s3     *fakeS3
		kms    *fakeKMS
		result bootState
		err    error
	}
	adopt := func(t *testing.T, a adoption) outcome {
		t.Helper()
		ctx := t.Context()
		signer := newTestAttestationSigner(t, bootAt.Add(-24*time.Hour), bootAt.Add(24*time.Hour))
		kmsf := newFakeKMS()
		params := handoffParams(t, testCfg, kmsf, keyID)
		params[testCfg.migrationPreviousPCR0Param(currentHex)] = a.predecessor
		params[testCfg.migrationPreviousKMSKeyIDParam(currentHex)] = "previous-key"
		root, err := Snapshot{
			kmsKeyID: keyID, ownerPCR0: currentHex,
			predecessorPCR0: a.predecessor, predecessorKMSKeyID: "previous-key",
			masterSeedCiphertext:      params[testCfg.masterSeedCiphertextParam(keyID)],
			tlsKeyCiphertext:          params[testCfg.tlsKeyCiphertextParam(keyID)],
			migrationIntentBucketName: stateOriginTestMigrationIntentBucket(),
		}.root(testCfg)

		require.NoError(t, err)
		params[testCfg.migrationStateOriginReceiptParam(keyID, currentHex)] = signer.build(
			t, a.pcrs, bootAt, receiptPayload(t, purposeMigrationTransition, root),
		).docB64
		if a.tamper != nil {
			a.tamper(params)
		}
		fake, ssm := stateOriginTestSSM(params)
		s3f := newFakeS3()
		s3f.versioned = true
		for _, seed := range a.intents {
			seedMigrationIntent(
				t, s3f, signer, seed.source, seed.action, seed.target, seed.sequence, seed.at,
			)
			if seed.weaken != nil {
				objects := s3f.objects[migrationIntentObjectKey(
					hex.EncodeToString(seed.source), seed.sequence,
				)]
				seed.weaken(&objects[len(objects)-1])
			}
		}
		session := newStatefulNSMSession(t, map[uint][]byte{0: current})
		session.attestationSign = signer
		cfg := stateOriginTestConfig()
		cfg.MigrationCooldown = 0
		cfg.PreviousPCR0 = a.eif
		boot := &Boot{
			cfg: cfg, nsm: &nsmW{nsm: &fakeNSM{session: session, verifyRoots: signer.roots}},
			kmsAPI: kmsf, ssm: ssm, s3: s3f, sts: &fakeSTS{}, pcr0: current,
			secretsMetadata: SecretsMetadata{Static: stateOriginTestSecrets},
		}
		out := outcome{ssm: fake, before: maps.Clone(fake.params), s3: s3f, kms: kmsf}
		planned, err := boot.plan(ctx)
		if err != nil {
			out.err = err
			return out
		}
		if a.beforeEstablish != nil {
			a.beforeEstablish(s3f)
		}
		out.result, out.err = boot.establish(ctx, planned)
		return out
	}
	refused := func(t *testing.T, out outcome) {
		t.Helper()
		require.Error(t, out.err)
		require.Zero(t, out.kms.decryptCalls, "nothing may decrypt before the handoff verifies")
		require.Equal(t, out.before, out.ssm.params, "a refused adoption writes nothing to SSM")
		require.Empty(t, out.s3.objects[snapshotObjectKey(currentHex)],
			"a refused adoption publishes nothing")
	}

	t.Run("accepts a valid handoff and publishes both receipts", func(t *testing.T) {
		out := adopt(t, valid())
		require.NoError(t, out.err)
		state := out.result.snapshot
		require.Equal(t, prevHex, state.predecessorPCR0)
		require.Equal(t, "previous-key", state.predecessorKMSKeyID)
		require.Equal(t,
			out.ssm.params[testCfg.migrationStateOriginReceiptParam(keyID, currentHex)],
			state.transitionReceipt,
			"the predecessor's receipt is published as it was written")
		require.Len(t, out.s3.objects[snapshotObjectKey(currentHex)], 1)
		require.Equal(t, out.before, out.ssm.params, "adoption writes nothing to SSM")
		wantSigningKey, err := deriveResponseSigningKey(out.result.masterSeed, current)
		require.NoError(t, err)
		require.Equal(t, wantSigningKey, out.result.responseSigningKey)
	})

	for _, tc := range []struct {
		name   string
		modify func(*adoption)
		is     error
		msg    string
	}{
		{
			name: "rejects a transition receipt with the wrong PCR31",
			modify: func(a *adoption) {
				a.pcrs[migrationPCRIndex] = pcrExtendFromZero(other)
			},
			msg: "invalid transition receipt",
		},
		{
			name: "rejects a ciphertext swapped after the receipt was signed",
			modify: func(a *adoption) {
				a.tamper = func(p map[string]string) {
					p[testCfg.masterSeedCiphertextParam(keyID)] = base64.StdEncoding.EncodeToString(
						bytes.Repeat([]byte{0x5a}, 32),
					)
				}
			},
			msg: "invalid transition receipt",
		},
		{
			name:   "refuses when no intent was ever recorded",
			modify: func(a *adoption) { a.intents = nil },
			is:     errMigrationIntentAbsent,
		},
		{
			name: "refuses an intent naming another successor",
			modify: func(a *adoption) {
				a.intents = []intentSeed{{
					source: prev, action: migrationIntentRequested, target: otherHex,
					sequence: 1, at: bootAt.Add(-time.Hour),
				}}
			},
			is: errMigrationIntentAborted,
		},
		{
			name: "refuses when a later abort revoked the authorization",
			modify: func(a *adoption) {
				a.intents = []intentSeed{
					{
						source: prev, action: migrationIntentRequested, target: currentHex,
						sequence: 1, at: bootAt.Add(-3 * time.Hour),
					},
					{
						source: prev, action: migrationIntentAborted, target: currentHex,
						sequence: 2, at: bootAt.Add(-2 * time.Hour),
					},
				}
			},
			is: errMigrationIntentAborted,
		},
		{
			name: "fails closed when the intent store is unreadable",
			modify: func(a *adoption) {
				a.beforeEstablish = func(s3f *fakeS3) { s3f.listErr = errors.New("s3 unavailable") }
			},
			is: errMigrationIntentStoreUnavailable,
		},
		{
			// B commits to A, but the host supplies Z's genuine handoff under B's PCR0.
			name: "rejects another predecessor's handoff",
			modify: func(a *adoption) {
				a.predecessor = otherHex
				a.pcrs = map[uint][]byte{0: other, migrationPCRIndex: pcrExtendFromZero(current)}
				a.intents = requested(other, currentHex)
			},
			msg: "does not match previous PCR0 committed in the EIF",
		},
		{
			name:   "rejects an image that commits to no predecessor",
			modify: func(a *adoption) { a.eif = "" },
			msg:    "does not match previous PCR0 committed in the EIF",
		},
		{
			name: "rejects an enclave as its own predecessor",
			modify: func(a *adoption) {
				a.predecessor = currentHex
				a.pcrs = map[uint][]byte{0: current, migrationPCRIndex: pcrExtendFromZero(other)}
				a.intents = nil
			},
			msg: "cannot be its own predecessor",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := valid()
			tc.modify(&a)
			out := adopt(t, a)
			if tc.is != nil {
				require.ErrorIs(t, out.err, tc.is)
			} else {
				require.ErrorContains(t, out.err, tc.msg)
			}
			refused(t, out)
		})
	}

	// Keep the predecessor and signed intent valid; only its S3 Object Lock
	// metadata changes. An unprotected request must not authorize adoption.
	for _, tc := range []struct {
		name   string
		weaken func(*fakeS3Object)
	}{
		{"missing compliance mode", func(o *fakeS3Object) { o.lockMode = "" }},
		{"governance instead of compliance", func(o *fakeS3Object) {
			o.lockMode = s3types.ObjectLockModeGovernance
		}},
		{"missing retention deadline", func(o *fakeS3Object) { o.retainUntil = time.Time{} }},
		{"retention below tolerated minimum", func(o *fakeS3Object) {
			cfg := migrationTestCfg()
			o.retainUntil = o.lastModified.Add(
				cfg.IntentRetention - cfg.IntentWriteTimeout - time.Second,
			)
		}},
	} {
		t.Run("refuses intent with "+tc.name, func(t *testing.T) {
			a := valid()
			a.intents[0].weaken = tc.weaken
			out := adopt(t, a)
			require.ErrorIs(t, out.err, errMigrationIntentAbsent)
			require.ErrorContains(t, out.err, "recorded no intent")
			refused(t, out)
		})
	}

	t.Run("adopts when a re-request superseded an earlier abort", func(t *testing.T) {
		a := valid()
		a.intents = []intentSeed{
			{
				source: prev, action: migrationIntentRequested, target: currentHex,
				sequence: 1, at: bootAt.Add(-5 * time.Hour),
			},
			{
				source: prev, action: migrationIntentAborted, target: currentHex,
				sequence: 2, at: bootAt.Add(-4 * time.Hour),
			},
			{
				source: prev, action: migrationIntentRequested, target: currentHex,
				sequence: 3, at: bootAt.Add(-3 * time.Hour),
			},
		}
		require.NoError(t, adopt(t, a).err)
	})
}

// The whole handoff through the real predecessor and successor code. Replicas
// of the successor converge on one published state, an adoption interrupted
// before publishing is simply redone, and the published state alone keeps the
// successor booting once its predecessor's key is deleted and the SSM handoff
// is wiped and rewritten.
func TestMigrationSnapshotOutlivesItsHandoff(t *testing.T) {
	ctx := t.Context()
	blue, green := bytes.Repeat([]byte{0xab}, 48), bytes.Repeat([]byte{0xcd}, 48)
	blueHex, greenHex := hex.EncodeToString(blue), hex.EncodeToString(green)
	fx := newGenesisFixture(t, blue)
	genesis, err := fx.establish(ctx)
	require.NoError(t, err)
	m, err := newMigrator(
		migrationTestCfg(), fx.nsm, fx.ssm, fx.s3f, genesis.migrationIntentBucketName,
	)
	require.NoError(t, err)
	m.kms, m.masterSeed, m.tlsKey = genesis.kms, genesis.masterSeed, genesis.tlsKey
	_, err = requestMigrationTo(t, ctx, m, fx.signer, greenHex)
	require.NoError(t, err)
	require.NoError(t, m.handOffToSuccessor(ctx, leaseHeld))

	cfg := stateOriginTestConfig()
	cfg.PreviousPCR0 = blueHex
	session := newStatefulNSMSession(t, map[uint][]byte{0: green})
	session.attestationSign = fx.signer
	nsm := &nsmW{nsm: &fakeNSM{session: session, verifyRoots: fx.signer.roots}}
	newGreen := func() *Boot {
		b, err := NewBoot(cfg, nsm, fx.kmsf, fx.sts, fx.ssm, fx.s3f)
		require.NoError(t, err)
		return b
	}

	fx.s3f.putErr = errors.New("s3 unwritable")
	_, err = newGreen().Boot(ctx)
	require.ErrorContains(t, err, "s3 unwritable")
	fx.s3f.putErr = nil
	unpublished, err := readSnapshot(
		ctx, cfg, fx.s3f, nsm, genesis.migrationIntentBucketName, greenHex,
	)
	require.NoError(t, err)
	require.Nil(t, unpublished, "an interrupted adoption leaves nothing adopted")

	// Two replicas that both planned an adoption race to publish it.
	var replicas []bootState
	planned := make([]*plannedBoot, 2)
	for i := range planned {
		planned[i], err = newGreen().plan(ctx)
		require.NoError(t, err)
		require.IsType(t, &migrationBoot{}, planned[i].mode)
	}
	for _, p := range planned {
		result, err := newGreen().establish(ctx, p)
		require.NoError(t, err)
		replicas = append(replicas, result)
	}
	adopted := replicas[0]
	require.Equal(t, adopted.snapshot, replicas[1].snapshot)
	require.Len(t, fx.s3f.objects[snapshotObjectKey(greenHex)], 1)

	// The seed crossed over, so every derived secret did too; so did the TLS key.
	require.Equal(t, genesis.masterSeed, adopted.masterSeed)
	require.Equal(t, genesis.dek, adopted.dek)
	require.Equal(t, genesis.acmeAccountKey, adopted.acmeAccountKey)
	require.Equal(t, genesis.tlsKey, adopted.tlsKey)
	require.Equal(t, genesis.secrets.Static, adopted.secrets.Static)
	require.NotEqual(t, genesis.kms.KeyID(), adopted.kms.KeyID())
	require.Equal(t, greenHex, adopted.snapshot.ownerPCR0)
	require.Equal(t, adopted.kms.KeyID(), adopted.snapshot.kmsKeyID)
	require.Equal(t, blueHex, adopted.snapshot.predecessorPCR0)
	require.Equal(t, genesis.kms.KeyID(), adopted.snapshot.predecessorKMSKeyID)

	fx.kmsf.deleteKey(genesis.kms.KeyID())
	for name := range fx.ssmf.params {
		if name != testCfg.leaseBucketParam() {
			delete(fx.ssmf.params, name)
		}
	}
	fx.ssmf.params[testCfg.kmsKeyIDParam(greenHex)] = "rewritten-key"
	fx.ssmf.params[testCfg.migrationPreviousPCR0Param(greenHex)] = hex.EncodeToString(
		bytes.Repeat([]byte{0x77}, 48),
	)
	fx.ssmf.calls = nil

	resumed, err := newGreen().Boot(ctx)

	require.NoError(t, err)
	require.Equal(t, adopted.snapshot, resumed.snapshot)
	require.Equal(t, adopted.kms.KeyID(), resumed.kms.KeyID())
	require.Equal(t, genesis.masterSeed, resumed.masterSeed)
	require.Len(t, fx.s3f.objects[snapshotObjectKey(greenHex)], 1)
	requireNoGenerationSSMReads(t, fx.ssmf)
	require.Equal(t, keyStateDeleted, resumed.kms.KeyState(ctx, genesis.kms.KeyID()))
}

// stateOriginTestPCR0Hex is the PCR0 every boot test runs as.
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
	return migrationIntentBucketName(testCfg, fakeSTSAccountID)
}

// stateOriginTestConfig is a genesis image declaring two static secrets.
func stateOriginTestConfig() *Config {
	cfg := testConfig()
	cfg.PreviousPCR0 = genesisPreviousPCR0
	cfg.StaticSecretConfig = `[
		{"name":"alpha","env_var":"ALPHA"},
		{"name":"beta","env_var":"BETA"}
	]`
	return cfg
}

func stateOriginTestSSM(params map[string]string) (*fakeSSM, SSM) {
	fake := &fakeSSM{params: map[string]string{}}
	maps.Copy(fake.params, params)
	return fake, NewSSM(fake)
}

// testHandoffSeed is the master seed every test handoff carries.
var testHandoffSeed = bytes.Repeat([]byte{0x42}, 32)

// handoffParams is a handoff a predecessor writes for the test PCR0: the
// pointer, and the seed and a fresh TLS key encrypted under keyID, which kmsf
// admits for that PCR0 alone.
func handoffParams(t *testing.T, cfg *Config, kmsf *fakeKMS, keyID string) map[string]string {
	t.Helper()
	identity, err := (&fakeSTS{}).GetCallerIdentity(t.Context(), nil)
	require.NoError(t, err)
	recovery := ""
	if !cfg.KMSLocked {
		recovery = aws.ToString(identity.Arn)
	}
	policy, err := NewKMSPolicy(aws.ToString(identity.Arn), stateOriginTestPCR0Hex(), recovery)
	require.NoError(t, err)
	policyJSON, err := policy.Encode()
	require.NoError(t, err)
	kmsf.putKey(keyID, policyJSON)

	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tlsKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	require.NoError(t, err)
	encrypt := func(plaintext []byte) string {
		out, err := kmsf.Encrypt(t.Context(), &kmscmd.EncryptInput{
			KeyId: aws.String(keyID), Plaintext: plaintext,
		})
		require.NoError(t, err)
		return base64.StdEncoding.EncodeToString(out.CiphertextBlob)
	}
	return map[string]string{
		cfg.kmsKeyIDParam(stateOriginTestPCR0Hex()): keyID,
		cfg.masterSeedCiphertextParam(keyID):        encrypt(testHandoffSeed),
		cfg.tlsKeyCiphertextParam(keyID):            encrypt(tlsKeyPKCS8),
	}
}

func receiptPayload(t *testing.T, purpose string, stateRoot []byte) []byte {
	t.Helper()
	payload, err := cbor.Marshal(snapshotRootPayloadV1{Purpose: purpose, SnapshotRoot: stateRoot})
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

func originReceiptPayload(t *testing.T, stateRoot []byte, snapshot Snapshot) []byte {
	t.Helper()
	payload, err := cbor.Marshal(snapshot.originPayload(stateRoot))
	require.NoError(t, err)
	return payload
}

func signedOriginReceipt(
	t *testing.T, pcrs map[uint][]byte, stateRoot []byte, snapshot Snapshot,
) signedAttestation {
	t.Helper()
	now := time.Now()
	return buildSignedAttestationCustom(
		t, pcrs, now.Add(-time.Hour), now.Add(time.Hour), now,
		originReceiptPayload(t, stateRoot, snapshot),
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
	signer  *testAttestationSigner
	pcr0Hex string
}

// keyIDParam is the handoff pointer a predecessor commits for this PCR0.
func (f *genesisFixture) keyIDParam() string { return testCfg.kmsKeyIDParam(f.pcr0Hex) }

func newGenesisFixture(t *testing.T, pcr0 []byte) *genesisFixture {
	t.Helper()
	session := newStatefulNSMSession(t, map[uint][]byte{0: pcr0})
	ssmf, ssm := stateOriginTestSSM(map[string]string{
		testCfg.leaseBucketParam(): testLeaseBucket,
	})
	s3f := newFakeS3()
	s3f.versioned = true
	return &genesisFixture{
		nsm:     &nsmW{nsm: &fakeNSM{session: session, verifyRoots: session.attestationSign.roots}},
		pcr0Hex: hex.EncodeToString(pcr0),
		ssmf:    ssmf,
		ssm:     ssm,
		s3f:     s3f,
		kmsf:    newFakeKMS(),
		sts:     &fakeSTS{arn: testRoleARN},
		signer:  session.attestationSign,
	}
}

func (f *genesisFixture) boot() *Boot {
	return &Boot{
		cfg: stateOriginTestConfig(), nsm: f.nsm, kmsAPI: f.kmsf, sts: f.sts, ssm: f.ssm,
		s3: f.s3f, pcr0: mustDecodeHexString(f.pcr0Hex),
		secretsMetadata: SecretsMetadata{Static: stateOriginTestSecrets},
	}
}

// config is what plan derives for this fixture's boots.
func (f *genesisFixture) config() *bootConfig {
	return &bootConfig{
		cfg: stateOriginTestConfig(), currentPCR0: mustDecodeHexString(f.pcr0Hex),
		snapshotBucket: stateOriginTestMigrationIntentBucket(),
	}
}

func (f *genesisFixture) establish(ctx context.Context) (bootState, error) {
	boot, err := NewBoot(stateOriginTestConfig(), f.nsm, f.kmsf, f.sts, f.ssm, f.s3f)
	if err != nil {
		return bootState{}, err
	}
	return boot.Boot(ctx)
}

func (f *genesisFixture) published(t *testing.T) *Snapshot {
	t.Helper()
	state, err := readSnapshot(
		t.Context(), testCfg, f.s3f, f.nsm, stateOriginTestMigrationIntentBucket(), f.pcr0Hex,
	)
	require.NoError(t, err)
	require.NotNil(t, state)
	return state
}

// publishByPeerBefore returns a fakeS3.beforePut hook that lands a peer
// replica's genesis state, keyed "peer-key", just before the first write to key.
func (f *genesisFixture) publishByPeerBefore(t *testing.T, key string) func(string) {
	t.Helper()
	body := (&snapshotTestFixture{signer: f.signer}).body(
		t, testGenerationSnapshot(mustDecodeHexString(f.pcr0Hex), nil, "peer-key"), nil,
	)
	stateKey := snapshotObjectKey(f.pcr0Hex)
	done := false
	return func(written string) {
		if done || written != key {
			return
		}
		done = true
		// beforePut runs holding the fake's lock.
		now := time.Now().UTC()
		f.s3f.seq++
		f.s3f.objects[stateKey] = append(f.s3f.objects[stateKey], fakeS3Object{
			id: fmt.Sprintf("peer-%d", f.s3f.seq), etag: `"peer"`, body: body,
			lockMode: s3types.ObjectLockModeCompliance, retainUntil: now.Add(prodRetention),
			lastModified: now.Add(-time.Second),
		})
	}
}

func mustDecodeHexString(s string) []byte {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return decoded
}

// seedMigrationIntent writes a genuinely signed intent record into the fake log,
// so a successor's authorization check reads it exactly as it would a record a
// predecessor published. publishedAt drives the cooldown and abort ordering the
// check applies, so callers set it relative to the handoff they are modelling.
func seedMigrationIntent(
	t *testing.T,
	s3f *fakeS3,
	signer *testAttestationSigner,
	sourcePCR0 []byte,
	action, targetPCR0 string,
	sequence uint64,
	publishedAt time.Time,
) {
	t.Helper()
	enc, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	payload, err := enc.Marshal(migrationIntentV1{
		Schema:     migrationIntentSchemaV1,
		BucketName: stateOriginTestMigrationIntentBucket(),
		Sequence:   sequence,
		Action:     action,
		TargetPCR0: targetPCR0,
	})
	require.NoError(t, err)

	attestation := signer.build(t, map[uint][]byte{0: sourcePCR0}, publishedAt, payload)
	body, err := json.Marshal(migrationIntentObjectV1{
		Schema:      migrationIntentSchemaV1,
		Sequence:    sequence,
		Action:      action,
		TargetPCR0:  targetPCR0,
		Attestation: attestation.docB64,
	})
	require.NoError(t, err)
	s3f.putRawObjectAt(
		migrationIntentObjectKey(hex.EncodeToString(sourcePCR0), sequence),
		body,
		publishedAt,
	)
}

var (
	snapshotTestOwner       = bytes.Repeat([]byte{0xab}, 48)
	snapshotTestPredecessor = bytes.Repeat([]byte{0x99}, 48)
)

// snapshotTestFixture reads and writes snapshot/<pcr0> with genuinely signed
// receipts, so every check under test is the real verification.
type snapshotTestFixture struct {
	s3f    *fakeS3
	signer *testAttestationSigner
	boot   *Boot
}

// ownerNSM attests as pcr0 and verifies with the real, stateless verifier, so
// concurrent publishers can share it.
type ownerNSM struct {
	NSM
	t      *testing.T
	signer *testAttestationSigner
	pcr0   []byte
}

func (n ownerNSM) BuildAttestationDocument(
	opts ...BuildAttestationOption,
) ([]byte, *rsa.PrivateKey, error) {
	var o BuildAttestationOptions
	for _, opt := range opts {
		opt(&o)
	}
	return n.signer.build(n.t, map[uint][]byte{0: n.pcr0}, time.Now(), o.userData).doc, nil, nil
}

func newSnapshotTestFixture(t *testing.T) *snapshotTestFixture {
	t.Helper()
	now := time.Now()
	signer := newTestAttestationSigner(t, now.Add(-time.Hour), now.Add(time.Hour))
	s3f := newFakeS3()
	s3f.versioned = true
	nsm := ownerNSM{
		NSM: &nsmW{nsm: &awsNSM{roots: signer.roots}}, t: t, signer: signer,
		pcr0: snapshotTestOwner,
	}
	boot := &Boot{cfg: testCfg, s3: s3f, nsm: nsm}
	return &snapshotTestFixture{s3f: s3f, signer: signer, boot: boot}
}

func testGenerationSnapshot(owner, predecessor []byte, keyID string) Snapshot {
	snapshot := Snapshot{
		kmsKeyID:                  keyID,
		ownerPCR0:                 hex.EncodeToString(owner),
		masterSeedCiphertext:      base64.StdEncoding.EncodeToString([]byte("seed-ct-" + keyID)),
		tlsKeyCiphertext:          base64.StdEncoding.EncodeToString([]byte("tls-ct-" + keyID)),
		migrationIntentBucketName: stateOriginTestMigrationIntentBucket(),
	}
	if predecessor != nil {
		snapshot.predecessorPCR0 = hex.EncodeToString(predecessor)
		snapshot.predecessorKMSKeyID = "predecessor-key"
	}
	return snapshot
}

// receipts signs root as the owner and, for a migrated snapshot, as its
// predecessor with PCR31 committed to the owner.
func (f *snapshotTestFixture) receipts(
	t *testing.T, snapshot Snapshot, root []byte,
) (transition, origin string) {
	t.Helper()
	owner := mustDecodeHex(t, snapshot.ownerPCR0)
	payload, err := cbor.Marshal(snapshot.originPayload(root))
	require.NoError(t, err)
	origin = f.signer.build(t, map[uint][]byte{0: owner}, time.Now(), payload).docB64
	if snapshot.predecessorPCR0 != "" {
		transition = f.signer.build(t, map[uint][]byte{
			0:                 mustDecodeHex(t, snapshot.predecessorPCR0),
			migrationPCRIndex: pcrExtendFromZero(owner),
		}, time.Now(), receiptPayload(t, purposeMigrationTransition, root)).docB64
	}
	return transition, origin
}

// body encodes snapshot as a state object with genuine receipts; mutate runs
// after signing, to forge what a host could write.
func (f *snapshotTestFixture) body(
	t *testing.T, snapshot Snapshot, mutate func(*snapshotObjectV1),
) []byte {
	t.Helper()
	raw, err := snapshot.encode(testCfg)
	require.NoError(t, err)
	transition, origin := f.receipts(t, snapshot, snapshotRootOf(raw))
	obj := snapshotObjectV1{
		Schema: snapshotObjectSchemaV1, Snapshot: raw,
		TransitionAttestation: transition, OriginAttestation: origin,
	}
	if mutate != nil {
		mutate(&obj)
	}
	body, err := json.Marshal(obj)
	require.NoError(t, err)
	return body
}

func withTransition(snapshot Snapshot, transition string) Snapshot {
	snapshot.transitionReceipt = transition
	return snapshot
}

// snapshotRootOf is the root over an already encoded snapshot.
func snapshotRootOf(raw []byte) []byte {
	sum := sha256.Sum256(append([]byte(snapshotRootDomainV1), raw...))
	return sum[:]
}

func (f *snapshotTestFixture) seed(t *testing.T, owner []byte, body []byte, at time.Time) {
	t.Helper()
	f.s3f.putRawObjectAt(snapshotObjectKey(hex.EncodeToString(owner)), body, at)
}

func (f *snapshotTestFixture) read(t *testing.T, owner []byte) (*Snapshot, error) {
	t.Helper()
	return readSnapshot(
		t.Context(), f.boot.cfg, f.s3f, f.boot.nsm, stateOriginTestMigrationIntentBucket(),
		hex.EncodeToString(owner),
	)
}

func TestSnapshotRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		dev  bool
	}{
		{"prod", false},
		{"dev", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newTestConfig(testCfg.Namespace, testCfg.AppName, tc.dev)
			for _, predecessor := range [][]byte{nil, snapshotTestPredecessor} {
				fx := newSnapshotTestFixture(t)
				fx.boot.cfg = cfg
				snapshot := testGenerationSnapshot(snapshotTestOwner, predecessor, "key-1")
				root, err := snapshot.root(cfg)
				require.NoError(t, err)
				transition, _ := fx.receipts(t, snapshot, root)

				published, err := fx.boot.publishSnapshot(
					t.Context(),
					withTransition(snapshot, transition),
				)
				require.NoError(t, err)

				require.Equal(t, withTransition(snapshot, transition), *published)
				publishedRoot, err := (*published).root(cfg)
				require.NoError(t, err)
				require.Equal(t, root, publishedRoot, "the receipts are not part of the root")
				read, err := fx.read(t, snapshotTestOwner)
				require.NoError(t, err)
				require.Equal(t, published, read)

				objects := fx.s3f.objects[snapshotObjectKey(snapshot.ownerPCR0)]
				require.Len(t, objects, 1)
				require.Equal(t, s3types.ObjectLockModeCompliance, objects[0].lockMode)
				require.WithinDuration(
					t,
					time.Now().Add(cfg.SnapshotRetention),
					objects[0].retainUntil,
					10*time.Second,
				)
			}
		})
	}
}

func TestSnapshotAbsentKeyIsNoSnapshot(t *testing.T) {
	state, err := newSnapshotTestFixture(t).read(t, snapshotTestOwner)
	require.NoError(t, err)
	require.Nil(t, state)
}

// No version a host could write on its own may be adopted. With nothing valid
// beside it, the key is unverifiable rather than empty, so it cannot invite a
// genesis either.
func TestSnapshotRejectsInvalidVersions(t *testing.T) {
	genesis := testGenerationSnapshot(snapshotTestOwner, nil, "key-1")
	migrated := testGenerationSnapshot(snapshotTestOwner, snapshotTestPredecessor, "key-1")
	otherPCR0 := bytes.Repeat([]byte{0x77}, 48)
	resign := func(t *testing.T, fx *snapshotTestFixture, obj *snapshotObjectV1, snapshot Snapshot) {
		obj.TransitionAttestation, obj.OriginAttestation = fx.receipts(
			t, snapshot, snapshotRootOf(obj.Snapshot),
		)
	}
	encodeWith := func(t *testing.T, doc any) []byte {
		raw, err := cbor.Marshal(doc)
		require.NoError(t, err)
		return raw
	}
	snapshotDoc := func(t *testing.T, s Snapshot) snapshotV1 {
		raw, err := s.encode(testCfg)
		require.NoError(t, err)
		var doc snapshotV1
		require.NoError(t, cbor.Unmarshal(raw, &doc))
		return doc
	}

	for _, tc := range []struct {
		name     string
		snapshot Snapshot
		mutate   func(*testing.T, *snapshotTestFixture, *snapshotObjectV1)
		raw      func(*testing.T, *snapshotTestFixture) []byte
		lock     func(*fakeS3Object)
		wantErr  string
	}{
		{
			name: "tampered master seed ciphertext", snapshot: genesis,
			mutate: func(t *testing.T, _ *snapshotTestFixture, obj *snapshotObjectV1) {
				doc := snapshotDoc(t, genesis)
				doc.MasterSeedCiphertext[0] ^= 0xff
				var err error
				obj.Snapshot, err = encodeSnapshotDoc(doc)
				require.NoError(t, err)
			},
			wantErr: "invalid state-origin receipt",
		},
		{
			name: "tampered TLS key ciphertext", snapshot: genesis,
			mutate: func(t *testing.T, _ *snapshotTestFixture, obj *snapshotObjectV1) {
				doc := snapshotDoc(t, genesis)
				doc.TLSKeyCiphertext[0] ^= 0xff
				var err error
				obj.Snapshot, err = encodeSnapshotDoc(doc)
				require.NoError(t, err)
			},
			wantErr: "invalid state-origin receipt",
		},
		{
			name: "missing master seed ciphertext",
			raw: func(t *testing.T, fx *snapshotTestFixture) []byte {
				snapshot := genesis
				snapshot.masterSeedCiphertext = ""
				return fx.body(t, snapshot, nil)
			},
			wantErr: "snapshot is incomplete",
		},
		{
			name: "missing TLS key ciphertext",
			raw: func(t *testing.T, fx *snapshotTestFixture) []byte {
				snapshot := genesis
				snapshot.tlsKeyCiphertext = ""
				return fx.body(t, snapshot, nil)
			},
			wantErr: "snapshot is incomplete",
		},
		{
			name: "non-canonical snapshot encoding", snapshot: genesis,
			mutate: func(t *testing.T, fx *snapshotTestFixture, obj *snapshotObjectV1) {
				obj.Snapshot = encodeWith(t, snapshotDoc(t, genesis)) // struct order, not canonical
				resign(t, fx, obj, genesis)
			},
		},
		{
			name: "unknown snapshot field", snapshot: genesis,
			mutate: func(t *testing.T, fx *snapshotTestFixture, obj *snapshotObjectV1) {
				doc := snapshotDoc(t, genesis)
				enc, err := cbor.CoreDetEncOptions().EncMode()
				require.NoError(t, err)
				obj.Snapshot, err = enc.Marshal(struct {
					snapshotV1
					Extra string `cbor:"extra"`
				}{doc, "x"})
				require.NoError(t, err)
				resign(t, fx, obj, genesis)
			},
		},
		{
			name: "snapshot of another deployment", snapshot: genesis,
			mutate: func(t *testing.T, fx *snapshotTestFixture, obj *snapshotObjectV1) {
				other := *testCfg
				other.Namespace = "other"
				raw, err := genesis.encode(&other)
				require.NoError(t, err)
				obj.Snapshot = raw
				resign(t, fx, obj, genesis)
			},
		},
		{
			name: "snapshot naming another bucket", snapshot: genesis,
			mutate: func(t *testing.T, fx *snapshotTestFixture, obj *snapshotObjectV1) {
				moved := genesis
				moved.migrationIntentBucketName = "attacker-bucket"
				raw, err := moved.encode(testCfg)
				require.NoError(t, err)
				obj.Snapshot = raw
				resign(t, fx, obj, moved)
			},
		},
		{
			name: "another PCR0's state copied in",
			raw: func(t *testing.T, fx *snapshotTestFixture) []byte {
				return fx.body(t, testGenerationSnapshot(otherPCR0, nil, "key-1"), nil)
			},
		},
		{
			name: "unknown envelope field", snapshot: genesis,
			raw: func(t *testing.T, fx *snapshotTestFixture) []byte {
				body := fx.body(t, genesis, nil)
				return append(body[:len(body)-1], []byte(`,"extra":1}`)...)
			},
		},
		{
			name: "non-canonical envelope",
			raw: func(t *testing.T, fx *snapshotTestFixture) []byte {
				return append(fx.body(t, genesis, nil), '\n')
			},
		},
		{
			name: "unexpected schema", snapshot: genesis,
			mutate: func(_ *testing.T, _ *snapshotTestFixture, obj *snapshotObjectV1) {
				obj.Schema = "enclave.generation_state.v0"
			},
		},
		{
			name: "forged origin receipt", snapshot: genesis,
			mutate: func(t *testing.T, _ *snapshotTestFixture, obj *snapshotObjectV1) {
				obj.OriginAttestation = base64.StdEncoding.EncodeToString(
					buildForgedAttestation(t, map[uint][]byte{0: snapshotTestOwner}),
				)
			},
		},
		{
			name: "origin receipt from another PCR0", snapshot: genesis,
			mutate: func(t *testing.T, fx *snapshotTestFixture, obj *snapshotObjectV1) {
				payload, err := cbor.Marshal(
					genesis.originPayload(snapshotRootOf(obj.Snapshot)),
				)
				require.NoError(t, err)
				obj.OriginAttestation = fx.signer.build(
					t, map[uint][]byte{0: otherPCR0}, time.Now(), payload,
				).docB64
			},
		},
		{
			name: "origin receipt over another root", snapshot: genesis,
			mutate: func(t *testing.T, fx *snapshotTestFixture, obj *snapshotObjectV1) {
				_, obj.OriginAttestation = fx.receipts(t, genesis, []byte("other-root"))
			},
		},
		{
			name: "genesis state carrying a transition receipt", snapshot: genesis,
			mutate: func(t *testing.T, fx *snapshotTestFixture, obj *snapshotObjectV1) {
				obj.TransitionAttestation, _ = fx.receipts(
					t, migrated, snapshotRootOf(obj.Snapshot),
				)
			},
		},
		{
			name: "migrated state without a transition receipt", snapshot: migrated,
			mutate: func(_ *testing.T, _ *snapshotTestFixture, obj *snapshotObjectV1) {
				obj.TransitionAttestation = ""
			},
		},
		{
			name: "transition receipt with the wrong PCR31", snapshot: migrated,
			mutate: func(t *testing.T, fx *snapshotTestFixture, obj *snapshotObjectV1) {
				obj.TransitionAttestation = fx.signer.build(t, map[uint][]byte{
					0:                 snapshotTestPredecessor,
					migrationPCRIndex: pcrExtendFromZero(otherPCR0),
				}, time.Now(), receiptPayload(
					t, purposeMigrationTransition, snapshotRootOf(obj.Snapshot),
				)).docB64
			},
		},
		{
			name: "transition receipt from another predecessor", snapshot: migrated,
			mutate: func(t *testing.T, fx *snapshotTestFixture, obj *snapshotObjectV1) {
				obj.TransitionAttestation = fx.signer.build(t, map[uint][]byte{
					0:                 otherPCR0,
					migrationPCRIndex: pcrExtendFromZero(snapshotTestOwner),
				}, time.Now(), receiptPayload(
					t, purposeMigrationTransition, snapshotRootOf(obj.Snapshot),
				)).docB64
			},
		},
		{
			name: "transition receipt with the origin purpose", snapshot: migrated,
			mutate: func(t *testing.T, fx *snapshotTestFixture, obj *snapshotObjectV1) {
				obj.TransitionAttestation = fx.signer.build(t, map[uint][]byte{
					0:                 snapshotTestPredecessor,
					migrationPCRIndex: pcrExtendFromZero(snapshotTestOwner),
				}, time.Now(), receiptPayload(
					t, purposeStateOrigin, snapshotRootOf(obj.Snapshot),
				)).docB64
			},
		},
		{
			name: "no object lock", snapshot: genesis,
			lock: func(o *fakeS3Object) { o.lockMode = "" },
		},
		{
			name: "governance instead of compliance", snapshot: genesis,
			lock: func(o *fakeS3Object) { o.lockMode = s3types.ObjectLockModeGovernance },
		},
		{
			name: "retention below the state retention", snapshot: genesis,
			lock: func(o *fakeS3Object) {
				o.retainUntil = o.lastModified.Add(
					testCfg.SnapshotRetention - testCfg.IntentWriteTimeout - time.Second,
				)
			},
		},
		{
			name: "multipart upload", snapshot: genesis,
			lock: func(o *fakeS3Object) { o.partsCount = aws.Int32(1) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newSnapshotTestFixture(t)
			var body []byte
			switch {
			case tc.raw != nil:
				body = tc.raw(t, fx)
			default:
				body = fx.body(t, tc.snapshot, func(obj *snapshotObjectV1) {
					if tc.mutate != nil {
						tc.mutate(t, fx, obj)
					}
				})
			}
			if tc.wantErr != "" {
				_, err := parseSnapshotObject(testCfg, fx.boot.nsm, body)
				require.ErrorContains(t, err, tc.wantErr)
			}
			fx.seed(t, snapshotTestOwner, body, time.Now())
			if tc.lock != nil {
				objects := fx.s3f.objects[snapshotObjectKey(hex.EncodeToString(snapshotTestOwner))]
				tc.lock(&objects[len(objects)-1])
			}

			state, err := fx.read(t, snapshotTestOwner)

			require.ErrorIs(t, err, errSnapshotUnverifiable)
			require.Nil(t, state)
		})
	}
}

// Object Lock protects versions, not the key. Whatever a host stacks on top -
// a newer valid state, garbage, a delete marker - the first valid version stands.
func TestSnapshotEarliestValidVersionWins(t *testing.T) {
	fx := newSnapshotTestFixture(t)
	base := time.Now().Add(-time.Hour)
	key := snapshotObjectKey(hex.EncodeToString(snapshotTestOwner))
	genuine := testGenerationSnapshot(snapshotTestOwner, nil, "genuine-key")

	fx.s3f.putRawObjectAt(key, []byte("garbage before"), base.Add(-time.Minute))
	fx.seed(t, snapshotTestOwner, fx.body(t, genuine, nil), base)
	fx.seed(t, snapshotTestOwner,
		fx.body(t, testGenerationSnapshot(snapshotTestOwner, nil, "later-key"), nil),
		base.Add(time.Minute))
	fx.s3f.putRawObjectAt(key, []byte("garbage after"), base.Add(2*time.Minute))
	_, err := fx.s3f.DeleteObject(t.Context(), &s3.DeleteObjectInput{Key: aws.String(key)})
	require.NoError(t, err)

	state, err := fx.read(t, snapshotTestOwner)

	require.NoError(t, err)
	require.Equal(t, genuine.kmsKeyID, state.kmsKeyID)
}

func TestSnapshotTieFailsClosedUnlessEquivalent(t *testing.T) {
	at := time.Now().Add(-time.Hour)
	a := testGenerationSnapshot(snapshotTestOwner, nil, "key-a")

	fx := newSnapshotTestFixture(t)
	fx.seed(t, snapshotTestOwner, fx.body(t, a, nil), at)
	fx.seed(t, snapshotTestOwner, fx.body(t, a, nil), at)
	state, err := fx.read(t, snapshotTestOwner)
	require.NoError(t, err, "two receipts over one root are the same state")
	require.Equal(t, a.kmsKeyID, state.kmsKeyID)

	fx = newSnapshotTestFixture(t)
	fx.seed(t, snapshotTestOwner, fx.body(t, a, nil), at)
	fx.seed(t, snapshotTestOwner,
		fx.body(t, testGenerationSnapshot(snapshotTestOwner, nil, "key-b"), nil), at)
	_, err = fx.read(t, snapshotTestOwner)
	require.ErrorIs(t, err, errSnapshotAmbiguous)
}

func TestSnapshotStoreErrorsFailClosed(t *testing.T) {
	fx := newSnapshotTestFixture(t)
	fx.s3f.listErr = errors.New("s3 down")
	_, err := fx.read(t, snapshotTestOwner)
	require.ErrorIs(t, err, errSnapshotStoreUnavailable)

	fx = newSnapshotTestFixture(t)
	fx.seed(t, snapshotTestOwner,
		fx.body(t, testGenerationSnapshot(snapshotTestOwner, nil, "key-1"), nil), time.Now())
	fx.s3f.getErr = errors.New("s3 down")
	_, err = fx.read(t, snapshotTestOwner)
	require.ErrorIs(t, err, errSnapshotUnverifiable, "an unread version is not an absence")
}

// An unreadable newer version must not hide a valid snapshot.
func TestSnapshotUnreadableVersionDoesNotBlockBoot(t *testing.T) {
	fx := newSnapshotTestFixture(t)
	base := time.Now().Add(-time.Hour)
	key := snapshotObjectKey(hex.EncodeToString(snapshotTestOwner))
	genuine := testGenerationSnapshot(snapshotTestOwner, nil, "genuine-key")
	fx.seed(t, snapshotTestOwner, fx.body(t, genuine, nil), base)
	fx.s3f.putRawObjectAt(key, []byte("unreadable"), base.Add(time.Minute))
	objects := fx.s3f.objects[key]
	fx.s3f.getErrVersions = map[string]error{
		objects[len(objects)-1].id: errors.New("InvalidObjectState"),
	}

	state, err := fx.read(t, snapshotTestOwner)

	require.NoError(t, err)
	require.Equal(t, genuine.kmsKeyID, state.kmsKeyID)
}

// A peer's equivalent publication is accepted on its own receipts; a different
// state is a conflict, whether S3 refused our create or a delete marker let it in.
func TestPublishSnapshotIsCreateOnly(t *testing.T) {
	ctx := t.Context()
	fx := newSnapshotTestFixture(t)
	snapshot := testGenerationSnapshot(snapshotTestOwner, snapshotTestPredecessor, "key-1")
	root, err := snapshot.root(testCfg)
	require.NoError(t, err)
	key := snapshotObjectKey(snapshot.ownerPCR0)

	transition, _ := fx.receipts(t, snapshot, root)
	first, err := fx.boot.publishSnapshot(ctx, withTransition(snapshot, transition))
	require.NoError(t, err)

	peerTransition, _ := fx.receipts(t, snapshot, root)
	require.NotEqual(t, transition, peerTransition, "attestations differ byte for byte")
	second, err := fx.boot.publishSnapshot(ctx, withTransition(snapshot, peerTransition))
	require.NoError(t, err)
	require.Equal(t, first, second, "the peer adopts the state already published")
	require.Len(t, fx.s3f.objects[key], 1)

	other := testGenerationSnapshot(snapshotTestOwner, snapshotTestPredecessor, "key-2")
	otherRoot, err := other.root(testCfg)
	require.NoError(t, err)
	otherTransition, _ := fx.receipts(t, other, otherRoot)
	_, err = fx.boot.publishSnapshot(ctx, withTransition(other, otherTransition))
	require.ErrorIs(t, err, errSnapshotConflict)
	require.Len(t, fx.s3f.objects[key], 1)

	_, err = fx.s3f.DeleteObject(ctx, &s3.DeleteObjectInput{Key: aws.String(key)})
	require.NoError(t, err)
	_, err = fx.boot.publishSnapshot(ctx, withTransition(other, otherTransition))
	require.ErrorIs(t, err, errSnapshotConflict, "a delete marker must not let a second state win")
	state, err := fx.read(t, snapshotTestOwner)
	require.NoError(t, err)
	require.Equal(t, first, state)
}

func TestPublishSnapshotConcurrentPeersConverge(t *testing.T) {
	fx := newSnapshotTestFixture(t)
	snapshot := testGenerationSnapshot(snapshotTestOwner, snapshotTestPredecessor, "key-1")
	root, err := snapshot.root(testCfg)
	require.NoError(t, err)

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		transition, _ := fx.receipts(t, snapshot, root)
		wg.Go(func() {
			_, errs[i] = fx.boot.publishSnapshot(
				context.Background(), withTransition(snapshot, transition),
			)
		})
	}
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}
	require.Len(t, fx.s3f.objects[snapshotObjectKey(snapshot.ownerPCR0)], 1)
}

func TestPublishSnapshotRetriesConditionalConflicts(t *testing.T) {
	fx := newSnapshotTestFixture(t)
	fx.s3f.putConflicts = 2
	snapshot := testGenerationSnapshot(snapshotTestOwner, nil, "key-1")

	_, err := fx.boot.publishSnapshot(t.Context(), snapshot)

	require.NoError(t, err)
}

// unlockedS3 is a bucket without Object Lock that silently drops the headers.
type unlockedS3 struct{ *fakeS3 }

func (u unlockedS3) PutObject(
	ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options),
) (*s3.PutObjectOutput, error) {
	stripped := *in
	stripped.ObjectLockMode, stripped.ObjectLockRetainUntilDate = "", nil
	return u.fakeS3.PutObject(ctx, &stripped, opts...)
}

// Only the read-back can tell that the bucket enforces nothing: the IAM
// simulation would pass.
func TestPublishSnapshotRequiresTheLockToHold(t *testing.T) {
	fx := newSnapshotTestFixture(t)
	fx.boot.s3 = unlockedS3{fx.s3f}
	snapshot := testGenerationSnapshot(snapshotTestOwner, nil, "key-1")

	_, err := fx.boot.publishSnapshot(t.Context(), snapshot)

	require.ErrorIs(t, err, errSnapshotUnverifiable)
}
