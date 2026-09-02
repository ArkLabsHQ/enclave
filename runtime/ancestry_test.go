package runtime

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func setAncestryTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_KMS_KEY_LOCKED", "true")
}

// testPCR0 mints a distinct well-formed 96-hex PCR0 per index, for any n.
func testPCR0(n int) string {
	return fmt.Sprintf("%096x", n)
}

// ancestryChain seeds an SSM store where generation i's predecessor is
// generation i+1, each with its own KMS key.
func ancestryChain(depth int) map[string]string {
	params := map[string]string{}
	for i := range depth {
		params[migrationPreviousPCR0Param(testPCR0(i))] = testPCR0(i + 1)
		params[kmsKeyIDParam(testPCR0(i+1))] = fmt.Sprintf("key-%d", i+1)
	}
	return params
}

func walkTestChain(
	t *testing.T,
	params map[string]string,
) ([]AncestorGeneration, bool, string) {
	t.Helper()
	a := newTestAncestry(t, params, &stubAuditor{status: KeyStatus{State: keyStateExists}})
	return a.walkAncestors(context.Background(), testPCR0(0))
}

func TestWalkAncestors(t *testing.T) {
	setAncestryTestEnv(t)

	t.Run("genesis has no ancestors", func(t *testing.T) {
		hops, complete, reason := walkTestChain(t, map[string]string{})

		require.Empty(t, hops)
		require.True(t, complete)
		require.Empty(t, reason)
	})

	t.Run("three generations newest first", func(t *testing.T) {
		hops, complete, reason := walkTestChain(t, ancestryChain(3))

		require.True(t, complete)
		require.Empty(t, reason)
		require.Len(t, hops, 3)
		for i, hop := range hops {
			require.Equal(t, testPCR0(i+1), hop.PCR0)
			require.Equal(t, fmt.Sprintf("key-%d", i+1), hop.KeyID)
		}
	})

	// A corrupt chain must terminate. The timeout is the real assertion: a
	// regression here would hang the enclave, not just the test.
	t.Run("two-node cycle terminates", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			hops, complete, reason := walkTestChain(t, map[string]string{
				migrationPreviousPCR0Param(testPCR0(0)): testPCR0(1),
				migrationPreviousPCR0Param(testPCR0(1)): testPCR0(2),
				migrationPreviousPCR0Param(testPCR0(2)): testPCR0(1),
			})
			require.False(t, complete)
			require.Contains(t, reason, "cycle")
			require.Len(t, hops, 2)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("walkAncestors did not terminate on a cyclic chain")
		}
	})

	t.Run("self cycle terminates", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			hops, complete, reason := walkTestChain(t, map[string]string{
				migrationPreviousPCR0Param(testPCR0(0)): testPCR0(0),
			})
			require.False(t, complete)
			require.Contains(t, reason, "cycle")
			require.Empty(t, hops)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("walkAncestors did not terminate on a self-referential chain")
		}
	})

	// There is no length cap: truncating would drop the oldest generations, which
	// are the most retired and the ones the audit exists to account for.
	t.Run("a long chain walks to genesis", func(t *testing.T) {
		const generations = 600

		hops, complete, reason := walkTestChain(t, ancestryChain(generations))

		require.True(t, complete)
		require.Empty(t, reason)
		require.Len(t, hops, generations)
		require.Equal(t, testPCR0(generations), hops[generations-1].PCR0)
	})

	// A pruned KMSKeyID is an operator action, not corruption: the generation is
	// still reported and the walk carries on past it.
	t.Run("missing key id keeps walking", func(t *testing.T) {
		params := ancestryChain(2)
		delete(params, kmsKeyIDParam(testPCR0(1)))

		hops, complete, reason := walkTestChain(t, params)

		require.True(t, complete)
		require.Empty(t, reason)
		require.Len(t, hops, 2)
		require.Empty(t, hops[0].KeyID)
		require.Equal(t, "key-2", hops[1].KeyID)
	})

	t.Run("malformed predecessor stops the walk", func(t *testing.T) {
		for _, bad := range []string{"not-hex", "genesis", strings.Repeat("zz", 48)} {
			hops, complete, reason := walkTestChain(t, map[string]string{
				migrationPreviousPCR0Param(testPCR0(0)): bad,
			})

			require.False(t, complete)
			require.Contains(t, reason, "malformed predecessor PCR0")
			require.Empty(t, hops)
		}
	})

	t.Run("ssm failure is reported as an error", func(t *testing.T) {
		a := newTestAncestry(t, nil, &stubAuditor{})
		a.ssm = NewSSM(&fakeSSM{err: errors.New("ssm down")})

		hops, complete, reason := a.walkAncestors(context.Background(), testPCR0(0))

		require.False(t, complete)
		require.Contains(t, reason, "ancestor chain walk failed")
		require.Empty(t, hops)
	})
}

// stubAuditor returns a canned status and counts probes.
type stubAuditor struct {
	mu     sync.Mutex
	status KeyStatus
	keys   []string
	block  chan struct{}
}

func (s *stubAuditor) KeyStatus(_ context.Context, keyID string) KeyStatus {
	if s.block != nil {
		<-s.block
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, keyID)
	return s.status
}

func (s *stubAuditor) probes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.keys...)
}

func ancestryTestNSM(t *testing.T) NSM {
	t.Helper()
	raw, err := hex.DecodeString(testPCR0(0))
	require.NoError(t, err)
	return &nsmW{nsm: &fakeNSM{session: newStatefulNSMSession(t, map[uint][]byte{0: raw})}}
}

// newTestAncestry builds an ancestry with no genesis record, for tests that only
// exercise the walk. Use newTestAncestryChain when the snapshot must anchor.
func newTestAncestry(t *testing.T, params map[string]string, auditor KeyAuditor) *ancestry {
	t.Helper()
	return newTestAncestryWithGenesis(t, params, auditor, "")
}

// newTestAncestryChain seeds a depth-long chain plus the genesis record its
// oldest generation must anchor to.
func newTestAncestryChain(t *testing.T, depth int, auditor KeyAuditor) *ancestry {
	t.Helper()
	return newTestAncestryWithGenesis(t, ancestryChain(depth), auditor, testPCR0(depth))
}

func newTestAncestryWithGenesis(
	t *testing.T,
	params map[string]string,
	auditor KeyAuditor,
	genesisPCR0 string,
) *ancestry {
	t.Helper()
	s3f := newFakeS3()
	var log *genesisLog
	if genesisPCR0 != "" {
		seedGenesisRecord(t, s3f, genesisPCR0)
		var err error
		log, err = newGenesisLog(s3f, ancestryTestNSM(t), "ancestry-test-bucket")
		require.NoError(t, err)
	}
	a, ok := NewAncestry(
		ancestryTestNSM(t), NewSSM(&fakeSSM{params: params}), auditor, log,
	).(*ancestry)
	require.True(t, ok)
	a.ctx = context.Background()
	return a
}

// "not yet audited" must never be mistakable for "audited and all keys gone".
func TestAncestrySnapshotBeforeFirstRefresh(t *testing.T) {
	setAncestryTestEnv(t)
	a := NewAncestry(ancestryTestNSM(t), NewSSM(&fakeSSM{}), &stubAuditor{}, nil)

	snap := a.Snapshot()

	require.Nil(t, snap.CheckedAt)
	require.False(t, snap.Complete)
	require.Contains(t, snap.Reason, "not completed yet")

	body, err := json.Marshal(snap)
	require.NoError(t, err)
	require.Contains(t, string(body), `"generations":[]`, "must marshal [] not null")
	require.Contains(t, string(body), `"checked_at":null`)
}

// A failed audit must render as an empty list, never null: a client
// distinguishing "no ancestors" from "field absent" would read the two the same.
func TestAncestryFailedRefreshStillMarshalsAnEmptyList(t *testing.T) {
	setAncestryTestEnv(t)
	a := newTestAncestryChain(t, 1, &stubAuditor{})
	a.nsm = &nsmW{nsm: &fakeNSM{openErr: errors.New("nsm unavailable")}}

	a.refresh(context.Background())
	snap := a.Snapshot()

	require.False(t, snap.Complete)
	require.Contains(t, snap.Reason, "own PCR0")
	body, err := json.Marshal(snap)
	require.NoError(t, err)
	require.Contains(t, string(body), `"generations":[]`)
	require.NotContains(t, string(body), `"generations":null`)
}

func TestAncestryRefreshBuildsSnapshot(t *testing.T) {
	setAncestryTestEnv(t)
	deletionDate := time.Now().Add(30 * 24 * time.Hour).UTC()
	auditor := &stubAuditor{status: KeyStatus{
		State:        keyStatePendingDeletion,
		CheckedVia:   checkedViaDescribeKey,
		DeletionDate: &deletionDate,
	}}
	a := newTestAncestryChain(t, 2, auditor)

	a.refresh(context.Background())
	snap := a.Snapshot()

	require.True(t, snap.Complete)
	require.NotNil(t, snap.CheckedAt)
	require.Len(t, snap.Generations, 2)
	require.Equal(t, testPCR0(1), snap.Generations[0].PCR0)
	require.Equal(t, "key-1", snap.Generations[0].KeyID)
	require.Equal(t, keyStatePendingDeletion, snap.Generations[0].State)
	require.Equal(t, deletionDate, snap.Generations[0].DeletionDate.UTC())
	require.Equal(t, []string{"key-1", "key-2"}, auditor.probes())
}

// Each refresh re-reads the chain and re-probes every key, so a deletion that
// happens after boot shows up rather than being masked by a cached verdict.
func TestAncestryRefreshReprobesEveryGeneration(t *testing.T) {
	setAncestryTestEnv(t)
	auditor := &stubAuditor{status: KeyStatus{State: keyStateExists}}
	a := newTestAncestryChain(t, 2, auditor)

	a.refresh(context.Background())
	require.Len(t, auditor.probes(), 2)

	auditor.mu.Lock()
	auditor.status = KeyStatus{State: keyStateDeleted, CheckedVia: checkedViaDescribeKey}
	auditor.mu.Unlock()
	a.refresh(context.Background())

	require.Len(t, auditor.probes(), 4, "every generation must be re-probed")
	for _, gen := range a.Snapshot().Generations {
		require.Equal(t, keyStateDeleted, gen.State)
	}
}

func TestAncestryChainRetriedAfterSSMError(t *testing.T) {
	setAncestryTestEnv(t)
	backing := &fakeSSM{params: ancestryChain(1), err: errors.New("ssm down")}
	a := newTestAncestryChain(t, 1, &stubAuditor{status: KeyStatus{State: keyStateExists}})
	a.ssm = NewSSM(backing)

	a.refresh(context.Background())
	require.Empty(t, a.Snapshot().Generations)

	backing.err = nil
	a.refresh(context.Background())

	require.Len(t, a.Snapshot().Generations, 1, "a later refresh must recover")
}

func TestAncestrySnapshotIsSingleFlight(t *testing.T) {
	setAncestryTestEnv(t)
	auditor := &stubAuditor{
		status: KeyStatus{State: keyStateExists},
		block:  make(chan struct{}),
	}
	a := newTestAncestryChain(t, 1, auditor)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NotNil(t, a.Snapshot())
		}()
	}
	wg.Wait() // Snapshot must return without waiting on the blocked refresh.
	close(auditor.block)

	require.Eventually(t, func() bool {
		return len(a.Snapshot().Generations) == 1
	}, 5*time.Second, 10*time.Millisecond)
	require.Len(t, auditor.probes(), 1, "concurrent polls must not multiply KMS traffic")
}

// Absence of proof must never render as proof of deletion.
func TestAncestryUnknownIsNeverDeleted(t *testing.T) {
	setAncestryTestEnv(t)
	a := newTestAncestryChain(t, 3, &stubAuditor{status: KeyStatus{
		State:      keyStateUnknown,
		CheckedVia: checkedViaGetKeyPolicy,
		Reason:     "AccessDeniedException",
	}})

	a.refresh(context.Background())
	snap := a.Snapshot()

	require.Len(t, snap.Generations, 3)
	for _, gen := range snap.Generations {
		require.Equal(t, keyStateUnknown, gen.State)
	}
	body, err := json.Marshal(snap)
	require.NoError(t, err)
	require.NotContains(t, string(body), keyStateDeleted)
	// The AWS error names role ARNs and account IDs; it goes to the operator's
	// logs, not to a payload anyone can fetch.
	require.NotContains(t, string(body), "AccessDeniedException")
}

func TestAncestryReportsTheGenesisRecord(t *testing.T) {
	setAncestryTestEnv(t)

	t.Run("record is served alongside the chain", func(t *testing.T) {
		a := newTestAncestryChain(t, 2, &stubAuditor{status: KeyStatus{State: keyStateDeleted}})

		a.refresh(context.Background())
		snap := a.Snapshot()

		require.True(t, snap.Complete, "the walk ran out of predecessors cleanly")
		require.Empty(t, snap.Reason)
		require.NotNil(t, snap.Genesis)
		require.Equal(t, testPCR0(2), snap.Genesis.PCR0)
		require.NotNil(t, snap.Genesis.PublishedAt)
		require.Equal(t, testPCR0(2), snap.Generations[len(snap.Generations)-1].PCR0,
			"the client compares these two itself")
	})

	t.Run("genesis-born enclave reports the record and no ancestors", func(t *testing.T) {
		a := newTestAncestryWithGenesis(t, nil, &stubAuditor{}, testPCR0(0))

		a.refresh(context.Background())
		snap := a.Snapshot()

		require.True(t, snap.Complete)
		require.Empty(t, snap.Generations)
		require.Equal(t, testPCR0(0), snap.Genesis.PCR0)
	})

	t.Run("a chain ending short of the record is reported unjudged", func(t *testing.T) {
		a := newTestAncestryWithGenesis(
			t, ancestryChain(2), &stubAuditor{}, testPCR0(9),
		)

		a.refresh(context.Background())
		snap := a.Snapshot()

		require.True(t, snap.Complete, "complete describes the walk, not the anchor")
		require.Empty(t, snap.Reason)
		require.Equal(t, testPCR0(9), snap.Genesis.PCR0)
		require.NotEqual(t, testPCR0(9), snap.Generations[len(snap.Generations)-1].PCR0)
	})

	// The client checks the signature itself, so the document has to reach it
	// intact rather than as the runtime's verdict on it.
	t.Run("the genesis attestation is handed to the client", func(t *testing.T) {
		const bucket = "ancestry-test-bucket"
		originPCR0 := testPCR0(1)
		raw, err := hex.DecodeString(originPCR0)
		require.NoError(t, err)

		session := newStatefulNSMSession(t, map[uint][]byte{0: raw})
		signer := &nsmW{nsm: &fakeNSM{
			session: session, verifyRoots: session.attestationSign.roots,
		}}
		s3f := newFakeS3()
		log, err := newGenesisLog(s3f, signer, bucket)
		require.NoError(t, err)
		_, err = log.CommitGenesis(context.Background(), originPCR0)
		require.NoError(t, err)

		a := newTestAncestry(t, ancestryChain(1), &stubAuditor{})
		a.genesis = log

		a.refresh(context.Background())
		snap := a.Snapshot()

		require.True(t, snap.Complete)
		require.NotEmpty(t, snap.Genesis.Attestation)
		// What was served must be the document a client can actually verify.
		preImage, err := log.preImage(originPCR0)
		require.NoError(t, err)
		require.NoError(t, signer.VerifyAttestation(
			snap.Genesis.Attestation,
			map[uint]string{0: originPCR0},
			preImage,
		))
	})

	// An unreadable record omits the block rather than colouring the walk: the
	// client sees it has nothing to anchor against.
	t.Run("missing genesis record omits the block", func(t *testing.T) {
		a := newTestAncestryChain(t, 1, &stubAuditor{})
		a.genesis = nil

		a.refresh(context.Background())
		snap := a.Snapshot()

		require.Nil(t, snap.Genesis)
		require.True(t, snap.Complete, "the walk itself was unaffected")
		require.Len(t, snap.Generations, 1)

		body, err := json.Marshal(snap)
		require.NoError(t, err)
		require.NotContains(t, string(body), "genesis")
	})
}
