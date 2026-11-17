package runtime

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func ancestryPCR0(n int) string { return fmt.Sprintf("%096x", n) }

type stubAuditor struct {
	mu    sync.Mutex
	state string
	keys  []string
	block chan struct{}
}

func (s *stubAuditor) KeyState(_ context.Context, keyID string) string {
	if s.block != nil {
		<-s.block
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, keyID)
	return s.state
}

func (s *stubAuditor) probes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}

type ancestryFixture struct {
	a     *ancestry
	state *snapshotTestFixture
}

func newAncestryFixture(t *testing.T, current Snapshot, auditor KeyAuditor) *ancestryFixture {
	t.Helper()
	state := newSnapshotTestFixture(t)
	a := NewAncestry(
		testCfg, state.s3f, state.boot.nsm, stateOriginTestMigrationIntentBucket(), auditor, current,
	).(*ancestry)
	a.ctx = context.Background()
	return &ancestryFixture{a: a, state: state}
}

// publish lands snapshot as its owner's verified snapshot/<pcr0>.
func (f *ancestryFixture) publish(t *testing.T, snapshot Snapshot) {
	t.Helper()
	pcr0, err := hex.DecodeString(snapshot.ownerPCR0)
	require.NoError(t, err)
	f.state.seed(t, pcr0, f.state.body(t, snapshot, nil), time.Now())
}

func testSnapshot(pcr0, keyID, prevPCR0, prevKeyID string) Snapshot {
	return Snapshot{
		ownerPCR0: pcr0, kmsKeyID: keyID,
		predecessorPCR0: prevPCR0, predecessorKMSKeyID: prevKeyID,
		migrationIntentBucketName: stateOriginTestMigrationIntentBucket(),
		masterSeedCiphertext:      base64.StdEncoding.EncodeToString([]byte("seed-" + keyID)),
		tlsKeyCiphertext:          base64.StdEncoding.EncodeToString([]byte("tls-" + keyID)),
	}
}

func TestAncestryWalksVerifiedStateRoots(t *testing.T) {
	p0, p1, p2 := ancestryPCR0(1), ancestryPCR0(2), ancestryPCR0(3)
	auditor := &stubAuditor{state: keyStateExists}
	fx := newAncestryFixture(t, testSnapshot(p2, "key-2", p1, "key-1"), auditor)
	fx.publish(t, testSnapshot(p1, "key-1", p0, "key-0"))
	fx.publish(t, testSnapshot(p0, "key-0", "", ""))

	generations, complete, reason := fx.a.walkAncestors(context.Background())

	require.True(t, complete)
	require.Empty(t, reason)
	require.Equal(
		t,
		[]string{"key-1", "key-0"},
		[]string{generations[0].KeyID, generations[1].KeyID},
	)
}

func TestAncestryRejectsAlteredKeyID(t *testing.T) {
	p0, p1 := ancestryPCR0(1), ancestryPCR0(2)
	fx := newAncestryFixture(t, testSnapshot(p1, "key-1", p0, "key-0"), &stubAuditor{})
	// A genuine state for p0, but not the generation the link names.
	fx.publish(t, testSnapshot(p0, "substituted-key", "", ""))

	_, complete, reason := fx.a.walkAncestors(context.Background())

	require.False(t, complete)
	require.Contains(t, reason, "missing or invalid")
}

func TestAncestryMissingStateIsIncomplete(t *testing.T) {
	p0, p1 := ancestryPCR0(1), ancestryPCR0(2)
	fx := newAncestryFixture(t, testSnapshot(p1, "key-1", p0, "key-0"), &stubAuditor{})

	_, complete, reason := fx.a.walkAncestors(context.Background())

	require.False(t, complete)
	require.Contains(t, reason, "missing or invalid")
}

func TestAncestryGenesisHasNoAncestors(t *testing.T) {
	fx := newAncestryFixture(t, testSnapshot(ancestryPCR0(1), "key-0", "", ""), &stubAuditor{})
	generations, complete, reason := fx.a.walkAncestors(context.Background())
	require.True(t, complete)
	require.Empty(t, generations)
	require.Empty(t, reason)
}

func TestAncestryCycleIsIncomplete(t *testing.T) {
	p0, p1 := ancestryPCR0(1), ancestryPCR0(2)
	fx := newAncestryFixture(t, testSnapshot(p1, "key-1", p0, "key-0"), &stubAuditor{})
	fx.publish(t, testSnapshot(p0, "key-0", p1, "key-1"))

	_, complete, reason := fx.a.walkAncestors(context.Background())

	require.False(t, complete)
	require.Contains(t, reason, "cycle")
}

func TestAncestrySnapshotDoesNotBlockOnRefresh(t *testing.T) {
	p0, p1 := ancestryPCR0(1), ancestryPCR0(2)
	auditor := &stubAuditor{state: keyStateExists, block: make(chan struct{})}
	fx := newAncestryFixture(t, testSnapshot(p1, "key-1", p0, "key-0"), auditor)
	fx.publish(t, testSnapshot(p0, "key-0", "", ""))
	fx.a.kickRefresh()
	require.Eventually(
		t,
		func() bool { return auditor.probes() == 0 && fx.a.refreshing },
		time.Second,
		time.Millisecond,
	)
	require.NotNil(t, fx.a.Snapshot())
	close(auditor.block)
	require.Eventually(
		t,
		func() bool { return fx.a.Snapshot().CheckedAt != nil },
		time.Second,
		time.Millisecond,
	)
}
