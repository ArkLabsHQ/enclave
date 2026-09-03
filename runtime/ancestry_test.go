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

func (s *stubAuditor) probes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}

type ancestryFixture struct {
	a      *ancestry
	params map[string]string
	signer *testAttestationSigner
}

func newAncestryFixture(t *testing.T, current bootSnapshot, auditor KeyAuditor) *ancestryFixture {
	t.Helper()
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_KMS_KEY_LOCKED", "true")
	now := time.Now()
	signer := newTestAttestationSigner(t, now.Add(-time.Hour), now.Add(time.Hour))
	params := map[string]string{}
	nsm := &nsmW{nsm: &fakeNSM{verifyRoots: signer.roots}}
	a := NewAncestry(nsm, NewSSM(&fakeSSM{params: params}), auditor, current.lineage()).(*ancestry)
	a.ctx = context.Background()
	return &ancestryFixture{a: a, params: params, signer: signer}
}

func (f *ancestryFixture) storeOriginReceipt(t *testing.T, snapshot bootSnapshot) {
	t.Helper()
	root, err := stateRoot(snapshot)
	require.NoError(t, err)
	payload := originReceiptPayload(t, root, snapshot)
	pcr0, err := hex.DecodeString(snapshot.ownerPCR0)
	require.NoError(t, err)
	doc := f.signer.build(t, map[uint][]byte{0: pcr0}, time.Now(), payload)
	f.params[stateOriginReceiptParam(snapshot.kmsKeyID, snapshot.ownerPCR0)] = doc.docB64
}

func testSnapshot(pcr0, keyID, prevPCR0, prevKeyID string) bootSnapshot {
	return bootSnapshot{
		ownerPCR0: pcr0, kmsKeyID: keyID,
		predecessorPCR0: prevPCR0, predecessorKMSKeyID: prevKeyID,
		migrationIntentBucketName: "intent-bucket",
		staticSecrets: map[StaticSecretMetadata]string{
			{Name: "secret"}: base64.StdEncoding.EncodeToString([]byte("secret-" + keyID)),
		},
		storageDEK:       base64.StdEncoding.EncodeToString([]byte("dek-" + keyID)),
		tlsKeyCiphertext: base64.StdEncoding.EncodeToString([]byte("tls-" + keyID)),
	}
}

func TestAncestryWalksVerifiedStateRoots(t *testing.T) {
	p0, p1, p2 := ancestryPCR0(1), ancestryPCR0(2), ancestryPCR0(3)
	auditor := &stubAuditor{status: KeyStatus{State: keyStateExists}}
	fx := newAncestryFixture(t, testSnapshot(p2, "key-2", p1, "key-1"), auditor)
	fx.storeOriginReceipt(t, testSnapshot(p1, "key-1", p0, "key-0"))
	fx.storeOriginReceipt(t, testSnapshot(p0, "key-0", "", ""))

	generations, complete, reason := fx.a.walkAncestors(context.Background())

	require.True(t, complete)
	require.Empty(t, reason)
	require.Equal(t, []string{"key-1", "key-0"}, []string{generations[0].KeyID, generations[1].KeyID})
}

func TestAncestryRejectsAlteredKeyID(t *testing.T) {
	p0, p1 := ancestryPCR0(1), ancestryPCR0(2)
	fx := newAncestryFixture(t, testSnapshot(p1, "key-1", p0, "key-0"), &stubAuditor{})
	snapshot := testSnapshot(p0, "substituted-key", "", "")
	root, err := stateRoot(snapshot)
	require.NoError(t, err)
	payload := originReceiptPayload(t, root, snapshot)
	pcr0, err := hex.DecodeString(p0)
	require.NoError(t, err)
	doc := fx.signer.build(t, map[uint][]byte{0: pcr0}, time.Now(), payload)
	fx.params[stateOriginReceiptParam("key-0", p0)] = doc.docB64

	_, complete, reason := fx.a.walkAncestors(context.Background())

	require.False(t, complete)
	require.Contains(t, reason, "missing or invalid")
}

func TestAncestryMissingReceiptIsIncomplete(t *testing.T) {
	p0, p1 := ancestryPCR0(1), ancestryPCR0(2)
	fx := newAncestryFixture(t, testSnapshot(p1, "key-1", p0, "key-0"), &stubAuditor{})
	fx.storeOriginReceipt(t, testSnapshot(p0, "key-0", "", ""))
	delete(fx.params, stateOriginReceiptParam("key-0", p0))

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
	fx.storeOriginReceipt(t, testSnapshot(p0, "key-0", p1, "key-1"))

	_, complete, reason := fx.a.walkAncestors(context.Background())

	require.False(t, complete)
	require.Contains(t, reason, "cycle")
}

func TestAncestrySnapshotDoesNotBlockOnRefresh(t *testing.T) {
	p0, p1 := ancestryPCR0(1), ancestryPCR0(2)
	auditor := &stubAuditor{status: KeyStatus{State: keyStateExists}, block: make(chan struct{})}
	fx := newAncestryFixture(t, testSnapshot(p1, "key-1", p0, "key-0"), auditor)
	fx.storeOriginReceipt(t, testSnapshot(p0, "key-0", "", ""))
	fx.a.kickRefresh()
	require.Eventually(t, func() bool { return auditor.probes() == 0 && fx.a.refreshing }, time.Second, time.Millisecond)
	require.NotNil(t, fx.a.Snapshot())
	close(auditor.block)
	require.Eventually(t, func() bool { return fx.a.Snapshot().CheckedAt != nil }, time.Second, time.Millisecond)
}
