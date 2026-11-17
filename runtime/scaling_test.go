package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

// TestConfigureScalingHandlers verifies a leader's handshake route is served from
// the enclave mux once configured, and not before.
func TestConfigureScalingHandlers(t *testing.T) {
	s := &servers{rm: http.NewServeMux()}
	newReq := func() *http.Request { return httptest.NewRequest("GET", handshakePathNonce, nil) }

	w := httptest.NewRecorder()
	s.rm.ServeHTTP(w, newReq())
	if w.Code != http.StatusNotFound {
		t.Errorf("unconfigured: got %d, want 404", w.Code)
	}

	s.ConfigureScalingHandlers(newLeaderEntity(t))
	w = httptest.NewRecorder()
	s.rm.ServeHTTP(w, newReq())
	if w.Code != http.StatusOK {
		t.Fatalf("leader: got %d, want 200", w.Code)
	}
	if _, err := base64.StdEncoding.DecodeString(strings.TrimSpace(w.Body.String())); err != nil {
		t.Errorf("leader nonce not base64: %q", w.Body.String())
	}
}

func TestScalingRoleParsing(t *testing.T) {
	// An unset or invalid role is rejected.
	if _, err := newScalingEntity(&Config{}, nil); err == nil {
		t.Errorf("empty role should be rejected")
	}

	// Leader.
	leader, err := newScalingEntity(&Config{ScalingRole: "leader"}, nil)
	if err != nil {
		t.Fatalf("leader: %v", err)
	}
	if !leader.IsLeader() {
		t.Errorf("role=leader should be a leader")
	}

	// A follower requires a leader address.
	if _, err := newScalingEntity(&Config{ScalingRole: "follower"}, nil); err == nil {
		t.Errorf("follower without ENCLAVE_SCALING_LEADER_ADDR should error")
	}
	follower, err := newScalingEntity(
		&Config{ScalingRole: "follower", ScalingLeaderAddr: "https://leader:443"}, nil,
	)
	if err != nil {
		t.Fatalf("follower: %v", err)
	}
	if follower.IsLeader() {
		t.Errorf("role=follower should not be a leader")
	}
}

func TestScalingListenPortDefault(t *testing.T) {
	t.Setenv(envScalingRole, "leader")
	t.Setenv(envScalingListenPort, "")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	ts, err := newScalingEntity(cfg, nil)
	if err != nil {
		t.Fatalf("newScalingEntity: %v", err)
	}
	if ts.listenPort != defaultRelayPort {
		t.Errorf("listenPort = %q, want default %q", ts.listenPort, defaultRelayPort)
	}
}

func TestThresholdStoreLeaderSecret(t *testing.T) {
	// A leader resolves a0 through the injected resolver (its seed-derived signing secrets).
	leaderSecrets := map[string][]byte{"SIGNING_KEY": {0x0a, 0x0b, 0x0c}}
	resolve := func(label string) ([]byte, error) {
		m, ok := leaderSecrets[label]
		if !ok {
			return nil, fmt.Errorf("no leader secret for %q", label)
		}
		return m, nil
	}
	s := newDKGStore(nil, resolve)
	got, err := s.GetLeaderSecret("SIGNING_KEY")
	if err != nil {
		t.Fatalf("GetLeaderSecret: %v", err)
	}
	if string(got) != string([]byte{0x0a, 0x0b, 0x0c}) {
		t.Errorf("a0 = %x, want 0a0b0c", got)
	}

	if _, err := s.GetLeaderSecret("MISSING_KEY"); err == nil {
		t.Error("expected error when the leader secret is not cached")
	}

	// A follower has no resolver and must never answer GetLeaderSecret.
	if _, err := newDKGStore(nil, nil).GetLeaderSecret("SIGNING_KEY"); err == nil {
		t.Error("expected error when no resolver is wired (follower)")
	}
}

func TestThresholdStoreRecoveryKey(t *testing.T) {
	s := newDKGStore(nil, nil)
	key := s.recoveryKey([]byte{0xab, 0xcd})
	if key != thresholdRecoveryPrefix+"abcd" {
		t.Errorf("recoveryKey = %q", key)
	}
}

func TestAdmissionNonceOneShotAndExpiry(t *testing.T) {
	a := newLeaderEntity(t)

	b64, err := a.issueNonce()
	if err != nil {
		t.Fatalf("issueNonce: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}

	if !a.consumeNonce(raw) {
		t.Errorf("first consume of a fresh nonce should succeed")
	}
	if a.consumeNonce(raw) {
		t.Errorf("second consume of the same nonce must fail (one-shot)")
	}

	// A nonce we never issued must be rejected.
	if a.consumeNonce([]byte("never-issued-noncexx")) {
		t.Errorf("unknown nonce must be rejected")
	}
}

func TestAdmissionAuthorizeGate(t *testing.T) {
	a := newLeaderEntity(t)
	hostpub := []byte{0x02, 0x01, 0x02, 0x03}

	if a.IsAuthorized(hostpub) {
		t.Errorf("host key must not be authorized before a handshake")
	}
	a.authorize(hostpub)
	if !a.IsAuthorized(hostpub) {
		t.Errorf("host key must be authorized after authorize()")
	}
	if a.IsAuthorized([]byte{0x02, 0x09, 0x09}) {
		t.Errorf("a different host key must remain unauthorized")
	}
}

// TestVerifyFollowerAttestation: the leader admits only the follower images it was
// built with, and each nonce it issued only once.
func TestVerifyFollowerAttestation(t *testing.T) {
	fake := newFakeNSM(t)
	followerPCR0 := bytes.Repeat([]byte{0xab}, 48)
	a := newLeaderEntity(t)
	a.cfg.ScalingFollowerPCR0s = []string{hex.EncodeToString(followerPCR0)}
	a.nsm = &nsmW{nsm: fake}

	sk, err := secp.GeneratePrivateKey()
	require.NoError(t, err)
	hostPub := sk.PubKey().SerializeCompressed()
	reqData, err := json.Marshal(admitRequestData{Nonce: []byte{1, 2, 3}, HostPub: hostPub})
	require.NoError(t, err)
	boxPub := bytes.Repeat([]byte{0x07}, 32)
	attest := func(pcr0 []byte) string {
		b64, err := a.issueNonce()
		require.NoError(t, err)
		nonce, err := base64.StdEncoding.DecodeString(b64)
		require.NoError(t, err)
		return fake.attestWithNonce(
			map[uint][]byte{0: pcr0}, time.Now(), reqData, nonce, boxPub,
		).docB64
	}

	req, pub, err := a.verifyFollowerAttestation(attest(followerPCR0))
	require.NoError(t, err)
	require.Equal(t, hostPub, req.HostPub)
	require.Equal(t, boxPub, pub)

	_, _, err = a.verifyFollowerAttestation(attest(bytes.Repeat([]byte{0xcd}, 48)))
	require.ErrorContains(t, err, "not an admitted follower image")

	doc := attest(followerPCR0)
	_, _, err = a.verifyFollowerAttestation(doc)
	require.NoError(t, err)
	_, _, err = a.verifyFollowerAttestation(doc)
	require.ErrorContains(t, err, "unknown or expired nonce", "a nonce admits once")
}

func TestAdmitDataRoundTrip(t *testing.T) {
	req := admitRequestData{Nonce: []byte{1, 2, 3}, HostPub: []byte{0x02, 0xaa}}
	b, _ := json.Marshal(req)
	var got admitRequestData
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got.HostPub) != "02aa" || len(got.Nonce) != 3 {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	resp := admitResponseData{LeaderPub: []byte{0x03, 0xbb}, RelayPort: "9000"}
	b, _ = json.Marshal(resp)
	var gotResp admitResponseData
	if err := json.Unmarshal(b, &gotResp); err != nil {
		t.Fatal(err)
	}
	if gotResp.RelayPort != "9000" || hex.EncodeToString(gotResp.LeaderPub) != "03bb" {
		t.Errorf("resp round-trip mismatch: %+v", gotResp)
	}
}

// TestShareStoreAndRestore: a share a ceremony delivers is persisted and signalled,
// replaces only its signing secret, and is restored after a restart.
func TestShareStoreAndRestore(t *testing.T) {
	ctx := context.Background()
	store := &thresholdStore{
		cfg: newTestConfig(
			"prod",
			"myapp",
			false,
		),
		s3:     newFakeS3(),
		dek:    testDEK(),
		bucket: "certs",
	}
	share := bytes.Repeat([]byte{0x11}, 32)
	groupKey := bytes.Repeat([]byte{0x02}, 33)

	a := newLeaderEntity(t)
	a.storage = store
	a.labels = []string{"GROUP_KEY"}
	require.ErrorContains(t, a.storeShare(ctx, "OTHER_KEY", share, groupKey),
		"no configured signing secret")
	require.NoError(t, a.storeShare(ctx, "GROUP_KEY", share, groupKey))
	select {
	case <-a.Reshared():
	default:
		t.Fatal("storing a share signals Reshared")
	}

	static := []StaticSecret{
		{
			StaticSecretMetadata: StaticSecretMetadata{EnvVar: "GROUP_KEY", Kind: "signing"},
			Plaintext:            "a0",
		},
		{StaticSecretMetadata: StaticSecretMetadata{EnvVar: "APP_KEY"}, Plaintext: "app"},
	}
	want := []StaticSecret{
		{
			StaticSecretMetadata: static[0].StaticSecretMetadata,
			Plaintext:            hex.EncodeToString(share),
			GroupKey:             groupKey,
		},
		static[1],
	}
	require.Equal(t, want, a.applyShares(static))
	require.Equal(t, "a0", static[0].Plaintext, "applyShares leaves its input unchanged")

	restarted := newLeaderEntity(t)
	restarted.storage = store
	restarted.labels = a.labels
	require.NoError(t, restarted.loadShares(ctx))
	require.Equal(t, want, restarted.applyShares(static))

	var none *ScalingEntity
	require.Equal(t, static, none.applyShares(static), "no scaling role leaves secrets unchanged")
}

// TestHeartbeatAuth exercises the leader's liveness endpoint
func TestHeartbeatAuth(t *testing.T) {
	a := newLeaderEntity(t)

	sk, err := secp.GeneratePrivateKey()
	require.NoError(t, err)
	hostpub := sk.PubKey().SerializeCompressed()
	a.authorize(hostpub)

	// beat builds a heartbeat carrying a freshly-issued leader nonce signed by `signer`.
	beat := func(signer *secp.PrivateKey, pub []byte) heartbeatRequest {
		b64, err := a.issueNonce()
		require.NoError(t, err)
		nonce, _ := base64.StdEncoding.DecodeString(b64)
		sig, err := signHeartbeat(signer, nonce)
		require.NoError(t, err)
		return heartbeatRequest{HostPub: pub, Nonce: nonce, Sig: sig}
	}
	post := func(hb heartbeatRequest) int {
		body, _ := json.Marshal(hb)
		w := httptest.NewRecorder()
		a.handleHeartbeat(w, httptest.NewRequest("POST", heartbeatPath, bytes.NewReader(body)))
		return w.Code
	}

	// Valid → 204 and lastSeen recorded.
	require.Equal(t, http.StatusNoContent, post(beat(sk, hostpub)), "valid heartbeat")
	a.mu.Lock()
	_, seen := a.lastSeen[hex.EncodeToString(hostpub)]
	a.mu.Unlock()
	require.True(t, seen, "valid heartbeat records lastSeen")

	// Replay of the same nonce → 401 (one-shot).
	hb := beat(sk, hostpub)
	require.Equal(t, http.StatusNoContent, post(hb), "first use of nonce")
	require.Equal(t, http.StatusUnauthorized, post(hb), "nonce replay")

	// Signature by a different key → 401.
	other, _ := secp.GeneratePrivateKey()
	require.Equal(t, http.StatusUnauthorized, post(beat(other, hostpub)), "bad signature")

	// Valid signature by an unadmitted key → 403.
	stranger, _ := secp.GeneratePrivateKey()
	require.Equal(
		t,
		http.StatusForbidden,
		post(beat(stranger, stranger.PubKey().SerializeCompressed())),
		"unadmitted host",
	)

	// Banned key → 403 even with a valid nonce+signature.
	a.mu.Lock()
	a.banned[hex.EncodeToString(hostpub)] = true
	a.mu.Unlock()
	require.Equal(t, http.StatusForbidden, post(beat(sk, hostpub)), "banned host")
}

// TestBanEvicts verifies Ban revokes local admission, blocklists the key,
func TestBanEvicts(t *testing.T) {
	a := newLeaderEntity(t)
	hostpub := []byte{0x02, 0xde, 0xad, 0xbe, 0xef}

	a.authorize(hostpub)
	require.True(t, a.IsAuthorized(hostpub), "precondition: host should be authorized")

	calls := 0
	a.sdkBan = func(context.Context, []byte) error {
		calls++
		return nil
	}

	require.NoError(t, a.Ban(context.Background(), hostpub))
	require.False(t, a.IsAuthorized(hostpub), "banned key must no longer be authorized")
	require.True(t, a.isBanned(hostpub), "key must be on the blocklist")
	require.Equal(t, 1, calls, "SDK eviction seam fired once")

	a.mu.Lock()
	_, seen := a.lastSeen[hex.EncodeToString(hostpub)]
	_, auth := a.authorized[hex.EncodeToString(hostpub)]
	a.mu.Unlock()
	require.False(t, seen, "Ban clears lastSeen")
	require.False(t, auth, "Ban revokes authorized")

	// Idempotent: a second ban is a no-op.
	require.NoError(t, a.Ban(context.Background(), hostpub), "second Ban")
	require.Equal(t, 1, calls, "sdk ban invoked once (idempotent)")
}

// TestStaleFollowers ensures only stale followers are selected, never the leader.
func TestStaleFollowers(t *testing.T) {
	a := newLeaderEntity(t)
	a.leaderPub = []byte{0x02, 0x11}

	fresh := []byte{0x02, 0xaa}
	stale := []byte{0x02, 0xbb}
	a.authorize(fresh)
	a.authorize(stale)

	a.mu.Lock()
	a.lastSeen[hex.EncodeToString(stale)] = time.Now().Add(-2 * time.Minute)
	a.mu.Unlock()

	require.Equal(
		t,
		[][]byte{stale},
		a.staleFollowers(time.Minute),
		"only the silent follower is stale",
	)
}

func TestScalingDurationConfig(t *testing.T) {
	t.Setenv(envScalingHeartbeatInterval, "")
	require.Equal(t, 10*time.Second,
		scalingDuration(envScalingHeartbeatInterval, defaultScalingHeartbeatInterval),
		"default heartbeat interval")
	t.Setenv(envScalingHeartbeatInterval, "3s")
	require.Equal(t, 3*time.Second,
		scalingDuration(envScalingHeartbeatInterval, defaultScalingHeartbeatInterval),
		"override heartbeat interval")
	t.Setenv(envScalingLivenessTimeout, "garbage")
	require.Equal(t, 60*time.Second,
		scalingDuration(envScalingLivenessTimeout, defaultScalingLivenessTimeout),
		"invalid timeout falls back to default")
}

func newLeaderEntity(t *testing.T) *ScalingEntity {
	t.Helper()
	a, err := newScalingEntity(&Config{ScalingRole: scalingRoleLeader}, nil)
	require.NoError(t, err)
	return a
}
