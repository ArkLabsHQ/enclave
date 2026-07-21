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

// TestScalingHandshakeGating verifies the handshake route (mounted unconditionally
// at New) gates correctly at request time: 503 before Init returns, 404 when there's
// no leader scaling entity, and a nonce once a leader entity is wired.
func TestScalingHandshakeGating(t *testing.T) {
	newReq := func() *http.Request { return httptest.NewRequest("GET", handshakePathNonce, nil) }

	// Before Init returns → 503.
	e := &Runtime{}
	w := httptest.NewRecorder()
	e.scalingHandshakeNonce(w, newReq())
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("pre-init: got %d, want 503", w.Code)
	}

	// Init done, no scaling entity → 404.
	e.initDone.Store(true)
	w = httptest.NewRecorder()
	e.scalingHandshakeNonce(w, newReq())
	if w.Code != http.StatusNotFound {
		t.Errorf("no entity: got %d, want 404", w.Code)
	}

	// Init done, follower → 404 (a follower never serves the handshake).
	t.Setenv("ENCLAVE_SCALING_ROLE", "follower")
	t.Setenv("ENCLAVE_SCALING_LEADER_ADDR", "https://leader:443")
	follower, err := newScalingEntity()
	if err != nil {
		t.Fatalf("newScalingEntity follower: %v", err)
	}
	e.scalingEntity = follower
	w = httptest.NewRecorder()
	e.scalingHandshakeNonce(w, newReq())
	if w.Code != http.StatusNotFound {
		t.Errorf("follower: got %d, want 404", w.Code)
	}

	// Init done, leader → 200 with a base64 nonce body.
	t.Setenv("ENCLAVE_SCALING_ROLE", "leader")
	leader, err := newScalingEntity()
	if err != nil {
		t.Fatalf("newScalingEntity leader: %v", err)
	}
	e.scalingEntity = leader
	w = httptest.NewRecorder()
	e.scalingHandshakeNonce(w, newReq())
	if w.Code != http.StatusOK {
		t.Fatalf("leader: got %d, want 200", w.Code)
	}
	if _, err := base64.StdEncoding.DecodeString(strings.TrimSpace(w.Body.String())); err != nil {
		t.Errorf("leader nonce not base64: %q", w.Body.String())
	}
}

func TestScalingRoleParsing(t *testing.T) {
	// An unset or invalid role is rejected.
	t.Setenv("ENCLAVE_SCALING_ROLE", "")
	if _, err := newScalingEntity(); err == nil {
		t.Errorf("empty role should be rejected")
	}

	// Leader.
	t.Setenv("ENCLAVE_SCALING_ROLE", "leader")
	leader, err := newScalingEntity()
	if err != nil {
		t.Fatalf("leader: %v", err)
	}
	if !leader.IsLeader() {
		t.Errorf("role=leader should be a leader")
	}

	// A follower requires a leader address.
	t.Setenv("ENCLAVE_SCALING_ROLE", "follower")
	t.Setenv("ENCLAVE_SCALING_LEADER_ADDR", "")
	if _, err := newScalingEntity(); err == nil {
		t.Errorf("follower without ENCLAVE_SCALING_LEADER_ADDR should error")
	}
	t.Setenv("ENCLAVE_SCALING_LEADER_ADDR", "https://leader:443")
	follower, err := newScalingEntity()
	if err != nil {
		t.Fatalf("follower: %v", err)
	}
	if follower.IsLeader() {
		t.Errorf("role=follower should not be a leader")
	}
}

func TestScalingListenPortDefault(t *testing.T) {
	t.Setenv("ENCLAVE_SCALING_ROLE", "leader")
	t.Setenv("ENCLAVE_SCALING_LISTEN_PORT", "")
	ts, err := newScalingEntity()
	if err != nil {
		t.Fatalf("newScalingEntity: %v", err)
	}
	if ts.listenPort != defaultRelayPort {
		t.Errorf("listenPort = %q, want default %q", ts.listenPort, defaultRelayPort)
	}
}

func TestThresholdStoreLeaderSecret(t *testing.T) {
	// A leader resolves a0 through the injected resolver (its in-memory leader-secret cache).
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
	t.Setenv("ENCLAVE_SCALING_ROLE", "leader")
	a, err := newScalingEntity()
	if err != nil {
		t.Fatalf("newScalingEntity: %v", err)
	}

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
	t.Setenv("ENCLAVE_SCALING_ROLE", "leader")
	a, err := newScalingEntity()
	if err != nil {
		t.Fatalf("newScalingEntity: %v", err)
	}
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

func newLeaderEntity(t *testing.T) *ScalingEntity {
	t.Helper()
	t.Setenv("ENCLAVE_SCALING_ROLE", "leader")
	a, err := newScalingEntity()
	require.NoError(t, err)
	return a
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
	require.Equal(t, http.StatusForbidden, post(beat(stranger, stranger.PubKey().SerializeCompressed())), "unadmitted host")

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

	require.Equal(t, [][]byte{stale}, a.staleFollowers(time.Minute), "only the silent follower is stale")
}

func TestScalingDurationConfig(t *testing.T) {
	t.Setenv("ENCLAVE_SCALING_HEARTBEAT_INTERVAL", "")
	require.Equal(t, 10*time.Second, scalingHeartbeatInterval(), "default heartbeat interval")
	t.Setenv("ENCLAVE_SCALING_HEARTBEAT_INTERVAL", "3s")
	require.Equal(t, 3*time.Second, scalingHeartbeatInterval(), "override heartbeat interval")
	t.Setenv("ENCLAVE_SCALING_LIVENESS_TIMEOUT", "garbage")
	require.Equal(t, 60*time.Second, scalingLivenessTimeout(), "invalid timeout falls back to default")
}
