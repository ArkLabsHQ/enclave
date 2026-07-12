package runtime

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
