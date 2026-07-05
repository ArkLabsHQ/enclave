package runtime

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

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
	s := newThresholdStore(nil)
	t.Setenv("SIGNING_KEY", "0a0b0c")
	got, err := s.GetLeaderSecret("SIGNING_KEY")
	if err != nil {
		t.Fatalf("GetLeaderSecret: %v", err)
	}
	if string(got) != string([]byte{0x0a, 0x0b, 0x0c}) {
		t.Errorf("a0 = %x, want 0a0b0c", got)
	}

	t.Setenv("SIGNING_KEY", "")
	if _, err := s.GetLeaderSecret("SIGNING_KEY"); err == nil {
		t.Error("expected error when the master env var is empty")
	}
}

func TestThresholdStoreRecoveryKey(t *testing.T) {
	s := newThresholdStore(nil)
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
