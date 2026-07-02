package runtime

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	sdk "thresholdsdk"
)

func TestScalingRoleParsing(t *testing.T) {
	t.Setenv("ENCLAVE_THRESHOLD_ROLE", "")
	if ts := NewSigningSecrets(nil); !ts.IsLeader() {
		t.Errorf("empty role should default to leader")
	}

	t.Setenv("ENCLAVE_THRESHOLD_ROLE", "follower")
	ts := NewSigningSecrets(nil)
	if ts.IsLeader() {
		t.Errorf("role=follower should not be leader")
	}
	if ts.Admission() != nil {
		t.Errorf("a follower must not expose an admission responder")
	}

	t.Setenv("ENCLAVE_THRESHOLD_ROLE", "leader")
	ts = NewSigningSecrets(nil)
	if ts.Admission() == nil {
		t.Errorf("a leader must expose an admission responder")
	}
}

func TestThresholdAddressingDefaults(t *testing.T) {
	t.Setenv("ENCLAVE_SCALING_ROLE", "leader")
	t.Setenv("ENCLAVE_SCALING_LISTEN_ADDR", "")
	t.Setenv("ENCLAVE_SCALING_RELAY_ADDR", "")
	ts := NewSigningSecrets(nil)
	if ts.listenAddr != defaultRelayListenAddr {
		t.Errorf("listenAddr = %q, want default %q", ts.listenAddr, defaultRelayListenAddr)
	}
	if ts.relayAddr != defaultRelayListenAddr {
		t.Errorf("relayAddr should fall back to listenAddr, got %q", ts.relayAddr)
	}
}

func TestGroupPubkeyEnvVar(t *testing.T) {
	if got := groupPubkeyEnvVar("SIGNING_KEY"); got != "SIGNING_KEY_GROUP_PUBKEY" {
		t.Errorf("groupPubkeyEnvVar = %q", got)
	}
}

func TestThresholdStoreLeaderSecret(t *testing.T) {
	secret := []byte("this-is-a-32-byte-leader-secret!")
	s := newThresholdStore(nil, secret)
	got, err := s.GetLeaderSecret()
	if err != nil {
		t.Fatalf("GetLeaderSecret: %v", err)
	}
	if string(got) != string(secret) {
		t.Errorf("GetLeaderSecret returned wrong bytes")
	}

	// A follower store carries no leader secret.
	empty := newThresholdStore(nil, nil)
	if _, err := empty.GetLeaderSecret(); err != sdk.ErrNotFound {
		t.Errorf("empty leader secret should return ErrNotFound, got %v", err)
	}
}

func TestThresholdStoreRecoveryKey(t *testing.T) {
	s := newThresholdStore(nil, nil)
	key := s.recoveryKey([]byte{0xab, 0xcd})
	if key != thresholdRecoveryPrefix+"abcd" {
		t.Errorf("recoveryKey = %q", key)
	}
}

func TestAdmissionNonceOneShotAndExpiry(t *testing.T) {
	a := newScalingEntity()

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
	a := newScalingEntity()
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

	resp := admitResponseData{LeaderPub: []byte{0x03, 0xbb}, RelayAddr: "10.0.0.5:9000"}
	b, _ = json.Marshal(resp)
	var gotResp admitResponseData
	if err := json.Unmarshal(b, &gotResp); err != nil {
		t.Fatal(err)
	}
	if gotResp.RelayAddr != "10.0.0.5:9000" || hex.EncodeToString(gotResp.LeaderPub) != "03bb" {
		t.Errorf("resp round-trip mismatch: %+v", gotResp)
	}
}
