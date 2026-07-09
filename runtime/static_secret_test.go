package runtime

import (
	"encoding/json"
	"os"
	"testing"
)

func newTestStaticSecrets() *StaticSecrets {
	return &StaticSecrets{leaders: map[string][]byte{}}
}

func TestApplySharedSecretLeaderWithShare(t *testing.T) {
	// Once a group has formed the leader's single env var holds its SHARE, and the
	// master is cached in memory (not exposed in any env var) for a0 pinning.
	s := newTestStaticSecrets()
	secret := StaticSecret{Name: "signing", EnvVar: "SIGN_KEY", Kind: "signing"}
	t.Setenv(secret.EnvVar, "")

	if err := s.applySharedSecret(secret, sharedSecret{Master: "aa", Share: "bb"}); err != nil {
		t.Fatalf("applySharedSecret: %v", err)
	}
	if got := os.Getenv(secret.EnvVar); got != "bb" {
		t.Errorf("env var = %q, want the share bb", got)
	}
	m, err := s.leaderSecret(secret.EnvVar)
	if err != nil {
		t.Fatalf("leaderMaster: %v", err)
	}
	if string(m) != string([]byte{0xaa}) {
		t.Errorf("cached master = %x, want aa", m)
	}
}

func TestApplySharedSecretSoloLeader(t *testing.T) {
	// A solo leader (no followers yet, no share) pipes the MASTER into the env var and
	// still caches it for pinning.
	s := newTestStaticSecrets()
	secret := StaticSecret{Name: "signing", EnvVar: "SIGN_KEY", Kind: "signing"}
	t.Setenv(secret.EnvVar, "")

	if err := s.applySharedSecret(secret, sharedSecret{Master: "aa"}); err != nil {
		t.Fatalf("applySharedSecret: %v", err)
	}
	if got := os.Getenv(secret.EnvVar); got != "aa" {
		t.Errorf("env var = %q, want the master aa", got)
	}
	if _, err := s.leaderSecret(secret.EnvVar); err != nil {
		t.Errorf("leaderMaster: %v", err)
	}
}

func TestApplySharedSecretFollower(t *testing.T) {
	// A follower envelope carries only the share, which lands in EnvVar; no master is
	// cached (leaderMaster stays empty).
	s := newTestStaticSecrets()
	secret := StaticSecret{Name: "signing", EnvVar: "SIGN_KEY", Kind: "signing"}
	t.Setenv(secret.EnvVar, "")

	if err := s.applySharedSecret(secret, sharedSecret{Share: "cc"}); err != nil {
		t.Fatalf("applySharedSecret: %v", err)
	}
	if got := os.Getenv(secret.EnvVar); got != "cc" {
		t.Errorf("env var = %q, want the share cc", got)
	}
	if _, err := s.leaderSecret(secret.EnvVar); err == nil {
		t.Error("follower must not cache a master")
	}
}

func TestApplySharedSecretEmpty(t *testing.T) {
	s := newTestStaticSecrets()
	secret := StaticSecret{Name: "signing", EnvVar: "SIGN_KEY", Kind: "signing"}
	if err := s.applySharedSecret(secret, sharedSecret{}); err == nil {
		t.Error("expected error for an envelope with neither master nor share")
	}
}

func TestSharedSecretJSONRoundTrip(t *testing.T) {
	// omitempty keeps a follower envelope free of a master field.
	b, err := json.Marshal(sharedSecret{Share: "bb"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"share":"bb"}` {
		t.Errorf("follower envelope = %s, want {\"share\":\"bb\"}", b)
	}

	var env sharedSecret
	if err := json.Unmarshal([]byte(`{"master":"aa","share":"bb"}`), &env); err != nil {
		t.Fatal(err)
	}
	if env.Master != "aa" || env.Share != "bb" {
		t.Errorf("round-trip mismatch: %+v", env)
	}
}
