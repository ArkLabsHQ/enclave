package runtime

import (
	"encoding/json"
	"os"
	"testing"
)

func TestApplySharedSecretLeader(t *testing.T) {
	secret := StaticSecret{Name: "signing", EnvVar: "SIGN_MASTER", ShareEnvVar: "SIGN_SHARE", Kind: "signing"}
	t.Setenv(secret.EnvVar, "")
	t.Setenv(secret.ShareEnvVar, "")

	if err := applySharedSecret(secret, sharedSecret{Master: "aa", Share: "bb"}); err != nil {
		t.Fatalf("applySharedSecret: %v", err)
	}
	if got := os.Getenv(secret.EnvVar); got != "aa" {
		t.Errorf("master env = %q, want aa", got)
	}
	if got := os.Getenv(secret.ShareEnvVar); got != "bb" {
		t.Errorf("share env = %q, want bb", got)
	}
}

func TestApplySharedSecretFollower(t *testing.T) {
	// A follower envelope carries only the share, which lands in EnvVar.
	secret := StaticSecret{Name: "signing", EnvVar: "SIGN_MASTER", Kind: "signing"}
	t.Setenv(secret.EnvVar, "")

	if err := applySharedSecret(secret, sharedSecret{Share: "cc"}); err != nil {
		t.Fatalf("applySharedSecret: %v", err)
	}
	if got := os.Getenv(secret.EnvVar); got != "cc" {
		t.Errorf("share env = %q, want cc", got)
	}
}

func TestApplySharedSecretLeaderMissingShareEnvVar(t *testing.T) {
	// A leader envelope with a share but no configured ShareEnvVar is a misconfig.
	secret := StaticSecret{Name: "signing", EnvVar: "SIGN_MASTER", Kind: "signing"}
	t.Setenv(secret.EnvVar, "")
	if err := applySharedSecret(secret, sharedSecret{Master: "aa", Share: "bb"}); err == nil {
		t.Error("expected error when ShareEnvVar is unset on a leader envelope")
	}
}

func TestApplySharedSecretEmpty(t *testing.T) {
	secret := StaticSecret{Name: "signing", EnvVar: "SIGN_MASTER", Kind: "signing"}
	if err := applySharedSecret(secret, sharedSecret{}); err == nil {
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
