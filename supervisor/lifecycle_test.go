package supervisor

import (
	"context"
	"testing"
	"time"
)

func TestTerminateEnclaveHonorsContext(t *testing.T) {
	t.Setenv("ENCLAVE_STOP_CMD", "while :; do :; done")
	lifecycle := &Lifecycle{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	started := time.Now()
	err := lifecycle.terminateEnclave(ctx)
	if err == nil {
		t.Fatal("terminateEnclave unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("terminateEnclave ignored context for %s", elapsed)
	}
}
