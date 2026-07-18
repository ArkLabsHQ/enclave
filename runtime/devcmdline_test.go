package runtime

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyCmdlineOverrides(t *testing.T) {
	t.Setenv("ENCLAVE_CLOCK_POLL_INTERVAL", "")
	t.Setenv("ENCLAVE_CLOCK_TEST_STEP_NS", "")
	t.Setenv("ENCLAVE_DEPLOYMENT", "")
	t.Setenv("ENCLAVE_KMS_KEY_LOCKED", "")

	applyCmdlineOverrides("BOOT_IMAGE=/vmlinuz " +
		"enclavecfg.clock_poll_interval=2s " +
		"enclavecfg.clock_test_step_ns=500000000 " +
		"enclavecfg.deployment=dev " +
		"enclavecfg.kms_key_locked=false " + // security gate — not whitelisted
		"quiet")

	require.Equal(t, "2s", os.Getenv("ENCLAVE_CLOCK_POLL_INTERVAL"), "whitelisted interval applied")
	require.Equal(t, "500000000", os.Getenv("ENCLAVE_CLOCK_TEST_STEP_NS"), "whitelisted step applied")
	require.Equal(t, "dev", os.Getenv("ENCLAVE_DEPLOYMENT"), "whitelisted deployment applied")
	require.Empty(t, os.Getenv("ENCLAVE_KMS_KEY_LOCKED"), "non-whitelisted security gate ignored")
}
