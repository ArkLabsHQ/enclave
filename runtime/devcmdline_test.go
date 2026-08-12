package runtime

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyCmdlineOverrides(t *testing.T) {
	// Clear the targets so we observe only what the parser sets.
	for _, env := range devCmdlineKeys {
		t.Setenv(env, "")
	}
	t.Setenv("UNRELATED", "keep")

	cmdline := "console=ttyS0 " +
		"enclavecfg.deployment=dev " +
		"enclavecfg.gvproxy_port=1124 " +
		"enclavecfg.imds_out=3:8102 " +
		"enclavecfg.evil=pwned " + // not whitelisted, ignored
		"ENCLAVE_DEV=true " + // not prefixed, ignored (can't flip the gate)
		"quiet"
	applyCmdlineOverrides(cmdline)

	require.Equal(t, "dev", os.Getenv("ENCLAVE_DEPLOYMENT"))
	require.Equal(t, "1124", os.Getenv("ENCLAVE_NITRIDING_HOST_PROXY_PORT"))
	require.Equal(t, "3:8102", os.Getenv("ENCLAVE_VIPROXY_OUT_ADDRS"))

	require.Empty(t, os.Getenv("EVIL"), "non-whitelisted override leaked into env")
	require.Equal(t, "keep", os.Getenv("UNRELATED"), "parser clobbered an unrelated env var")
}

func TestApplyDevCmdlineOverridesGatedOnDev(t *testing.T) {
	// /proc/cmdline cannot be faked, so the gate is what we assert: outside dev the
	// function must return before reading it at all.
	t.Setenv("ENCLAVE_DEV", "false")
	t.Setenv("ENCLAVE_NITRIDING_HOST_PROXY_PORT", "sentinel")
	ApplyDevCmdlineOverrides()
	require.Equal(t, "sentinel", os.Getenv("ENCLAVE_NITRIDING_HOST_PROXY_PORT"))
}
