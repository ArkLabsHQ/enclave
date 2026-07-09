package runtime

import (
	"os"
	"testing"
)

func TestApplyCmdlineOverrides(t *testing.T) {
	// Clear the targets so we observe only what the parser sets.
	for _, env := range devCmdlineKeys {
		t.Setenv(env, "")
	}
	t.Setenv("UNRELATED", "keep")

	cmdline := "console=ttyS0 " +
		"enclavecfg.deployment=dev-leader " +
		"enclavecfg.role=leader " +
		"enclavecfg.gvproxy_port=1124 " +
		"enclavecfg.imds_out=3:8102 " +
		"enclavecfg.leader_addr=https://host.containers.internal:8443 " +
		"enclavecfg.evil=pwned " + // not whitelisted → ignored
		"ENCLAVE_DEV=true " + // not prefixed → ignored (can't flip the gate)
		"quiet"
	applyCmdlineOverrides(cmdline)

	want := map[string]string{
		"ENCLAVE_DEPLOYMENT":                "dev-leader",
		"ENCLAVE_SCALING_ROLE":              "leader",
		"ENCLAVE_NITRIDING_HOST_PROXY_PORT": "1124",
		"ENCLAVE_VIPROXY_OUT_ADDRS":         "3:8102",
		"ENCLAVE_SCALING_LEADER_ADDR":       "https://host.containers.internal:8443",
	}
	for env, exp := range want {
		if got := os.Getenv(env); got != exp {
			t.Errorf("%s = %q, want %q", env, got, exp)
		}
	}

	// Non-whitelisted token must not create an env var, and the gate var must not
	// be touchable via the cmdline (it isn't prefixed, so it's ignored entirely).
	if os.Getenv("EVIL") != "" {
		t.Error("non-whitelisted override leaked into env")
	}
	if os.Getenv("UNRELATED") != "keep" {
		t.Error("parser clobbered an unrelated env var")
	}
}

func TestApplyDevCmdlineOverrides_GatedOnDev(t *testing.T) {
	// Not dev → strict no-op even if /proc/cmdline had overrides (we can't easily
	// fake /proc/cmdline, so assert the gate short-circuits before the read).
	t.Setenv("ENCLAVE_DEV", "false")
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_SCALING_ROLE", "sentinel")
	ApplyDevCmdlineOverrides()
	if got := os.Getenv("ENCLAVE_SCALING_ROLE"); got != "sentinel" {
		t.Errorf("non-dev must not apply cmdline overrides; role = %q", got)
	}
}
