package runtime

import (
	"log/slog"
	"os"
	"strings"
)

// devCmdlinePrefix namespaces per-instance overrides on the kernel command line so
// they don't collide with real kernel args.
const devCmdlinePrefix = "enclavecfg."

// devCmdlineKeys whitelists which config the dev cmdline channel may set: the token
// (after the prefix) → the env var it maps to. Deliberately excludes security gates
// (ENCLAVE_DEV, ENCLAVE_KMS_KEY_LOCKED, ENCLAVE_SECRETS_CONFIG) — only the deployment
// namespace and the clock cadence / test-step knobs.
var devCmdlineKeys = map[string]string{
	"deployment":          "ENCLAVE_DEPLOYMENT",
	"clock_poll_interval": "ENCLAVE_CLOCK_POLL_INTERVAL",
	"clock_test_step_ns":  "ENCLAVE_CLOCK_TEST_STEP_NS",
}

// ApplyDevCmdlineOverrides reads whitelisted per-instance config from /proc/cmdline and
// os.Setenv's it — BEFORE config or the SSM overlay are read.
func ApplyDevCmdlineOverrides() {
	raw, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		slog.Debug("dev cmdline: read /proc/cmdline", "error", err)
		return
	}
	applyCmdlineOverrides(string(raw))
}

// applyCmdlineOverrides parses a kernel command line and sets the whitelisted env vars.
// Split out from the file read so it is unit-testable.
func applyCmdlineOverrides(cmdline string) {
	for _, tok := range strings.Fields(cmdline) {
		name, val, ok := strings.Cut(tok, "=")
		if !ok || !strings.HasPrefix(name, devCmdlinePrefix) {
			continue
		}
		env, allowed := devCmdlineKeys[strings.TrimPrefix(name, devCmdlinePrefix)]
		if !allowed {
			slog.Warn("dev cmdline: ignoring non-whitelisted override", "token", name)
			continue
		}
		if err := os.Setenv(env, val); err != nil {
			slog.Warn("dev cmdline: setenv failed", "env", env, "error", err)
			continue
		}
		slog.Info("dev cmdline override applied", "env", env, "value", val)
	}
}
