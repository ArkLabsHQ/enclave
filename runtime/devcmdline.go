package runtime

import (
	"log/slog"
	"os"
	"strings"
)

// devCmdlinePrefix namespaces the per-instance overrides on the kernel command
// line so they don't collide with real kernel args.
const devCmdlinePrefix = "enclavecfg."

// devCmdlineKeys is the whitelist of per-instance config the dev cmdline channel
// may set: the token name (after the prefix) maps to an env var. Restricted
// to networking / namespace config, never security gates like ENCLAVE_DEV,
// ENCLAVE_KMS_KEY_LOCKED, or ENCLAVE_SECRETS_CONFIG.
var devCmdlineKeys = map[string]string{
	"deployment":   "ENCLAVE_DEPLOYMENT",                // SSM/KMS namespace
	"gvproxy_port": "ENCLAVE_NITRIDING_HOST_PROXY_PORT", // host vsock port for gvproxy
	"imds_out":     "ENCLAVE_VIPROXY_OUT_ADDRS",         // host vsock CID:PORT for IMDS
}

// ApplyDevCmdlineOverrides reads whitelisted per-instance config from
// /proc/cmdline and os.Setenv's it, BEFORE networking, config or the SSM overlay
// are read. It is what lets several QEMU enclaves booting the SAME EIF get
// distinct vsock ports: baking them would change PCRs, and SSM is downstream of
// the ports themselves.
//
// SECURITY: a strict no-op unless IsDev(), which reads the baked, measured
// ENCLAVE_DEV flag (nonOverridableEnv), so an untrusted host can never inject
// config into a production enclave this way. The whitelist keeps the channel
// away from the dev gate and the secret-defining vars.
func ApplyDevCmdlineOverrides() {
	if !IsDev() {
		return
	}
	raw, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		slog.Debug("dev cmdline: read /proc/cmdline", "error", err)
		return
	}
	applyCmdlineOverrides(string(raw))
}

// Split out from the file read and the dev gate so it is unit-testable.
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
