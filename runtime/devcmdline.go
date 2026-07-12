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
// may set: the token name (after the prefix) → the env var it maps to. Restricted
// to networking / namespace / scaling config — never security gates like
// ENCLAVE_DEV, ENCLAVE_KMS_KEY_LOCKED, or ENCLAVE_SECRETS_CONFIG.
var devCmdlineKeys = map[string]string{
	"deployment":   "ENCLAVE_DEPLOYMENT",                // SSM/KMS namespace (per node)
	"role":         "ENCLAVE_SCALING_ROLE",              // leader | follower
	"leader_addr":  "ENCLAVE_SCALING_LEADER_ADDR",       // follower → leader handshake URL
	"gvproxy_port": "ENCLAVE_NITRIDING_HOST_PROXY_PORT", // host vsock port for gvproxy
	"imds_out":     "ENCLAVE_VIPROXY_OUT_ADDRS",         // host vsock CID:PORT for IMDS
}

// ApplyDevCmdlineOverrides reads whitelisted per-instance config from the kernel
// command line (/proc/cmdline) and os.Setenv's it — BEFORE networking, config, or
// the SSM overlay are read. This is the dev-only channel that lets several QEMU
// enclaves booting the SAME EIF (identical PCRs) get distinct vsock ports, SSM
// namespaces, and roles, without baking (which would change PCRs) and without SSM
// (which the ports are upstream of).
//
// SECURITY: a strict no-op unless isDev() — which reads the baked, measured
// ENCLAVE_DEV flag (nonOverridableEnv), so an untrusted host can never inject config
// into a production enclave via the command line. The whitelist further ensures the
// channel can never touch the dev gate or the secret/namespace-defining vars beyond
// the deployment namespace itself.
func ApplyDevCmdlineOverrides() {
	raw, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		slog.Debug("dev cmdline: read /proc/cmdline", "error", err)
		return
	}
	applyCmdlineOverrides(string(raw))
}

// applyCmdlineOverrides parses a kernel command line and sets the whitelisted env
// vars. Split out from the file read so it is unit-testable.
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
