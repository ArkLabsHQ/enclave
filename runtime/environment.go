package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// nonOverridableEnv lists vars the SSM env overlay must never set: they name the
// SSM namespace or the managed-secret set. ENCLAVE_DEV additionally selects the
// whole set of security settings — lock posture, both Object Lock retentions,
// the migration cooldown and the clock-source assertion — and skips COSE
// verification.
var nonOverridableEnv = map[string]bool{
	"ENCLAVE_DEPLOYMENT":     true,
	"ENCLAVE_APP_NAME":       true,
	"ENCLAVE_SECRETS_CONFIG": true,
	"ENCLAVE_DEV":            true,
}

func ApplyEnvOverrides(ctx context.Context, cfg *Config, ssm SSM) error {
	prefix := fmt.Sprintf("/%s/%s/env/", cfg.Deployment, cfg.AppName)

	params, err := ssm.ListParams(ctx, prefix)
	if err != nil {
		return fmt.Errorf("failed to list env override SSM params: %w", err)
	}

	applied := 0
	for _, p := range params {
		key := strings.TrimPrefix(p.Name, prefix)
		// Defensive: skip empty or nested keys so a misconfigured SSM
		// tree can't surface unexpected env var names.
		if key == "" || strings.ContainsRune(key, '/') {
			continue
		}

		// Never let SSM overlay change EIF-baked identity or security knobs.
		if nonOverridableEnv[key] {
			slog.Warn("ignoring non-overridable env var from SSM overlay", "key", key)
			continue
		}

		if err := os.Setenv(key, p.Value); err != nil {
			return fmt.Errorf("setenv %s: %w", key, err)
		}
		applied++
	}

	slog.Info("env overrides applied", "count", applied, "prefix", prefix)

	return nil
}

func envDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func IsDev() bool {
	if v := strings.TrimSpace(os.Getenv("ENCLAVE_DEV")); v != "" {
		return strings.EqualFold(v, "true")
	}
	return false
}

func getStaticSecretsConfig() string {
	return os.Getenv("ENCLAVE_SECRETS_CONFIG")
}

func getDeployment() string {
	return strings.TrimSpace(os.Getenv("ENCLAVE_DEPLOYMENT"))
}

func getAppName() string {
	return strings.TrimSpace(os.Getenv("ENCLAVE_APP_NAME"))
}

func getAppPort() string {
	return envDefault("ENCLAVE_APP_PORT", "7074")
}

func getFQDN() string {
	return envDefault("ENCLAVE_NITRIDING_FQDN", "localhost")
}

func getUpstreamProtocol() string {
	return strings.ToLower(envDefault("ENCLAVE_NITRIDING_UPSTREAM", "auto"))
}

func logShipInterval() time.Duration {
	if s := os.Getenv("ENCLAVE_LOG_SHIP_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil && d > 0 {
			return d
		}
	}
	return 10 * time.Second
}

func logRetentionDays() int32 {
	if s := os.Getenv("ENCLAVE_LOG_RETENTION_DAYS"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			return int32(n)
		}
	}
	return 30
}
