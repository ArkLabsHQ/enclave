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
	"ENCLAVE_DEPLOYMENT":         true,
	"ENCLAVE_APP_NAME":           true,
	"ENCLAVE_SECRETS_CONFIG":     true,
	"ENCLAVE_DEV":                true,
	"ENCLAVE_MIGRATION_COOLDOWN": true,
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

		nextCfg := *cfg
		if err := nextCfg.applyEnvOverride(key, p.Value); err != nil {
			return fmt.Errorf("apply env override %s: %w", key, err)
		}
		if err := safeSetenv(key, p.Value); err != nil {
			return fmt.Errorf("setenv %s: %w", key, err)
		}
		*cfg = nextCfg
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

func getAppBinaryName() string {
	return envDefault("APP_BINARY_NAME", "app")
}

func getFQDN() string {
	return envDefault("ENCLAVE_FQDN", "localhost")
}

func getUpstreamProtocol() string {
	return strings.ToLower(envDefault("ENCLAVE_UPSTREAM", "auto"))
}

func logShipInterval() time.Duration {
	value := envDefault("ENCLAVE_LOG_SHIP_INTERVAL", defaultLogShipInterval.String())
	interval, err := time.ParseDuration(value)
	if err != nil || interval <= 0 {
		return defaultLogShipInterval
	}
	return interval
}

func logRetentionDays() int32 {
	value := envDefault(
		"ENCLAVE_LOG_RETENTION_DAYS", strconv.FormatInt(int64(defaultLogRetentionDays), 10),
	)
	days, err := strconv.ParseInt(value, 10, 32)
	if err != nil || days <= 0 {
		return defaultLogRetentionDays
	}
	return int32(days)
}

func migrationCooldown() (time.Duration, bool, error) {
	v := strings.TrimSpace(os.Getenv("ENCLAVE_MIGRATION_COOLDOWN"))
	if v == "" {
		return 0, false, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, false, fmt.Errorf("invalid ENCLAVE_MIGRATION_COOLDOWN %q: %w", v, err)
	}
	if d < 0 {
		return 0, false, fmt.Errorf("ENCLAVE_MIGRATION_COOLDOWN must not be negative")
	}
	return d, true, nil
}
