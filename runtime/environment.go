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

// nonOverridableEnv lists vars the SSM env overlay must never set. Most name the
// SSM/KMS namespace and lock posture, the managed-secret set, or security timing
// (a short anchor window would let the operator wait out the Object Lock and roll
// back undetected). ENCLAVE_DEV would skip COSE verification when set.
var nonOverridableEnv = map[string]bool{
	"ENCLAVE_DEPLOYMENT":          true,
	"ENCLAVE_APP_NAME":            true,
	"ENCLAVE_ANCHOR_WINDOW":       true,
	"ENCLAVE_KMS_KEY_LOCKED":      true,
	"ENCLAVE_MIGRATION_COOLDOWN":  true,
	"ENCLAVE_SECRETS_CONFIG":      true,
	"ENCLAVE_PREVIOUS_PCR0":       true,
	"ENCLAVE_DEV":                 true,
	"ENCLAVE_VERIFY_CLOCK_SOURCE": true,
}

func ApplyEnvOverrides(ctx context.Context, ssm SSM) error {
	prefix := fmt.Sprintf("/%s/%s/env/", getDeployment(), getAppName())

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

func getDeployment() string {
	if d := strings.TrimSpace(os.Getenv("ENCLAVE_DEPLOYMENT")); d != "" {
		return d
	}
	return "test"
}

func IsDev() bool {
	if v := strings.TrimSpace(os.Getenv("ENCLAVE_DEV")); v != "" {
		return strings.EqualFold(v, "true")
	}
	return false
}

// skipCOSEVerification is dev-only; the dev signal is EIF-baked and not SSM-overridable.
func skipCOSEVerification() bool {
	return IsDev()
}

func getAppName() string {
	if name := strings.TrimSpace(os.Getenv("ENCLAVE_APP_NAME")); name != "" {
		return name
	}
	return "app"
}

func getPreviousPCR0() string {
	return os.Getenv("ENCLAVE_PREVIOUS_PCR0")
}

func getStaticSecretsConfig() string {
	return os.Getenv("ENCLAVE_SECRETS_CONFIG")
}

// kmsKeyLocked: when true, the KMS policy is built in strict mode (no root
// recovery principal). The choice is permanent at first lock.
func kmsKeyLocked() bool {
	return os.Getenv("ENCLAVE_KMS_KEY_LOCKED") == "true"
}

// lockSegment is the SSM namespace segment ("locked"|"unlocked") inserted after
// /{deployment}/{app}/ in every KMS-subtree path, so the lock posture is an
// IAM-enforceable boundary: a locked deployment can never read or write the
// unlocked namespace's key or ciphertexts (and vice versa).
func lockSegment() string {
	if kmsKeyLocked() {
		return "locked"
	}
	return "unlocked"
}

// kmsKeyIDParam: SSM path for the primary KMS key ID, lock-scoped.
func kmsKeyIDParam() string {
	return fmt.Sprintf("/%s/%s/%s/KMSKeyID", getDeployment(), getAppName(), lockSegment())
}

func getMigrationCooldown() time.Duration {
	v := strings.TrimSpace(os.Getenv("ENCLAVE_MIGRATION_COOLDOWN"))
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0
	}
	return d
}

// verifyClockSourceEnabled gates the kvm-clock assertion. Only trustworthy when
// baked into the measured EIF; harnesses that boot without the paravirtualized
// clock leave it unset.
func verifyClockSourceEnabled() bool {
	return strings.EqualFold(
		strings.TrimSpace(os.Getenv("ENCLAVE_VERIFY_CLOCK_SOURCE")), "true",
	)
}

// respPort is the TLS port for the RESP K/V listener.
func respPort() uint16 {
	if s := strings.TrimSpace(os.Getenv("ENCLAVE_KV_RESP_PORT")); s != "" {
		if n, err := strconv.ParseUint(s, 10, 16); err == nil {
			return uint16(n)
		}
	}
	return 6379
}

// anchorWindow is the Object-Lock retain-until duration set on each anchor
// object. Defaults to ~10 years.
func anchorWindow() time.Duration {
	if s := strings.TrimSpace(os.Getenv("ENCLAVE_ANCHOR_WINDOW")); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			return d
		}
	}
	return 10 * 365 * 24 * time.Hour
}

func logBufferSize() int {
	if s := os.Getenv("ENCLAVE_LOG_BUFFER_SIZE"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			return n
		}
	}
	return 1000
}

func cloudwatchLogsEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("ENCLAVE_LOG_CLOUDWATCH")), "true")
}

func logShipInterval() time.Duration {
	if s := os.Getenv("ENCLAVE_LOG_SHIP_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil && d > 0 {
			return d
		}
	}
	return 5 * time.Second
}

func logRetentionDays() int32 {
	if s := os.Getenv("ENCLAVE_LOG_RETENTION_DAYS"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			return int32(n)
		}
	}
	return 30
}

func spanBufferSize() int {
	if s := os.Getenv("ENCLAVE_SPAN_BUFFER_SIZE"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			return n
		}
	}
	return 1000
}

// secretCiphertextParam: SSM path for a secret's KMS ciphertext, lock-scoped and
// scoped by the KMS key ID. Flipping the KMSKeyID param is the atomic migration commit.
func secretCiphertextParam(secretName, keyID string) string {
	return fmt.Sprintf(
		"/%s/%s/%s/%s/Ciphertext/%s",
		getDeployment(),
		getAppName(),
		lockSegment(),
		secretName,
		keyID,
	)
}

// storageDEKCiphertextParam: SSM path for the storage DEK's KMS ciphertext, lock-scoped and key-scoped.
func storageDEKCiphertextParam(keyID string) string {
	return fmt.Sprintf(
		"/%s/%s/%s/StorageDEK/Ciphertext/%s",
		getDeployment(),
		getAppName(),
		lockSegment(),
		keyID,
	)
}

// stateOriginReceiptParam: SSM path for the receipt an enclave writes over its
// own state at genesis (and after adopting a migration). Scoped by key ID.
func stateOriginReceiptParam(keyID string) string {
	return fmt.Sprintf("/%s/%s/StateOriginReceipt/%s", getDeployment(), getAppName(), keyID)
}

// migrationStateOriginReceiptParam: SSM path for the receipt a predecessor
// writes over a successor's state during a migration handoff. Scoped by the
// successor key ID.
func migrationStateOriginReceiptParam(keyID string) string {
	return fmt.Sprintf(
		"/%s/%s/MigrationStateOriginReceipt/%s",
		getDeployment(),
		getAppName(),
		keyID,
	)
}

// migrationPreviousPCR0Param: SSM path for the predecessor enclave's PCR0.
func migrationPreviousPCR0Param() string {
	return fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", getDeployment(), getAppName())
}

// migrationPreviousPCR0AttestationParam: SSM path for the predecessor enclave's
// attestation document.
func migrationPreviousPCR0AttestationParam() string {
	return fmt.Sprintf("/%s/%s/MigrationPreviousPCR0Attestation", getDeployment(), getAppName())
}

// migrationRequestedAtParam: SSM path for the scheduled migration timestamp.
func migrationRequestedAtParam() string {
	return fmt.Sprintf("/%s/%s/MigrationRequestedAt", getDeployment(), getAppName())
}

func envVarOverridePath(name string) string {
	return fmt.Sprintf("/%s/%s/env/%s", getDeployment(), getAppName(), name)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
