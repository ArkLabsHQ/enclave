package runtime

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestConfig(deployment, appName string, dev bool) *Config {
	c := &Config{
		Deployment: deployment, AppName: appName,
		AppPort:         "7074",
		LogShipInterval: 10 * time.Millisecond, LogRetentionDays: defaultLogRetentionDays,
	}
	c.setSecurityConfig(dev)
	return c
}

// testConfig is the default: production posture, so the suite exercises locked
// paths and real verification unless a test asks otherwise.
func testConfig() *Config { return newTestConfig("prod", "app", false) }

// testCfg is the package-wide default namespace for tests.
var testCfg = testConfig()

func testConfigWithLogShipInterval(interval time.Duration) *Config {
	cfg := *testCfg
	cfg.LogShipInterval = interval
	return &cfg
}

func TestApplySecurityEnvelope(t *testing.T) {
	prod := newTestConfig("prod", "app", false)
	require.True(t, prod.KMSLocked, "production must not run an amendable key policy")
	require.False(t, prod.InsecureVerifySkipped, "production must verify COSE signatures")
	require.True(t, prod.VerifyClockSource)
	require.Equal(t, prodRetention, prod.GenesisRetention)
	require.Equal(t, prodRetention, prod.IntentRetention)
	require.Equal(t, prodMigrationCooldown, prod.MigrationCooldown)

	dev := newTestConfig("dev", "app", true)
	require.False(t, dev.KMSLocked)
	require.True(t, dev.InsecureVerifySkipped)
	require.False(t, dev.VerifyClockSource)
	require.Equal(t, devGenesisRetention, dev.GenesisRetention)
	require.Equal(t, devIntentRetention, dev.IntentRetention)
	require.Equal(t, devMigrationCooldown, dev.MigrationCooldown)
}

// Object Lock rejects a retain-until date that is not in the future, and a zero
// cooldown would leave the cooling_down branch unreachable in both postures.
func TestSecurityEnvelopeDurationsArePositive(t *testing.T) {
	for _, dev := range []bool{false, true} {
		c := newTestConfig("d", "a", dev)
		require.Positive(t, c.GenesisRetention)
		require.Positive(t, c.IntentRetention)
		require.Positive(t, c.MigrationCooldown)
	}
}

// The posture used to come from an exact `== "true"`, so "True" silently meant
// unlocked. IsDev trims and folds, which is why LoadConfig routes through it.
func TestIsDevParsing(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"", false},
		{"true", true},
		{"TRUE", true},
		{"  true  ", true},
		{"True", true},
		{"false", false},
		{"1", false},
		{"yes", false},
	} {
		t.Run("ENCLAVE_DEV="+tc.value, func(t *testing.T) {
			t.Setenv("ENCLAVE_DEV", tc.value)

			require.Equal(t, tc.want, IsDev())
		})
	}
}

func TestLoadConfigTelemetrySettings(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "250ms")
	t.Setenv("ENCLAVE_LOG_RETENTION_DAYS", "7")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, 250*time.Millisecond, cfg.LogShipInterval)
	require.Equal(t, int32(7), cfg.LogRetentionDays)
}

func TestLoadConfigDefaultsInvalidTelemetrySettings(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "invalid")
	t.Setenv("ENCLAVE_LOG_RETENTION_DAYS", "0")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, defaultLogShipInterval, cfg.LogShipInterval)
	require.Equal(t, defaultLogRetentionDays, cfg.LogRetentionDays)
}

// The lock posture is an IAM-enforceable boundary, so it must move exactly the
// KMS-subtree paths and nothing else.
func TestLockSegmentScopesOnlyTheKMSSubtree(t *testing.T) {
	pcr0, keyID := strings.Repeat("ab", 48), "key-1"
	locked, unlocked := newTestConfig("prod", "app", false), newTestConfig("prod", "app", true)

	scoped := func(c *Config) []string {
		return []string{
			c.kmsKeyIDParam(pcr0),
			c.secretCiphertextParam("alpha", keyID),
			c.storageDEKCiphertextParam(keyID),
			c.tlsKeyCiphertextParam(keyID),
		}
	}
	unscoped := func(c *Config) []string {
		return []string{
			c.stateOriginReceiptParam(keyID, pcr0),
			c.migrationStateOriginReceiptParam(keyID, pcr0),
			c.migrationPreviousPCR0Param(pcr0),
			c.migrationPreviousPCR0AttestationParam(pcr0),
		}
	}

	require.Equal(t, "locked", locked.lockSegment())
	require.Equal(t, "unlocked", unlocked.lockSegment())
	for i, p := range scoped(locked) {
		require.Contains(t, p, "/locked/")
		require.Contains(t, scoped(unlocked)[i], "/unlocked/")
		require.NotEqual(t, p, scoped(unlocked)[i], "the posture must move this path")
	}
	require.Equal(t, unscoped(locked), unscoped(unlocked),
		"these paths must not be lock-scoped")
}

func TestLoadConfigMigrationCooldown(t *testing.T) {
	base := func(t *testing.T) {
		t.Helper()
		t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
		t.Setenv("ENCLAVE_APP_NAME", "app")
	}

	t.Run("unset keeps the posture default", func(t *testing.T) {
		base(t)
		t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "")

		cfg, err := LoadConfig()
		require.NoError(t, err)
		require.Equal(t, prodMigrationCooldown, cfg.MigrationCooldown)
	})

	t.Run("dev unset keeps the dev default", func(t *testing.T) {
		base(t)
		t.Setenv("ENCLAVE_DEV", "true")
		t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "")

		cfg, err := LoadConfig()
		require.NoError(t, err)
		require.Equal(t, devMigrationCooldown, cfg.MigrationCooldown)
	})

	t.Run("override wins", func(t *testing.T) {
		base(t)
		t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "48h")

		cfg, err := LoadConfig()
		require.NoError(t, err)
		require.Equal(t, 48*time.Hour, cfg.MigrationCooldown)
	})

	// An explicit zero must stay distinct from an absent value, or "no cooldown"
	// would silently read back as the 24 hour default.
	t.Run("explicit zero is honoured", func(t *testing.T) {
		base(t)
		t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "0s")

		cfg, err := LoadConfig()
		require.NoError(t, err)
		require.Zero(t, cfg.MigrationCooldown)
	})

	for _, tc := range []struct{ name, value, wantErr string }{
		{"unparseable", "nope", "invalid ENCLAVE_MIGRATION_COOLDOWN"},
		{"negative", "-1h", "must not be negative"},
	} {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			base(t)
			t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", tc.value)

			_, err := LoadConfig()
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestSecurityProfileMigrationTimeouts(t *testing.T) {
	for _, dev := range []bool{false, true} {
		cfg := newTestConfig("test", "app", dev)
		want := 10 * time.Minute
		if dev {
			want = 2 * time.Minute
		}
		require.Equal(t, want, cfg.IntentWriteTimeout)
		require.Greater(t, cfg.IntentRetention, cfg.IntentWriteTimeout)
		require.Greater(t, cfg.IntentRetention-cfg.IntentWriteTimeout, time.Minute,
			"the retained window must stay well clear of the tolerance")
	}
}

func TestLoadConfigVerifyClockSource(t *testing.T) {
	base := func(t *testing.T, dev bool) {
		t.Helper()
		t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
		t.Setenv("ENCLAVE_APP_NAME", "app")
		t.Setenv("ENCLAVE_DEV", strconv.FormatBool(dev))
	}

	t.Run("unset keeps the posture default", func(t *testing.T) {
		for _, dev := range []bool{false, true} {
			base(t, dev)
			t.Setenv("ENCLAVE_VERIFY_CLOCK_SOURCE", "")

			cfg, err := LoadConfig()
			require.NoError(t, err)
			require.Equal(t, !dev, cfg.VerifyClockSource)
		}
	})

	// An explicit value must stay distinct from an absent one, or asking for the
	// assertion in dev, or waiving it in prod, would silently do nothing.
	t.Run("override wins in both postures", func(t *testing.T) {
		for _, dev := range []bool{false, true} {
			for _, want := range []bool{false, true} {
				base(t, dev)
				t.Setenv("ENCLAVE_VERIFY_CLOCK_SOURCE", strconv.FormatBool(want))

				cfg, err := LoadConfig()
				require.NoError(t, err)
				require.Equal(t, want, cfg.VerifyClockSource, "dev=%v want=%v", dev, want)
			}
		}
	})

	t.Run("rejects an unparseable value", func(t *testing.T) {
		base(t, false)
		t.Setenv("ENCLAVE_VERIFY_CLOCK_SOURCE", "sometimes")

		_, err := LoadConfig()
		require.ErrorContains(t, err, "invalid ENCLAVE_VERIFY_CLOCK_SOURCE")
	})
}
