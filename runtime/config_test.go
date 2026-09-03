package runtime

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)


func newTestConfig(deployment, appName string, dev bool) *Config {
	c := &Config{Deployment: deployment, AppName: appName}
	c.setSecurityConfig(dev)
	return c
}

// testConfig is the default: production posture, so the suite exercises locked
// paths and real verification unless a test asks otherwise.
func testConfig() *Config { return newTestConfig("prod", "app", false) }

// testCfg is the package-wide default namespace for tests.
var testCfg = testConfig()

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
			c.migrationStateOriginReceiptParam(keyID),
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
