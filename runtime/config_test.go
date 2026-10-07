package runtime

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestConfig(namespace, appName string, dev bool) *Config {
	c := &Config{
		Namespace: namespace, AppName: appName,
		AppPort:         "7074",
		LogShipInterval: 10 * time.Millisecond, LogRetentionDays: defaultLogRetentionDays,
		ExportTraces: true, ExportMetrics: true,
		InstanceID:         "i-0e2ce2ce2ce2ce2ce",
		KMSLocked:          true,
		VerifyClockSource:  true,
		GenesisRetention:   prodRetention,
		IntentRetention:    prodRetention,
		IntentWriteTimeout: prodIntentWriteTimeout,
		MigrationCooldown:  defaultMigrationCooldown,
		ClockSyncInterval:  prodClockSyncInterval,
		ChildEnv:           make(map[string]string),
	}
	if dev {
		c.KMSLocked = false
		c.GenesisRetention = devGenesisRetention
		c.IntentRetention = devIntentRetention
		c.IntentWriteTimeout = devIntentWriteTimeout
		c.ClockSyncInterval = devClockSyncInterval
	}
	return c
}

// testConfig is the default: production posture, so the suite exercises locked
// paths and real verification unless a test asks otherwise.
func testConfig() *Config { return newTestConfig("prod", "app", false) }

// testCfg is the package-wide default namespace for tests.
var testCfg = testConfig()

func testConfigWithPreviousPCR0(prev string) *Config {
	cfg := *testCfg
	cfg.PreviousPCR0 = prev
	return &cfg
}

func testConfigWithLogShipInterval(interval time.Duration) *Config {
	cfg := *testCfg
	cfg.LogShipInterval = interval
	return &cfg
}

func setConfigTestEnv(t *testing.T, dev bool) {
	t.Helper()
	t.Setenv(envNamespace, "prod")
	t.Setenv(envAppName, "app")
	t.Setenv(envAppPort, "7074")
	t.Setenv(envDev, strconv.FormatBool(dev))
	t.Setenv(envMigrationCooldown, "")
	t.Setenv(envVerifyClockSource, "")
	t.Setenv(envInsecureVerifySkipped, "")
	t.Setenv(envTraces, "")
	t.Setenv(envMetrics, "")
	t.Setenv(envSecretsConfig, "[]")
	t.Setenv(envOverrideAllowList, "")
}

func TestLoadConfigSecurityDefaults(t *testing.T) {
	for _, tc := range []struct {
		name               string
		dev                bool
		genesisRetention   time.Duration
		intentRetention    time.Duration
		intentWriteTimeout time.Duration
		clockSyncInterval  time.Duration
	}{
		{"prod", false, prodRetention, prodRetention, prodIntentWriteTimeout, prodClockSyncInterval},
		{"dev", true, devGenesisRetention, devIntentRetention, devIntentWriteTimeout, devClockSyncInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setConfigTestEnv(t, tc.dev)

			cfg, err := LoadConfig()
			require.NoError(t, err)
			require.Equal(t, !tc.dev, cfg.KMSLocked)
			require.False(
				t,
				cfg.InsecureVerifySkipped,
				"skipping verification requires an explicit opt-in",
			)
			require.True(t, cfg.VerifyClockSource)
			require.Equal(t, 24*time.Hour, cfg.MigrationCooldown)
			require.Equal(t, tc.genesisRetention, cfg.GenesisRetention)
			require.Equal(t, tc.intentRetention, cfg.IntentRetention)
			require.Equal(t, tc.intentWriteTimeout, cfg.IntentWriteTimeout)
			require.Equal(t, tc.clockSyncInterval, cfg.ClockSyncInterval)
			require.Greater(t, cfg.IntentRetention-cfg.IntentWriteTimeout, time.Minute,
				"the retained window must stay well clear of the tolerance")
		})
	}
}

func TestConfigValidate(t *testing.T) {
	valid := func() *Config {
		c := newTestConfig("prod", "myapp", false)
		c.ExtPort, c.IntPort, c.HostProxyPort, c.FQDN = extPort, intPort, hostProxyPort, "localhost"
		return c
	}

	for _, tc := range []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "all set", mutate: func(*Config) {}},
		{
			name:    "namespace missing",
			mutate:  func(c *Config) { c.Namespace = "" },
			wantErr: "ENCLAVE_NAMESPACE must be set",
		},
		{
			name:    "namespace has a leading slash",
			mutate:  func(c *Config) { c.Namespace = "/ark/dev" },
			wantErr: "no leading, trailing or doubled",
		},
		{
			name:    "namespace has a trailing slash",
			mutate:  func(c *Config) { c.Namespace = "ark/dev/" },
			wantErr: "no leading, trailing or doubled",
		},
		{
			name:    "namespace has an empty segment",
			mutate:  func(c *Config) { c.Namespace = "ark//dev" },
			wantErr: "no leading, trailing or doubled",
		},
		{
			name:    "namespace climbs above its root",
			mutate:  func(c *Config) { c.Namespace = "../prod" },
			wantErr: `"." and ".." segments are not allowed`,
		},
		{
			name:    "namespace has a dot segment",
			mutate:  func(c *Config) { c.Namespace = "ark/./prod" },
			wantErr: `"." and ".." segments are not allowed`,
		},
		{
			name:   "dots inside a segment are fine",
			mutate: func(c *Config) { c.Namespace = "ark/..backup/v1.2" },
		},
		{
			name:    "app name is a dot-dot segment",
			mutate:  func(c *Config) { c.AppName = ".." },
			wantErr: `"." and ".." segments are not allowed`,
		},
		{
			name:    "namespace has a character SSM refuses",
			mutate:  func(c *Config) { c.Namespace = "ark/dev#us" },
			wantErr: "allow only letters, digits and _.-",
		},
		{
			name:   "namespace spans path segments",
			mutate: func(c *Config) { c.Namespace = "ark/se7enz/dev" },
		},
		{
			name:    "app name missing",
			mutate:  func(c *Config) { c.AppName = "" },
			wantErr: "ENCLAVE_APP_NAME must be set",
		},
		{
			name:    "app name has a character SSM refuses",
			mutate:  func(c *Config) { c.AppName = "app:one" },
			wantErr: "allow only letters, digits and _.-",
		},
		{
			name:    "app name spans path segments",
			mutate:  func(c *Config) { c.AppName = "org/app" },
			wantErr: "must be a single path segment",
		},
		{
			name:    "namespace starts with a reserved SSM word",
			mutate:  func(c *Config) { c.Namespace = "AWS/team/prod" },
			wantErr: "SSM reserves parameter names",
		},
		{
			name:    "single-segment namespace starts with a reserved SSM word",
			mutate:  func(c *Config) { c.Namespace = "ssm-prod" },
			wantErr: "SSM reserves parameter names",
		},
		{
			name:   "reserved word inside a later segment is fine",
			mutate: func(c *Config) { c.Namespace = "ark/aws" },
		},
		{
			name:    "namespace deeper than SSM allows",
			mutate:  func(c *Config) { c.Namespace = "a/b/c/d/e/f/g/h/i/j" },
			wantErr: "at most 9 fit SSM's hierarchy",
		},
		{
			name:    "namespace longer than the name limits allow",
			mutate:  func(c *Config) { c.Namespace = strings.Repeat("d", 300) },
			wantErr: "fit SSM and CloudWatch name limits",
		},
		{
			name:    "port missing",
			mutate:  func(c *Config) { c.ExtPort = 0 },
			wantErr: "config is missing port",
		},
		{
			name:    "FQDN missing",
			mutate:  func(c *Config) { c.FQDN = "" },
			wantErr: "config is missing FQDN",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.mutate(c)

			err := c.Validate()

			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestLoadConfigTelemetrySettings(t *testing.T) {
	setConfigTestEnv(t, false)
	t.Setenv(envLogShipInterval, "250ms")
	t.Setenv(envLogRetentionDays, "7")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, 250*time.Millisecond, cfg.LogShipInterval)
	require.Equal(t, int32(7), cfg.LogRetentionDays)
}

func TestLoadConfigDefaultsInvalidTelemetrySettings(t *testing.T) {
	setConfigTestEnv(t, false)
	t.Setenv(envLogShipInterval, "invalid")
	t.Setenv(envLogRetentionDays, "0")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, defaultLogShipInterval, cfg.LogShipInterval)
	require.Equal(t, defaultLogRetentionDays, cfg.LogRetentionDays)
}

func TestConfigNamespace(t *testing.T) {
	cfg := newTestConfig("se7enz", "emulator", false)
	require.Equal(t, "/se7enz/emulator/enclave", cfg.namespace())
	require.Equal(t, "/se7enz/emulator/enclave/env/", cfg.envOverlayPrefix())
	require.Equal(t, "/se7enz/emulator/enclave/inherit/", cfg.inheritSecretPrefix())
	require.Equal(t, "/se7enz/emulator/enclave/CertBucketName", cfg.certBucketParam())
	require.Equal(t, "/se7enz/emulator/enclave/logs/app", cfg.logGroup(signalAppLogs))

	cfg.Namespace = "ark/se7enz"
	require.Equal(t, "/ark/se7enz/emulator/enclave", cfg.namespace())
	require.Equal(t, "/ark/se7enz/emulator/enclave/env/", cfg.envOverlayPrefix())
	require.Equal(t, "/ark/se7enz/emulator/enclave/logs/app", cfg.logGroup(signalAppLogs))
}

func TestLoadConfigNamespace(t *testing.T) {
	setConfigTestEnv(t, false)
	t.Setenv(envNamespace, "ark/se7enz/prod")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "ark/se7enz/prod", cfg.Namespace)
	require.Equal(t, "/ark/se7enz/prod/app/enclave", cfg.namespace())
	require.NoError(t, cfg.Validate())
}

// Identity is taken verbatim, never cleaned: what the operator sets is what gets
// hashed into the intent bucket name, so a value that would need cleaning is refused.
func TestLoadConfigIdentityIsVerbatim(t *testing.T) {
	for _, tc := range []struct{ namespace, app, wantErr string }{
		{"/ark/prod", "app", "no leading, trailing or doubled"},
		{" ark/prod ", "app", "allow only letters"},
		{"ark/prod", " app", "allow only letters"},
	} {
		setConfigTestEnv(t, false)
		t.Setenv(envNamespace, tc.namespace)
		t.Setenv(envAppName, tc.app)

		cfg, err := LoadConfig()
		require.NoError(t, err)
		require.Equal(t, tc.namespace, cfg.Namespace)
		require.Equal(t, tc.app, cfg.AppName)
		require.ErrorContains(t, cfg.Validate(), tc.wantErr)
	}
}

func TestConfigLogGroup(t *testing.T) {
	cfg := newTestConfig("prod", "app", false)
	require.Equal(t, "/prod/app/enclave/logs/app", cfg.logGroup(signalAppLogs))
	require.Equal(t, "/prod/app/enclave/logs/runtime", cfg.logGroup(signalRuntimeLogs))
}

// The lock posture is an IAM-enforceable boundary, so it must move exactly the
// KMS-subtree paths and nothing else.
func TestLockSegmentScopesOnlyTheKMSSubtree(t *testing.T) {
	pcr0, keyID := strings.Repeat("ab", 48), "key-1"
	locked, unlocked := testConfig(), testConfig()
	unlocked.KMSLocked = false

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
	for _, dev := range []bool{false, true} {
		for _, tc := range []struct {
			name, value string
			want        time.Duration
			wantErr     string
		}{
			{name: "unset", want: 24 * time.Hour},
			{name: "blank", value: "  ", want: 24 * time.Hour},
			{name: "override", value: "48h", want: 48 * time.Hour},
			{name: "padded override", value: " 2s ", want: 2 * time.Second},
			// Explicit zero must stay distinct from an absent value.
			{name: "zero", value: "0s", want: 0},
			{name: "unparseable", value: "nope", wantErr: "invalid ENCLAVE_MIGRATION_COOLDOWN"},
			{name: "negative", value: "-1h", wantErr: "must not be negative"},
		} {
			t.Run("dev="+strconv.FormatBool(dev)+"/"+tc.name, func(t *testing.T) {
				setConfigTestEnv(t, dev)
				t.Setenv(envMigrationCooldown, tc.value)

				cfg, err := LoadConfig()
				if tc.wantErr != "" {
					require.ErrorContains(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.want, cfg.MigrationCooldown)
			})
		}
	}
}

func TestLoadConfigVerifyClockSource(t *testing.T) {
	for _, dev := range []bool{false, true} {
		for _, tc := range []struct {
			name, value string
			want        bool
		}{
			{name: "unset", want: true},
			{name: "blank", value: "  ", want: true},
			{name: "enabled", value: "true", want: true},
			{name: "disabled", value: "false", want: false},
			{name: "padded lowercase", value: " false ", want: false},
			{name: "uppercase uses default", value: " FALSE ", want: true},
			{name: "unrecognized uses default", value: "sometimes", want: true},
		} {
			t.Run("dev="+strconv.FormatBool(dev)+"/"+tc.name, func(t *testing.T) {
				setConfigTestEnv(t, dev)
				t.Setenv(envVerifyClockSource, tc.value)

				cfg, err := LoadConfig()
				require.NoError(t, err)
				require.Equal(t, tc.want, cfg.VerifyClockSource)
				require.False(t, cfg.InsecureVerifySkipped,
					"waiving the clock assertion must not skip attestation verification")
				require.Equal(t, !dev, cfg.KMSLocked)
			})
		}
	}
}

// Logs always ship; traces and metrics only when their variable is set true.
func TestLoadConfigTelemetrySignals(t *testing.T) {
	for _, tc := range []struct {
		name, traces, metrics   string
		wantTraces, wantMetrics bool
		wantErr                 string
	}{
		{name: "unset"},
		{name: "blank", traces: "  ", metrics: "  "},
		{name: "traces only", traces: "true", metrics: "false", wantTraces: true},
		{name: "padded uppercase metrics only", metrics: " TRUE ", wantMetrics: true},
		{name: "numeric", traces: "1", metrics: "0", wantTraces: true},
		{name: "traces not a boolean", traces: "yes", wantErr: "invalid ENCLAVE_TRACES"},
		{name: "metrics not a boolean", metrics: "on", wantErr: "invalid ENCLAVE_METRICS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setConfigTestEnv(t, false)
			t.Setenv(envTraces, tc.traces)
			t.Setenv(envMetrics, tc.metrics)

			cfg, err := LoadConfig()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantTraces, cfg.ExportTraces)
			require.Equal(t, tc.wantMetrics, cfg.ExportMetrics)
		})
	}
}

func TestLoadConfigInsecureVerifySkipped(t *testing.T) {
	for _, dev := range []bool{false, true} {
		for _, tc := range []struct {
			name, value string
			want        bool
		}{
			{name: "unset"},
			{name: "blank", value: "  "},
			{name: "enabled", value: "true", want: dev},
			{name: "disabled", value: "false"},
			{name: "padded lowercase", value: " true ", want: dev},
			{name: "uppercase uses default", value: " TRUE "},
			{name: "unrecognized uses default", value: "sometimes"},
		} {
			t.Run("dev="+strconv.FormatBool(dev)+"/"+tc.name, func(t *testing.T) {
				setConfigTestEnv(t, dev)
				t.Setenv(envInsecureVerifySkipped, tc.value)

				cfg, err := LoadConfig()
				require.NoError(t, err)
				require.Equal(t, tc.want, cfg.InsecureVerifySkipped)
				require.True(t, cfg.VerifyClockSource,
					"skipping attestation verification must not waive the clock assertion")
				require.Equal(t, !dev, cfg.KMSLocked)
			})
		}
	}
}

func TestApplySSMOverlay(t *testing.T) {
	t.Setenv(envSecretsConfig, "[]")
	t.Setenv(envDev, "false")
	t.Setenv("APPLY_FOO", "")
	t.Setenv("APPLY_BAR", "")
	t.Setenv("OTHER_PREFIX", "")
	t.Setenv("VALID_KEY", "")
	t.Setenv("nested/IGNORE", "")
	t.Setenv("SAFE_KEY", "")

	ctx := context.Background()
	path := func(key string) string { return "/prod/app/enclave/env/" + key }
	ssmFor := func(params map[string]string) SSM { return NewSSM(&fakeSSM{params: params}) }

	t.Run("no params", func(t *testing.T) {
		err := testCfg.ApplySSMOverlay(ctx, ssmFor(nil))
		require.NoError(t, err)
	})

	t.Run("applies current prefix", func(t *testing.T) {
		cfg := testConfig()
		cfg.OverrideAllowList = map[string]bool{
			"APPLY_FOO": true, "APPLY_BAR": true, "OTHER_PREFIX": true,
		}
		err := cfg.ApplySSMOverlay(ctx, ssmFor(map[string]string{
			path("APPLY_FOO"):                      "one",
			path("APPLY_BAR"):                      "two",
			"/prod/other/enclave/env/OTHER_PREFIX": "wrong-app",
			"/dev/app/enclave/env/OTHER_PREFIX":    "wrong-namespace",
			"/prod/app/env/OTHER_PREFIX":           "outside-namespace",
		}))
		require.NoError(t, err)
		require.Equal(t, map[string]string{"APPLY_FOO": "one", "APPLY_BAR": "two"}, cfg.ChildEnv)
		require.Empty(t, os.Getenv("APPLY_FOO"))
		require.Empty(t, os.Getenv("APPLY_BAR"))
	})

	t.Run("updates mutable runtime config", func(t *testing.T) {
		cfg := *testCfg
		err := cfg.ApplySSMOverlay(ctx, ssmFor(map[string]string{
			path(envAppPort):       "9090",
			path(envFQDN):          "app.example.com",
			path(envUseACME):       "TRUE",
			path(envACMEDirectory): "https://acme.example.com/directory",
			path(envACMEEmail):     "ops@example.com",
			path(envACMECA):        "test-ca",
		}))
		require.NoError(t, err)
		require.Equal(t, "9090", cfg.AppPort)
		require.Equal(t, "http://127.0.0.1:9090", cfg.AppWebSrv.String())
		require.Equal(t, "app.example.com", cfg.FQDN)
		require.True(t, cfg.UseACME)
		require.Equal(t, "https://acme.example.com/directory", cfg.ACMEDirectory)
		require.Equal(t, "ops@example.com", cfg.ACMEEmail)
		require.Equal(t, "test-ca", cfg.ACMECA)
	})

	t.Run("rejects invalid application port", func(t *testing.T) {
		cfg := *testCfg
		err := cfg.ApplySSMOverlay(ctx, ssmFor(map[string]string{
			path(envAppPort): "not-a-port",
		}))

		require.ErrorContains(t, err, "invalid application port")
		require.Equal(t, testCfg.AppPort, cfg.AppPort)
	})

	t.Run("skips empty and nested keys", func(t *testing.T) {
		cfg := testConfig()
		cfg.OverrideAllowList = map[string]bool{"VALID_KEY": true, "nested/IGNORE": true, "": true}
		err := cfg.ApplySSMOverlay(ctx, ssmFor(map[string]string{
			path("VALID_KEY"):     "ok",
			path("nested/IGNORE"): "bad",
			path(""):              "empty",
		}))
		require.NoError(t, err)
		require.Equal(t, map[string]string{"VALID_KEY": "ok"}, cfg.ChildEnv)
		require.Empty(t, os.Getenv("VALID_KEY"))
	})

	t.Run("skips non overridable keys", func(t *testing.T) {
		for _, dev := range []bool{false, true} {
			t.Run("dev="+strconv.FormatBool(dev), func(t *testing.T) {
				setConfigTestEnv(t, dev)
				t.Setenv(envPreviousPCR0, "original-pcr0")
				t.Setenv(envOverrideAllowList, "SAFE_KEY")
				t.Setenv("SAFE_KEY", "")
				cfg, err := LoadConfig()
				require.NoError(t, err)
				before := *cfg

				err = cfg.ApplySSMOverlay(ctx, ssmFor(map[string]string{
					path(envNamespace):             "dev",
					path(envAppName):               "evil",
					path(envSecretsConfig):         `[{"name":"evil"}]`,
					path(envInheritSecretsConfig):  `[{"name":"evil"}]`,
					path(envDev):                   strconv.FormatBool(!dev),
					path(envMigrationCooldown):     "0s",
					path(envVerifyClockSource):     "false",
					path(envInsecureVerifySkipped): "true",
					path(envTraces):                "true",
					path(envMetrics):               "true",
					path(envPreviousPCR0):          "evil-pcr0",
					path("SAFE_KEY"):               "ok",
				}))
				require.NoError(t, err)
				require.Empty(t, os.Getenv(envNamespace))
				require.Empty(t, os.Getenv(envAppName))
				require.Empty(t, os.Getenv(envSecretsConfig))
				require.Empty(t, os.Getenv(envInheritSecretsConfig),
					"the overlay must not be able to pin an inherited secret of its own")
				require.Empty(t, os.Getenv(envDev))
				require.Empty(t, os.Getenv(envMigrationCooldown))
				require.Empty(t, os.Getenv(envVerifyClockSource))
				require.Empty(t, os.Getenv(envInsecureVerifySkipped),
					"the overlay must not be able to skip attestation verification")
				require.Empty(t, os.Getenv(envPreviousPCR0))
				require.Equal(
					t,
					before,
					*cfg,
					"the overlay must preserve the loaded security settings",
				)
				require.Equal(t, map[string]string{"SAFE_KEY": "ok"}, cfg.ChildEnv)
				require.Empty(t, os.Getenv("SAFE_KEY"))
			})
		}
	})

	t.Run("returns SSM errors", func(t *testing.T) {
		err := testCfg.ApplySSMOverlay(ctx, NewSSM(&fakeSSM{err: errors.New("access denied")}))
		require.Error(t, err)
	})
}

func TestApplySSMOverlayAllowlist(t *testing.T) {
	for _, tc := range []struct {
		name, allowlist, wantAllowed, wantSecond, wantAllowlistEnv string
	}{
		{name: "empty rejects application overrides"},
		{
			name:        "comma separated names are trimmed and deduplicated",
			allowlist:   " APP_ALLOWED , APP_SECOND , APP_ALLOWED ",
			wantAllowed: "one", wantSecond: "two",
		},
		{
			name:        "overlay cannot expand the loaded allowlist",
			allowlist:   "APP_ALLOWED," + envOverrideAllowList,
			wantAllowed: "one", wantAllowlistEnv: "APP_BLOCKED",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setConfigTestEnv(t, false)
			t.Setenv(envOverrideAllowList, tc.allowlist)
			for _, key := range []string{"APP_ALLOWED", "APP_SECOND", "APP_BLOCKED"} {
				t.Setenv(key, "baked")
			}
			cfg, err := LoadConfig()
			require.NoError(t, err)
			_, present := os.LookupEnv(envOverrideAllowList)
			require.False(t, present, "the allowlist must be consumed by LoadConfig")

			err = cfg.ApplySSMOverlay(
				context.Background(),
				NewSSM(&fakeSSM{params: map[string]string{
					"/prod/app/enclave/env/APP_ALLOWED":             "one",
					"/prod/app/enclave/env/APP_SECOND":              "two",
					"/prod/app/enclave/env/APP_BLOCKED":             "changed",
					"/prod/app/enclave/env/" + envOverrideAllowList: "APP_BLOCKED",
					"/prod/app/enclave/env/" + envFQDN:              "overlay.example.com",
				}}),
			)

			require.NoError(t, err)
			require.Equal(t, tc.wantAllowed, cfg.ChildEnv["APP_ALLOWED"])
			require.Equal(t, tc.wantSecond, cfg.ChildEnv["APP_SECOND"])
			require.NotContains(t, cfg.ChildEnv, "APP_BLOCKED")
			require.Equal(t, tc.wantAllowlistEnv, cfg.ChildEnv[envOverrideAllowList])
			for _, key := range []string{"APP_ALLOWED", "APP_SECOND", "APP_BLOCKED"} {
				require.Equal(t, "baked", os.Getenv(key))
			}
			require.Empty(t, os.Getenv(envOverrideAllowList))
			require.False(t, cfg.OverrideAllowList["APP_BLOCKED"])
			require.Equal(t, "overlay.example.com", cfg.FQDN,
				"explicit runtime overrides do not require an application allowlist entry")
		})
	}
}

func TestApplySSMOverlayAllowlistedEnvPreservesLoadedConfig(t *testing.T) {
	setConfigTestEnv(t, true)
	const secrets = `[{"name":"signing-key","env_var":"SIGNING_KEY"}]`
	t.Setenv(envSecretsConfig, secrets)
	t.Setenv(envAppBinaryName, "measured-app")
	t.Setenv(envAWSRegion, "eu-west-1")
	t.Setenv(envOverrideAllowList,
		strings.Join([]string{
			envSecretsConfig, envDev, envNamespace, envAppBinaryName, envAWSRegion,
		}, ","))
	cfg, err := LoadConfig()
	require.NoError(t, err)
	before := *cfg
	metadata, err := LoadStaticSecretMetadata(*cfg)
	require.NoError(t, err)
	require.Equal(t, []StaticSecretMetadata{{Name: "signing-key", EnvVar: "SIGNING_KEY"}}, metadata)

	err = cfg.ApplySSMOverlay(context.Background(), NewSSM(&fakeSSM{params: map[string]string{
		"/prod/app/enclave/env/" + envSecretsConfig: `[{"name":"changed"}]`,
		"/prod/app/enclave/env/" + envDev:           "false",
		"/prod/app/enclave/env/" + envNamespace:     "other",
		"/prod/app/enclave/env/" + envAppBinaryName: "other-app",
		"/prod/app/enclave/env/" + envAWSRegion:     "us-west-2",
	}}))

	require.NoError(t, err)
	require.Equal(t, "other-app", cfg.ChildEnv[envAppBinaryName])
	require.Equal(t, `[{"name":"changed"}]`, cfg.ChildEnv[envSecretsConfig])
	require.Empty(t, os.Getenv(envAppBinaryName))
	require.Empty(t, os.Getenv(envSecretsConfig))
	require.Equal(
		t,
		before,
		*cfg,
		"allowlisted environment writes must not replace captured config",
	)
	after, err := LoadStaticSecretMetadata(*cfg)
	require.NoError(t, err)
	require.Equal(t, metadata, after, "boot must parse the captured secret definitions")
}
