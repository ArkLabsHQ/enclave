package runtime

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyEnvOverrides(t *testing.T) {
	t.Setenv("ENCLAVE_SECRETS_CONFIG", "[]")
	t.Setenv("ENCLAVE_DEV", "false")
	t.Setenv("APPLY_FOO", "")
	t.Setenv("APPLY_BAR", "")
	t.Setenv("OTHER_PREFIX", "")
	t.Setenv("VALID_KEY", "")
	t.Setenv("nested/IGNORE", "")
	t.Setenv("SAFE_KEY", "")
	t.Setenv("ENCLAVE_LOG_GROUP_PREFIX", "")

	ctx := context.Background()
	path := func(key string) string { return "/prod/app/env/" + key }
	ssmFor := func(params map[string]string) SSM { return NewSSM(&fakeSSM{params: params}) }

	t.Run("no params", func(t *testing.T) {
		err := ApplyEnvOverrides(ctx, testCfg, ssmFor(nil))
		require.NoError(t, err)
	})

	t.Run("applies current prefix", func(t *testing.T) {
		err := ApplyEnvOverrides(ctx, testCfg, ssmFor(map[string]string{
			path("APPLY_FOO"):              "one",
			path("APPLY_BAR"):              "two",
			"/prod/other/env/OTHER_PREFIX": "wrong-app",
			"/dev/app/env/OTHER_PREFIX":    "wrong-deploy",
		}))
		require.NoError(t, err)
		require.Equal(t, "one", os.Getenv("APPLY_FOO"))
		require.Equal(t, "two", os.Getenv("APPLY_BAR"))
		require.Empty(t, os.Getenv("OTHER_PREFIX"))
	})

	t.Run("updates mutable runtime config", func(t *testing.T) {
		cfg := *testCfg
		err := ApplyEnvOverrides(ctx, &cfg, ssmFor(map[string]string{
			path("ENCLAVE_APP_PORT"):         "9090",
			path("ENCLAVE_FQDN"):             "app.example.com",
			path("ENCLAVE_USE_ACME"):         "TRUE",
			path("ENCLAVE_ACME_DIRECTORY"):   "https://acme.example.com/directory",
			path("ENCLAVE_ACME_EMAIL"):       "ops@example.com",
			path("ENCLAVE_ACME_CA"):          "test-ca",
			path("ENCLAVE_LOG_GROUP_PREFIX"): "/ark/se7enz",
		}))
		require.NoError(t, err)
		require.Equal(t, "9090", cfg.AppPort)
		require.Equal(t, "http://127.0.0.1:9090", cfg.AppWebSrv.String())
		require.Equal(t, "app.example.com", cfg.FQDN)
		require.True(t, cfg.UseACME)
		require.Equal(t, "https://acme.example.com/directory", cfg.ACMEDirectory)
		require.Equal(t, "ops@example.com", cfg.ACMEEmail)
		require.Equal(t, "test-ca", cfg.ACMECA)
		require.Equal(t, "/ark/se7enz", cfg.LogGroupPrefix)
	})

	t.Run("rejects an unusable log group prefix", func(t *testing.T) {
		cfg := *testCfg
		err := ApplyEnvOverrides(ctx, &cfg, ssmFor(map[string]string{
			path("ENCLAVE_LOG_GROUP_PREFIX"): "/ark:evil",
		}))

		require.ErrorContains(t, err, "apply env override ENCLAVE_LOG_GROUP_PREFIX")
		require.Equal(t, testCfg.LogGroupPrefix, cfg.LogGroupPrefix)
	})

	t.Run("rejects invalid application port", func(t *testing.T) {
		cfg := *testCfg
		err := ApplyEnvOverrides(ctx, &cfg, ssmFor(map[string]string{
			path("ENCLAVE_APP_PORT"): "not-a-port",
		}))

		require.ErrorContains(t, err, "invalid application port")
		require.Equal(t, testCfg.AppPort, cfg.AppPort)
	})

	t.Run("skips empty and nested keys", func(t *testing.T) {
		err := ApplyEnvOverrides(ctx, testCfg, ssmFor(map[string]string{
			path("VALID_KEY"):     "ok",
			path("nested/IGNORE"): "bad",
			path(""):              "empty",
		}))
		require.NoError(t, err)
		require.Equal(t, "ok", os.Getenv("VALID_KEY"))
		require.Empty(t, os.Getenv("nested/IGNORE"))
	})

	t.Run("skips non overridable keys", func(t *testing.T) {
		for _, dev := range []bool{false, true} {
			t.Run("dev="+strconv.FormatBool(dev), func(t *testing.T) {
				setConfigTestEnv(t, dev)
				t.Setenv("ENCLAVE_PREVIOUS_PCR0", "original-pcr0")
				t.Setenv("SAFE_KEY", "")
				cfg, err := LoadConfig()
				require.NoError(t, err)
				before := *cfg

				err = ApplyEnvOverrides(ctx, cfg, ssmFor(map[string]string{
					path("ENCLAVE_DEPLOYMENT"):              "dev",
					path("ENCLAVE_APP_NAME"):                "evil",
					path("ENCLAVE_SECRETS_CONFIG"):          `[{"name":"evil"}]`,
					path("ENCLAVE_DEV"):                     strconv.FormatBool(!dev),
					path("ENCLAVE_MIGRATION_COOLDOWN"):      "0s",
					path("ENCLAVE_VERIFY_CLOCK_SOURCE"):     "false",
					path("ENCLAVE_INSECURE_VERIFY_SKIPPED"): "true",
					path("ENCLAVE_PREVIOUS_PCR0"):           "evil-pcr0",
					path("SAFE_KEY"):                        "ok",
				}))
				require.NoError(t, err)
				require.Equal(t, "prod", os.Getenv("ENCLAVE_DEPLOYMENT"))
				require.Equal(t, "app", os.Getenv("ENCLAVE_APP_NAME"))
				require.Equal(t, "[]", os.Getenv("ENCLAVE_SECRETS_CONFIG"))
				require.Equal(t, strconv.FormatBool(dev), os.Getenv("ENCLAVE_DEV"))
				require.Empty(t, os.Getenv("ENCLAVE_MIGRATION_COOLDOWN"))
				require.Empty(t, os.Getenv("ENCLAVE_VERIFY_CLOCK_SOURCE"))
				require.Empty(t, os.Getenv("ENCLAVE_INSECURE_VERIFY_SKIPPED"),
					"the overlay must not be able to skip attestation verification")
				require.Equal(t, "original-pcr0", os.Getenv("ENCLAVE_PREVIOUS_PCR0"))
				require.Equal(
					t,
					before,
					*cfg,
					"the overlay must preserve the loaded security settings",
				)
				require.Equal(t, "ok", os.Getenv("SAFE_KEY"))
			})
		}
	})

	t.Run("returns SSM errors", func(t *testing.T) {
		err := ApplyEnvOverrides(ctx, testCfg, NewSSM(&fakeSSM{err: errors.New("access denied")}))
		require.Error(t, err)
	})
}

func TestIsDev(t *testing.T) {
	cases := []struct {
		name            string
		dev, deployment string
		want            bool
	}{
		{"ENCLAVE_DEV=true is dev", "true", "prod", true},
		{"ENCLAVE_DEV case-insensitive", "TRUE", "prod", true},
		{"ENCLAVE_DEV mixed case", "True", "prod", true},
		{"ENCLAVE_DEV trims whitespace", "  true  ", "prod", true},
		{"ENCLAVE_DEV=false is not dev", "false", "dev", false},
		{"unset is not dev regardless of deployment", "", "dev", false},
		{"ENCLAVE_DEV=1 is not dev", "1", "dev", false},
		{"ENCLAVE_DEV=yes is not dev", "yes", "dev", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("ENCLAVE_DEV", c.dev)
			t.Setenv("ENCLAVE_DEPLOYMENT", c.deployment)
			require.Equal(t, c.want, IsDev())
		})
	}
}
