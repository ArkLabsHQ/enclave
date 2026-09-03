package runtime

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

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
			name:    "deployment missing",
			mutate:  func(c *Config) { c.Deployment = "" },
			wantErr: "ENCLAVE_DEPLOYMENT must be set",
		},
		{
			name:    "app name missing",
			mutate:  func(c *Config) { c.AppName = "" },
			wantErr: "ENCLAVE_APP_NAME must be set",
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

func TestApplyEnvOverrides(t *testing.T) {
	t.Setenv("ENCLAVE_SECRETS_CONFIG", "[]")
	t.Setenv("ENCLAVE_DEV", "false")
	t.Setenv("APPLY_FOO", "")
	t.Setenv("APPLY_BAR", "")
	t.Setenv("OTHER_PREFIX", "")
	t.Setenv("VALID_KEY", "")
	t.Setenv("nested/IGNORE", "")
	t.Setenv("SAFE_KEY", "")

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
		err := ApplyEnvOverrides(ctx, testCfg, ssmFor(map[string]string{
			path("ENCLAVE_DEPLOYMENT"):     "dev",
			path("ENCLAVE_APP_NAME"):       "evil",
			path("ENCLAVE_SECRETS_CONFIG"): `[{"name":"evil"}]`,
			path("ENCLAVE_DEV"):            "true",
			path("SAFE_KEY"):               "ok",
		}))
		require.NoError(t, err)
		require.Equal(t, "[]", os.Getenv("ENCLAVE_SECRETS_CONFIG"))
		// ENCLAVE_DEV now selects the lock posture, both Object Lock retentions
		// and the migration cooldown, so an overlay that could set it would hand
		// back everything this refused elsewhere.
		require.Equal(t, "false", os.Getenv("ENCLAVE_DEV"))
		require.True(t, testCfg.KMSLocked)
		require.Equal(t, "ok", os.Getenv("SAFE_KEY"))
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
		{"ENCLAVE_DEV=false is not dev", "false", "dev", false},
		{"unset is not dev regardless of deployment", "", "dev", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("ENCLAVE_DEV", c.dev)
			t.Setenv("ENCLAVE_DEPLOYMENT", c.deployment)
			require.Equal(t, c.want, IsDev())
		})
	}
}
