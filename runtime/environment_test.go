package runtime

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyEnvOverrides(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_ANCHOR_WINDOW", "10h")
	t.Setenv("ENCLAVE_KMS_KEY_LOCKED", "true")
	t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "1m")
	t.Setenv("ENCLAVE_SECRETS_CONFIG", "[]")
	t.Setenv("ENCLAVE_PREVIOUS_PCR0", "pcr0")
	t.Setenv("APPLY_FOO", "")
	t.Setenv("APPLY_BAR", "")
	t.Setenv("OTHER_PREFIX", "")
	t.Setenv("VALID_KEY", "")
	t.Setenv("nested/IGNORE", "")
	t.Setenv("SAFE_KEY", "")

	ctx := context.Background()
	path := func(key string) string { return "/prod/myapp/env/" + key }
	ssmFor := func(params map[string]string) SSM { return NewSSM(&fakeSSM{params: params}) }

	t.Run("no params", func(t *testing.T) {
		err := ApplyEnvOverrides(ctx, ssmFor(nil))
		require.NoError(t, err)
	})

	t.Run("applies current prefix", func(t *testing.T) {
		err := ApplyEnvOverrides(ctx, ssmFor(map[string]string{
			path("APPLY_FOO"):              "one",
			path("APPLY_BAR"):              "two",
			"/prod/other/env/OTHER_PREFIX": "wrong-app",
			"/dev/myapp/env/OTHER_PREFIX":  "wrong-deploy",
		}))
		require.NoError(t, err)
		require.Equal(t, "one", os.Getenv("APPLY_FOO"))
		require.Equal(t, "two", os.Getenv("APPLY_BAR"))
		require.Empty(t, os.Getenv("OTHER_PREFIX"))
	})

	t.Run("skips empty and nested keys", func(t *testing.T) {
		err := ApplyEnvOverrides(ctx, ssmFor(map[string]string{
			path("VALID_KEY"):     "ok",
			path("nested/IGNORE"): "bad",
			path(""):              "empty",
		}))
		require.NoError(t, err)
		require.Equal(t, "ok", os.Getenv("VALID_KEY"))
		require.Empty(t, os.Getenv("nested/IGNORE"))
	})

	t.Run("skips non overridable keys", func(t *testing.T) {
		err := ApplyEnvOverrides(ctx, ssmFor(map[string]string{
			path("ENCLAVE_DEPLOYMENT"):         "dev",
			path("ENCLAVE_APP_NAME"):           "evil",
			path("ENCLAVE_ANCHOR_WINDOW"):      "1s",
			path("ENCLAVE_KMS_KEY_LOCKED"):     "false",
			path("ENCLAVE_MIGRATION_COOLDOWN"): "0s",
			path("ENCLAVE_SECRETS_CONFIG"):     `[{"name":"evil"}]`,
			path("ENCLAVE_PREVIOUS_PCR0"):      "evil-pcr0",
			path("SAFE_KEY"):                   "ok",
		}))
		require.NoError(t, err)
		require.Equal(t, "prod", os.Getenv("ENCLAVE_DEPLOYMENT"))
		require.Equal(t, "myapp", os.Getenv("ENCLAVE_APP_NAME"))
		require.Equal(t, "10h", os.Getenv("ENCLAVE_ANCHOR_WINDOW"))
		require.Equal(t, "true", os.Getenv("ENCLAVE_KMS_KEY_LOCKED"))
		require.Equal(t, "1m", os.Getenv("ENCLAVE_MIGRATION_COOLDOWN"))
		require.Equal(t, "[]", os.Getenv("ENCLAVE_SECRETS_CONFIG"))
		require.Equal(t, "pcr0", os.Getenv("ENCLAVE_PREVIOUS_PCR0"))
		require.Equal(t, "ok", os.Getenv("SAFE_KEY"))
	})

	t.Run("returns SSM errors", func(t *testing.T) {
		err := ApplyEnvOverrides(ctx, NewSSM(&fakeSSM{err: errors.New("access denied")}))
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
