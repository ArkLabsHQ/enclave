package runtime

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTelemetryEnvValidation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		token    string
		wantErr  string
	}{
		{"equals", "BAD=NAME", "TOKEN", "invalid environment variable name"},
		{"whitespace", " ENDPOINT", "TOKEN", "invalid environment variable name"},
		{"digit", "ENDPOINT", "1TOKEN", "invalid environment variable name"},
		{"newline", "ENDPOINT", "TOKEN\n", "invalid environment variable name"},
		{"port collision", "PORT", "TOKEN", "reserved"},
		{"proxy port collision", "ENDPOINT", "ENCLAVE_PROXY_PORT", "reserved"},
		{"default token collision", defaultOtelTokenEnv, "TOKEN", "reserved"},
		{"duplicate names", "SAME", "SAME", "must use different names"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, source := range []string{"baked", "SSM"} {
				t.Run(source, func(t *testing.T) {
					setConfigTestEnv(t, false)
					t.Setenv(envOtelEndpointEnv, defaultOtelEndpointEnv)
					t.Setenv(envOtelTokenEnv, defaultOtelTokenEnv)
					if source == "baked" {
						t.Setenv(envOtelEndpointEnv, tc.endpoint)
						t.Setenv(envOtelTokenEnv, tc.token)
					}
					cfg, err := LoadConfig()
					require.NoError(t, err)
					if source == "baked" {
						err = cfg.Validate()
					} else {
						err = cfg.ApplySSMOverlay(t.Context(), NewSSM(&fakeSSM{
							params: map[string]string{
								"/prod/app/enclave/env/" + envOtelEndpointEnv: tc.endpoint,
								"/prod/app/enclave/env/" + envOtelTokenEnv:    tc.token,
							},
						}))
					}
					require.ErrorContains(t, err, tc.wantErr)
				})
			}
		})
	}
}

func TestTelemetryEnvSecretCollisions(t *testing.T) {
	cfg := Config{OtelEndpointEnv: "APP_ENDPOINT", OtelTokenEnv: "APP_TOKEN"}
	for _, name := range []string{defaultOtelEndpointEnv, cfg.OtelEndpointEnv, cfg.OtelTokenEnv} {
		t.Run(name, func(t *testing.T) {
			static := SecretsMetadata{
				Static: []StaticSecretMetadata{{Name: "key", EnvVar: name}},
			}
			require.ErrorContains(t, static.Validate(cfg), "reserved")
			inherited := SecretsMetadata{
				Inherited: []InheritSecretMetadata{{Name: "key", EnvVar: name}},
			}
			require.ErrorContains(t, inherited.Validate(cfg), "reserved")
		})
	}
}
