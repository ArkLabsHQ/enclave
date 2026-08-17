package supervisor

import (
	"strings"
	"testing"
)

func TestValidateEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name    string
		key     string
		value   string
		wantErr string
	}{
		{name: "all set"},
		{
			name: "deployment missing", key: "ENCLAVE_DEPLOYMENT",
			wantErr: "ENCLAVE_DEPLOYMENT must be set",
		},
		{
			name: "app name missing", key: "ENCLAVE_APP_NAME",
			wantErr: "ENCLAVE_APP_NAME must be set",
		},
		{
			name: "deployment blank", key: "ENCLAVE_DEPLOYMENT", value: "   ",
			wantErr: "ENCLAVE_DEPLOYMENT must be set",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
			t.Setenv("ENCLAVE_APP_NAME", "myapp")
			if tc.key != "" {
				t.Setenv(tc.key, tc.value)
			}

			err := validateEnvironment()

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateEnvironment() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateEnvironment() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
