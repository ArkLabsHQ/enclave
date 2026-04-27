package runtime

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type fakeSSM struct {
	params map[string]string
	err    error
	calls  []string
}

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	name := aws.ToString(in.Name)
	f.calls = append(f.calls, name)
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.params[name]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	return &ssm.GetParameterOutput{
		Parameter: &ssmtypes.Parameter{Name: aws.String(name), Value: aws.String(v)},
	}, nil
}

func TestApplyEnvOverrides(t *testing.T) {
	type tc struct {
		name      string
		schema    string
		baked     map[string]string
		ssmParams map[string]string
		ssmErr    error
		want      map[string]string // expected env value after override
		wantErr   bool
	}
	cases := []tc{
		{
			name:      "override applied for matching key",
			schema:    `["API_URL","ROLLOUT_ID"]`,
			baked:     map[string]string{"API_URL": "default", "ROLLOUT_ID": "green"},
			ssmParams: map[string]string{"/dev/myapp/env/API_URL": "https://prod.example.com"},
			want:      map[string]string{"API_URL": "https://prod.example.com", "ROLLOUT_ID": "green"},
		},
		{
			name:      "missing ssm param leaves baked default",
			schema:    `["API_URL"]`,
			baked:     map[string]string{"API_URL": "default"},
			ssmParams: map[string]string{},
			want:      map[string]string{"API_URL": "default"},
		},
		{
			name:      "empty schema is a no-op",
			schema:    `[]`,
			baked:     map[string]string{"X": "x"},
			ssmParams: map[string]string{"/dev/myapp/env/X": "override"},
			want:      map[string]string{"X": "x"},
		},
		{
			name:    "malformed schema returns error",
			schema:  `not-json`,
			wantErr: true,
		},
		{
			name:    "ssm error other than NotFound is fatal",
			schema:  `["X"]`,
			baked:   map[string]string{"X": "x"},
			ssmErr:  errors.New("access denied"),
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("ENCLAVE_APP_ENV_KEYS", c.schema)
			for k, v := range c.baked {
				t.Setenv(k, v)
			}
			fake := &fakeSSM{params: c.ssmParams, err: c.ssmErr}
			err := applyEnvOverrides(context.Background(), fake, "dev", "myapp")
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for k, want := range c.want {
				if got := os.Getenv(k); got != want {
					t.Errorf("env[%s] = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestApplyEnvOverridesEmptyEnvVar(t *testing.T) {
	t.Setenv("ENCLAVE_APP_ENV_KEYS", "")
	fake := &fakeSSM{}
	if err := applyEnvOverrides(context.Background(), fake, "dev", "myapp"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Errorf("expected no SSM calls, got %d", len(fake.calls))
	}
}
