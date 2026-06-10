package runtime

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type fakeSSM struct {
	params map[string]string
	err    error
	calls  []string

	// For GetParametersByPath pagination tests: pages[i] is the i-th page of
	// (Name, Value) pairs. nextTokens[i] is the NextToken returned on page i
	// (empty string = no more). lastDecryption captures the last call's
	// WithDecryption value so tests can assert SecureString handling.
	pages          [][]ssmtypes.Parameter
	nextTokens     []string
	lastDecryption bool
	pathCalls      int
}

func (f *fakeSSM) PutParameter(_ context.Context, _ *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	return &ssm.PutParameterOutput{}, nil
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

func (f *fakeSSM) GetParametersByPath(_ context.Context, in *ssm.GetParametersByPathInput, _ ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if in.WithDecryption != nil {
		f.lastDecryption = *in.WithDecryption
	}

	// Page-based mode: walk pages/nextTokens.
	if f.pages != nil {
		i := f.pathCalls
		f.pathCalls++
		if i >= len(f.pages) {
			return &ssm.GetParametersByPathOutput{}, nil
		}
		out := &ssm.GetParametersByPathOutput{Parameters: f.pages[i]}
		if i < len(f.nextTokens) && f.nextTokens[i] != "" {
			out.NextToken = aws.String(f.nextTokens[i])
		}
		return out, nil
	}

	// Simple mode: filter params by prefix, return in a single page.
	prefix := aws.ToString(in.Path)
	var out []ssmtypes.Parameter
	for name, val := range f.params {
		if strings.HasPrefix(name, prefix) {
			n, v := name, val
			out = append(out, ssmtypes.Parameter{Name: &n, Value: &v})
		}
	}
	return &ssm.GetParametersByPathOutput{Parameters: out}, nil
}

func TestLoadDeployTLSConfig(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "dev")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	p := func(k string) string { return "/dev/app/env/" + k }

	t.Run("defaults when unset", func(t *testing.T) {
		got, err := loadDeployTLSConfig(context.Background(), &fakeSSM{params: map[string]string{}})
		if err != nil {
			t.Fatalf("loadDeployTLSConfig: %v", err)
		}
		if got.FQDN != "localhost" || got.UseACME || got.Directory != "self-signed" || got.Email != "" {
			t.Errorf("defaults = %+v, want {localhost false self-signed }", got)
		}
	})

	t.Run("acme params populated", func(t *testing.T) {
		fake := &fakeSSM{params: map[string]string{
			p("ENCLAVE_NITRIDING_FQDN"):           "api.example.com",
			p("ENCLAVE_NITRIDING_USE_ACME"):       "true",
			p("ENCLAVE_NITRIDING_ACME_DIRECTORY"): "letsencrypt-staging",
			p("ENCLAVE_NITRIDING_ACME_EMAIL"):     "ops@example.com",
		}}
		got, err := loadDeployTLSConfig(context.Background(), fake)
		if err != nil {
			t.Fatalf("loadDeployTLSConfig: %v", err)
		}
		if got.FQDN != "api.example.com" || !got.UseACME ||
			got.Directory != "letsencrypt-staging" || got.Email != "ops@example.com" {
			t.Errorf("got %+v", got)
		}
	})

	t.Run("custom directory and ca", func(t *testing.T) {
		wantCA := "-----BEGIN CERTIFICATE-----\nQ0E=\n-----END CERTIFICATE-----"
		fake := &fakeSSM{params: map[string]string{
			p("ENCLAVE_NITRIDING_FQDN"):           "enclave.test",
			p("ENCLAVE_NITRIDING_USE_ACME"):       "true",
			p("ENCLAVE_NITRIDING_ACME_DIRECTORY"): "https://pebble.internal:14000/dir",
			p("ENCLAVE_NITRIDING_ACME_CA"):        wantCA,
		}}
		got, err := loadDeployTLSConfig(context.Background(), fake)
		if err != nil {
			t.Fatalf("loadDeployTLSConfig: %v", err)
		}
		if got.Directory != "https://pebble.internal:14000/dir" {
			t.Errorf("Directory = %q", got.Directory)
		}
		if got.CA != wantCA {
			t.Errorf("CA = %q, want %q", got.CA, wantCA)
		}
	})

	t.Run("ssm error surfaces", func(t *testing.T) {
		_, err := loadDeployTLSConfig(context.Background(), &fakeSSM{err: errors.New("AccessDenied")})
		requireErrContains(t, err, "ssm get-parameter")
	})
}

// TestApplyEnvOverrides_EmptyPrefix: no params under prefix → no-op, no error.
func TestApplyEnvOverrides_EmptyPrefix(t *testing.T) {
	fake := &fakeSSM{params: map[string]string{}}
	if err := applyEnvOverrides(context.Background(), fake, "dev", "myapp"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestApplyEnvOverrides_SinglePage: 3 params under the prefix → all set as env.
func TestApplyEnvOverrides_SinglePage(t *testing.T) {
	// Ensure clean env before test so leftover values don't mask bugs.
	for _, k := range []string{"FOO", "BAR", "BAZ"} {
		_ = os.Unsetenv(k)
	}
	fake := &fakeSSM{params: map[string]string{
		"/dev/myapp/env/FOO": "one",
		"/dev/myapp/env/BAR": "two",
		"/dev/myapp/env/BAZ": "three",
	}}
	if err := applyEnvOverrides(context.Background(), fake, "dev", "myapp"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for k, want := range map[string]string{"FOO": "one", "BAR": "two", "BAZ": "three"} {
		if got := os.Getenv(k); got != want {
			t.Errorf("env[%s] = %q, want %q", k, got, want)
		}
	}
}

// TestApplyEnvOverrides_Paginated: NextToken cycles through two pages.
func TestApplyEnvOverrides_Paginated(t *testing.T) {
	_ = os.Unsetenv("PAGE1_A")
	_ = os.Unsetenv("PAGE1_B")
	_ = os.Unsetenv("PAGE2_C")
	mk := func(n, v string) ssmtypes.Parameter {
		return ssmtypes.Parameter{Name: aws.String(n), Value: aws.String(v)}
	}
	fake := &fakeSSM{
		pages: [][]ssmtypes.Parameter{
			{mk("/dev/myapp/env/PAGE1_A", "a"), mk("/dev/myapp/env/PAGE1_B", "b")},
			{mk("/dev/myapp/env/PAGE2_C", "c")},
		},
		nextTokens: []string{"token-page-2", ""}, // first call returns NextToken, second drains
	}
	if err := applyEnvOverrides(context.Background(), fake, "dev", "myapp"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.pathCalls != 2 {
		t.Errorf("expected 2 GetParametersByPath calls, got %d", fake.pathCalls)
	}
	for k, want := range map[string]string{"PAGE1_A": "a", "PAGE1_B": "b", "PAGE2_C": "c"} {
		if got := os.Getenv(k); got != want {
			t.Errorf("env[%s] = %q, want %q", k, got, want)
		}
	}
}

// TestApplyEnvOverrides_SecureString: WithDecryption: true must be sent so
// SSM SecureString params are returned plaintext to the caller.
func TestApplyEnvOverrides_SecureString(t *testing.T) {
	fake := &fakeSSM{params: map[string]string{}}
	if err := applyEnvOverrides(context.Background(), fake, "dev", "myapp"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fake.lastDecryption {
		t.Error("expected WithDecryption=true on GetParametersByPath call")
	}
}

// TestApplyEnvOverrides_SkipsNestedAndEmpty: defensive — keys with '/' (nested
// under a sub-path) or empty after prefix-strip are ignored, not setenv'd.
func TestApplyEnvOverrides_SkipsNestedAndEmpty(t *testing.T) {
	_ = os.Unsetenv("VALID_KEY")
	fake := &fakeSSM{params: map[string]string{
		"/dev/myapp/env/VALID_KEY":     "ok",
		"/dev/myapp/env/nested/IGNORE": "should-not-set",
		"/dev/myapp/env/":              "empty-key", // edge: stat as a folder
	}}
	if err := applyEnvOverrides(context.Background(), fake, "dev", "myapp"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := os.Getenv("VALID_KEY"); got != "ok" {
		t.Errorf("VALID_KEY = %q, want %q", got, "ok")
	}
	// IGNORE (under the nested path) must not have been set.
	if got := os.Getenv("IGNORE"); got != "" {
		t.Errorf("IGNORE was set to %q; nested keys must be skipped", got)
	}
}

// TestApplyEnvOverrides_SSMError: a non-NotFound error from SSM must surface.
func TestApplyEnvOverrides_SSMError(t *testing.T) {
	fake := &fakeSSM{err: errors.New("access denied")}
	err := applyEnvOverrides(context.Background(), fake, "dev", "myapp")
	requireErrContains(t, err, "ssm get-parameters-by-path")
}

// The overlay must never change framework-identity vars: an SSM writer could
// otherwise set ENCLAVE_DEPLOYMENT=dev to flip the COSE-verification skip.
func TestApplyEnvOverrides_SkipsNonOverridable(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	_ = os.Unsetenv("SAFE_KEY")
	fake := &fakeSSM{params: map[string]string{
		"/prod/myapp/env/ENCLAVE_DEPLOYMENT": "dev",
		"/prod/myapp/env/ENCLAVE_APP_NAME":   "evil",
		"/prod/myapp/env/SAFE_KEY":           "ok",
	}}
	if err := applyEnvOverrides(context.Background(), fake, "prod", "myapp"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := os.Getenv("ENCLAVE_DEPLOYMENT"); got != "prod" {
		t.Errorf("ENCLAVE_DEPLOYMENT overridden via overlay to %q; must stay %q", got, "prod")
	}
	if got := os.Getenv("ENCLAVE_APP_NAME"); got != "myapp" {
		t.Errorf("ENCLAVE_APP_NAME overridden via overlay to %q; must stay %q", got, "myapp")
	}
	if got := os.Getenv("SAFE_KEY"); got != "ok" {
		t.Errorf("non-identity key should still apply, got %q", got)
	}
}
