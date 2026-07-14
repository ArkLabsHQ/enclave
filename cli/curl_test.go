package cli

import (
	"io"
	"os"
	"strings"
	"testing"
)

func runCurl_(args ...string) error {
	cmd := curlCmd()
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cmd.Execute()
}

func TestCurlFlagValidation(t *testing.T) {
	// --insecure and --strict-tls are mutually exclusive.
	err := runCurl_("--insecure", "--strict-tls", "--base-url", "https://x", "/health")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got: %v", err)
	}

	// Verified mode (default) requires --expected-pcr0.
	err = runCurl_("--base-url", "https://x", "/health")
	if err == nil || !strings.Contains(err.Error(), "expected-pcr0 is required") {
		t.Fatalf("expected pcr0-required error, got: %v", err)
	}
}

// TestCurlInsecureWarns checks --insecure skips the pcr0 requirement and warns on stderr.
func TestCurlInsecureWarns(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	err := runCurl_("--insecure", "--base-url", "https://127.0.0.1:1", "/health")

	_ = w.Close()
	os.Stderr = old
	out, _ := io.ReadAll(r)

	// It must NOT have failed on the pcr0 requirement (insecure bypasses it).
	if err != nil && strings.Contains(err.Error(), "expected-pcr0") {
		t.Fatalf("--insecure must bypass the pcr0 requirement, got: %v", err)
	}
	if !strings.Contains(string(out), "WARNING") || !strings.Contains(strings.ToLower(string(out)), "insecure") {
		t.Fatalf("--insecure must warn on stderr, got: %q", out)
	}
}
