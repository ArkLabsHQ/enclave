package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildComposeDoc asserts the generated compose has the four
// baseline services with image tags derived from the framework
// runtime version + cfg.Name / cfg.Deployment wired into the test-runner.
func TestBuildComposeDoc(t *testing.T) {
	cfg := &Config{Name: "my-app", Deployment: "dev"}
	doc := buildComposeDoc(cfg, "0.0.99")

	want := []string{"local-kms", "aws-mocks", "localstack", "test-runner"}
	for _, name := range want {
		if _, ok := doc.Services[name]; !ok {
			t.Errorf("services[%q] missing from compose doc", name)
		}
	}
	if got := doc.Services["aws-mocks"].Image; got != "ghcr.io/arklabshq/enclave-awsmocks:0.0.99" {
		t.Errorf("aws-mocks image = %q, want ghcr.io/arklabshq/enclave-awsmocks:0.0.99", got)
	}
	if got := doc.Services["test-runner"].Image; got != "ghcr.io/arklabshq/enclave-test-runner:0.0.99" {
		t.Errorf("test-runner image = %q, want ghcr.io/arklabshq/enclave-test-runner:0.0.99", got)
	}
	if got := doc.Services["test-runner"].Environment["ENCLAVE_APP_NAME"]; got != "my-app" {
		t.Errorf("ENCLAVE_APP_NAME = %q, want my-app", got)
	}
	if got := doc.Services["test-runner"].Environment["ENCLAVE_DEPLOYMENT"]; got != "dev" {
		t.Errorf("ENCLAVE_DEPLOYMENT = %q, want dev", got)
	}
	if !doc.Services["test-runner"].Privileged {
		t.Errorf("test-runner.privileged = false, want true")
	}
}

// TestWriteTestComposeMergeOnlyNew confirms a second invocation
// against the same project skips the existing file (so user
// hand-edits survive re-runs) unless force=true.
func TestWriteTestComposeMergeOnlyNew(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{Name: "my-app", Deployment: "dev"}

	// Need a non-empty runtimeRev for writeTestCompose; restore at end.
	prev := runtimeRev
	runtimeRev = "v0.0.99"
	t.Cleanup(func() { runtimeRev = prev })

	written, err := writeTestCompose(cfg, root, false)
	if err != nil {
		t.Fatalf("initial write: %v", err)
	}
	if !written {
		t.Fatalf("initial write reported written=false; want true")
	}

	composeAbs := filepath.Join(root, composeFilePath)
	contents, err := os.ReadFile(composeAbs)
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}
	hand := append(contents, []byte("\n# user hand edit\n")...)
	if err := os.WriteFile(composeAbs, hand, 0o644); err != nil {
		t.Fatal(err)
	}

	written, err = writeTestCompose(cfg, root, false)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if written {
		t.Errorf("second write reported written=true; want false (merge-only-new)")
	}
	after, _ := os.ReadFile(composeAbs)
	if !strings.Contains(string(after), "# user hand edit") {
		t.Errorf("merge-only-new clobbered user edit")
	}

	written, err = writeTestCompose(cfg, root, true)
	if err != nil {
		t.Fatalf("force write: %v", err)
	}
	if !written {
		t.Errorf("--force-compose returned written=false; want true")
	}
	regenerated, _ := os.ReadFile(composeAbs)
	if strings.Contains(string(regenerated), "# user hand edit") {
		t.Errorf("--force-compose preserved the user edit; want regenerated from scratch")
	}
}

// TestWriteTestComposeIncludesMarker confirms the user-services
// comment block is appended verbatim — that marker is the only
// documented spot for adding mock-arkd / mock-postgres / etc.
func TestWriteTestComposeIncludesMarker(t *testing.T) {
	root := t.TempDir()
	prev := runtimeRev
	runtimeRev = "v0.0.99"
	t.Cleanup(func() { runtimeRev = prev })

	if _, err := writeTestCompose(&Config{Name: "app", Deployment: "dev"}, root, false); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(filepath.Join(root, composeFilePath))
	if !strings.Contains(string(body), "# === user services below this line ===") {
		t.Errorf("user-services marker missing from generated compose")
	}
}

// TestWriteTestComposeUnknownVersion ensures we fail loudly if the
// CLI binary was built without a framework version baked in.
func TestWriteTestComposeUnknownVersion(t *testing.T) {
	prev := runtimeRev
	runtimeRev = ""
	t.Cleanup(func() { runtimeRev = prev })

	_, err := writeTestCompose(&Config{Name: "app", Deployment: "dev"}, t.TempDir(), false)
	requireErrContains(t, err, "framework runtime version unknown")
}
