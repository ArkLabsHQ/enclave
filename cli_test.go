package introspector_enclave

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// requireCmd skips the test if the given binary is not in PATH.
func requireCmd(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not found in PATH, skipping", name)
	}
}

// buildCLI builds the enclave CLI binary into the given directory.
func buildCLI(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "enclave")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/enclave")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build CLI: %v", err)
	}
	return bin
}

// TestCLI_Init builds the CLI and runs "enclave init" for each language.
func TestCLI_Init(t *testing.T) {
	binDir := t.TempDir()
	bin := buildCLI(t, binDir)

	for _, lang := range []string{"go", "nodejs", "dotnet", "rust"} {
		t.Run(lang, func(t *testing.T) {
			dir := t.TempDir()

			cmd := exec.Command(bin, "init", "--language", lang)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("enclave init --language %s failed:\n%s", lang, out)
			}

			// Verify enclave.yaml was created.
			cfgPath := filepath.Join(dir, "enclave", "enclave.yaml")
			if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
				t.Fatal("enclave/enclave.yaml not created")
			}

			// Verify critical framework files.
			for _, f := range []string{
				"flake.nix",
				"enclave/start.sh",
				"enclave/scripts/enclave_init.sh",
				"enclave/tofu/modules/enclave/kms.tf",
			} {
				if _, err := os.Stat(filepath.Join(dir, f)); os.IsNotExist(err) {
					t.Errorf("missing: %s", f)
				}
			}

			// Verify start.sh has NSM entropy seeding.
			startSh, _ := os.ReadFile(filepath.Join(dir, "enclave", "start.sh"))
			if !strings.Contains(string(startSh), "/dev/nsm") {
				t.Error("start.sh missing NSM entropy seeding")
			}

			// Verify kms.tf has destroy provisioner.
			kmsTf, _ := os.ReadFile(filepath.Join(dir, "enclave", "tofu", "modules", "enclave", "kms.tf"))
			if !strings.Contains(string(kmsTf), "when    = destroy") {
				t.Error("kms.tf missing destroy provisioner")
			}
		})
	}
}

// TestCLI_Build builds the CLI and runs "enclave build" using the
// test/app project. Requires Nix.
func TestCLI_Build(t *testing.T) {
	requireCmd(t, "nix")

	testAppDir, err := filepath.Abs("test/app")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(testAppDir, "enclave", "enclave.yaml")); os.IsNotExist(err) {
		t.Skip("test/app not found")
	}

	binDir := t.TempDir()
	bin := buildCLI(t, binDir)

	// Copy test/app to a temp dir to avoid polluting the repo.
	dir := t.TempDir()
	cpCmd := exec.Command("cp", "-r", testAppDir+"/.", dir)
	if err := cpCmd.Run(); err != nil {
		t.Fatalf("copy test app: %v", err)
	}

	// Init a git repo (build needs it).
	gitInit := exec.Command("git", "init")
	gitInit.Dir = dir
	if err := gitInit.Run(); err != nil {
		t.Fatalf("git init: %v", err)
	}
	gitAdd := exec.Command("git", "add", ".")
	gitAdd.Dir = dir
	if err := gitAdd.Run(); err != nil {
		t.Fatalf("git add: %v", err)
	}
	gitCommit := exec.Command("git", "-c", "user.email=test@test.com",
		"-c", "user.name=Test", "commit", "-m", "init")
	gitCommit.Dir = dir
	if err := gitCommit.Run(); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	// Run enclave build.
	buildCmd := exec.Command(bin, "build")
	buildCmd.Dir = dir
	out, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("enclave build failed:\n%s", out)
	}

	// Verify artifacts were created.
	for _, artifact := range []string{
		"enclave/artifacts/image.eif",
		"enclave/artifacts/pcr.json",
		"enclave/artifacts/enclave-mgmt",
		"enclave/artifacts/gvproxy",
		"enclave/build-config.json",
		"enclave/tofu/terraform.tfvars.json",
	} {
		if _, err := os.Stat(filepath.Join(dir, artifact)); os.IsNotExist(err) {
			t.Errorf("missing artifact: %s", artifact)
		}
	}

	// Verify PCR0 was extracted.
	pcr0 := readPCR0FromArtifacts(dir)
	if pcr0 == "" {
		t.Error("PCR0 should be populated after build")
	}
}
