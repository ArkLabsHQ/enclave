package cli

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
	cmd := exec.Command("go", "build", "-o", bin, "./cli/cmd/enclave")
	cmd.Dir = ".."
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

			// Verify critical build-time framework files.
			for _, f := range []string{
				"enclave/flake.nix",
			} {
				if _, err := os.Stat(filepath.Join(dir, f)); os.IsNotExist(err) {
					t.Errorf("missing: %s", f)
				}
			}
			// flake.nix at repo root must NOT exist post-refactor.
			if _, err := os.Stat(filepath.Join(dir, "flake.nix")); err == nil {
				t.Error("flake.nix found at repo root; should be under enclave/")
			}
			// `enclave init` must NOT scaffold tofu files — that's `enclave tofu`.
			if _, err := os.Stat(filepath.Join(dir, "tofu")); err == nil {
				t.Error("tofu/ found after init; should only be created by 'enclave tofu'")
			}
			if _, err := os.Stat(filepath.Join(dir, "enclave", "tofu")); err == nil {
				t.Error("enclave/tofu/ found after init; tofu tree now lives at ./tofu/")
			}

			// `enclave tofu` scaffolds the consolidated OpenTofu tree: one
			// main.tf per module, plus the user_data template.
			tofuCmd := exec.Command(bin, "tofu")
			tofuCmd.Dir = dir
			if out, err := tofuCmd.CombinedOutput(); err != nil {
				t.Fatalf("enclave tofu failed:\n%s", out)
			}
			for _, f := range []string{
				"tofu/main.tf",
				"tofu/modules/backend/main.tf",
				"tofu/modules/enclave/main.tf",
				"tofu/modules/enclave/templates/user_data.sh.tftpl",
			} {
				if _, err := os.Stat(filepath.Join(dir, f)); os.IsNotExist(err) {
					t.Errorf("missing after enclave tofu: %s", f)
				}
			}

			// Destroy provisioner content (from the old kms.tf) now lives
			// inside the merged module main.tf.
			moduleMain, _ := os.ReadFile(filepath.Join(dir, "tofu", "modules", "enclave", "main.tf"))
			if !strings.Contains(string(moduleMain), "when    = destroy") {
				t.Error("modules/enclave/main.tf missing destroy provisioner")
			}
		})
	}
}

// TestCLI_Build builds the CLI and runs "enclave build" using the
// test/app project. Requires Nix.
func TestCLI_Build(t *testing.T) {
	requireCmd(t, "nix")

	testAppDir, err := filepath.Abs("../test/app")
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

	// Verify artifacts were created. terraform.tfvars.json is no longer a
	// build output — `enclave tofu` writes it now (verified separately in
	// TestCLI_Init).
	for _, artifact := range []string{
		".enclave/artifacts/image.eif",
		".enclave/artifacts/pcr.json",
		".enclave/artifacts/supervisor",
		".enclave/build-config.json",
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
