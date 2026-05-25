package cli

import (
	"encoding/json"
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
			// `enclave init` must NOT scaffold tofu files — that's `enclave tofu init`.
			if _, err := os.Stat(filepath.Join(dir, "tofu")); err == nil {
				t.Error("tofu/ found after init; should only be created by 'enclave tofu init'")
			}
			if _, err := os.Stat(filepath.Join(dir, "enclave", "tofu")); err == nil {
				t.Error("enclave/tofu/ found after init; tofu tree now lives at ./tofu/")
			}

			// `enclave tofu init` scaffolds the consolidated OpenTofu tree: one
			// main.tf per module, plus the user_data template.
			tofuCmd := exec.Command(bin, "tofu", "init")
			tofuCmd.Dir = dir
			tofuCmd.Stdin = nil // /dev/null — never let the subprocess inherit a TTY
			if out, err := tofuCmd.CombinedOutput(); err != nil {
				t.Fatalf("enclave tofu init failed:\n%s", out)
			}
			for _, f := range []string{
				"tofu/main.tf",
				"tofu/modules/backend/main.tf",
				"tofu/modules/enclave/main.tf",
				"tofu/modules/enclave/templates/user_data.sh.tftpl",
			} {
				if _, err := os.Stat(filepath.Join(dir, f)); os.IsNotExist(err) {
					t.Errorf("missing after enclave tofu init: %s", f)
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

// runEnclaveTofu runs `enclave init --language go && enclave tofu init [args...]`
// in a fresh temp dir and returns the parsed terraform.tfvars.json.
func runEnclaveTofu(t *testing.T, bin string, tofuArgs []string, yamlEdits map[string]string) map[string]any {
	t.Helper()
	dir := t.TempDir()

	initCmd := exec.Command(bin, "init", "--language", "go")
	initCmd.Dir = dir
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("enclave init failed:\n%s", out)
	}

	// Mutate enclave.yaml so nix_owner/nix_repo/release_tag are non-empty —
	// `enclave tofu init --remote` requires owner+repo, and the default
	// release_tag from the loader is "eif-latest" but the scaffolded file
	// pins it.
	cfgPath := filepath.Join(dir, "enclave", "enclave.yaml")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read enclave.yaml: %v", err)
	}
	updated := string(cfg)
	for needle, replacement := range yamlEdits {
		updated = strings.Replace(updated, needle, replacement, 1)
	}
	if err := os.WriteFile(cfgPath, []byte(updated), 0644); err != nil {
		t.Fatalf("write enclave.yaml: %v", err)
	}

	tofuCmd := exec.Command(bin, append([]string{"tofu", "init"}, tofuArgs...)...)
	tofuCmd.Dir = dir
	tofuCmd.Stdin = nil // /dev/null — never let the subprocess inherit a TTY
	if out, err := tofuCmd.CombinedOutput(); err != nil {
		t.Fatalf("enclave tofu init %v failed:\n%s", tofuArgs, out)
	}

	tfvarsPath := filepath.Join(dir, "tofu", "terraform.tfvars.json")
	tfvars, err := os.ReadFile(tfvarsPath)
	if err != nil {
		t.Fatalf("read tfvars: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(tfvars, &parsed); err != nil {
		t.Fatalf("parse tfvars: %v", err)
	}
	return parsed
}

// TestCLI_Tofu_Default verifies that `enclave tofu init` (no flag)
// populates the local artifact paths so tofu uploads them straight from disk.
func TestCLI_Tofu_Default(t *testing.T) {
	binDir := t.TempDir()
	bin := buildCLI(t, binDir)

	parsed := runEnclaveTofu(t, bin, nil, map[string]string{
		`nix_owner: ""`: `nix_owner: "ArkLabsHQ"`,
		`nix_repo: ""`:  `nix_repo: "introspector-enclave"`,
	})

	if eifPath, _ := parsed["eif_path"].(string); eifPath == "" {
		t.Error("default mode: expected eif_path to be populated, got empty")
	}
	if supPath, _ := parsed["supervisor_binary_path"].(string); supPath == "" {
		t.Error("default mode: expected supervisor_binary_path to be populated, got empty")
	}
	// Round-trip: the scaffolded yaml's `release_tag: "eif-latest"` line
	// flows through the loader into tfvars. Catches regressions where a
	// future template edit drops the field and the loader's default
	// silently masks it.
	if tag, _ := parsed["release_tag"].(string); tag != "eif-latest" {
		t.Errorf("default mode: release_tag=%q, want eif-latest (from scaffolded enclave.yaml)", tag)
	}
}

// TestCLI_Tofu_Remote verifies that `enclave tofu init --remote` leaves the
// local paths empty (so the tofu module's null_resource downloads from
// GitHub Release at apply time) and surfaces the user-pinned release_tag.
func TestCLI_Tofu_Remote(t *testing.T) {
	binDir := t.TempDir()
	bin := buildCLI(t, binDir)

	parsed := runEnclaveTofu(t, bin, []string{"--remote"}, map[string]string{
		`nix_owner: ""`:             `nix_owner: "ArkLabsHQ"`,
		`nix_repo: ""`:              `nix_repo: "introspector-enclave"`,
		`release_tag: "eif-latest"`: `release_tag: "eif-v0.1.0"`,
	})

	if eifPath, _ := parsed["eif_path"].(string); eifPath != "" {
		t.Errorf("--remote: expected empty eif_path, got %q", eifPath)
	}
	if supPath, _ := parsed["supervisor_binary_path"].(string); supPath != "" {
		t.Errorf("--remote: expected empty supervisor_binary_path, got %q", supPath)
	}
	if owner, _ := parsed["github_owner"].(string); owner != "ArkLabsHQ" {
		t.Errorf("--remote: github_owner=%q, want ArkLabsHQ", owner)
	}
	if repo, _ := parsed["github_repo"].(string); repo != "introspector-enclave" {
		t.Errorf("--remote: github_repo=%q, want introspector-enclave", repo)
	}
	if tag, _ := parsed["release_tag"].(string); tag != "eif-v0.1.0" {
		t.Errorf("--remote: release_tag=%q, want eif-v0.1.0 (pinned in enclave.yaml)", tag)
	}
}

// TestCLI_Tofu_Remote_RequiresOwnerRepo verifies the early error when
// --remote is used but the GitHub coords aren't set in enclave.yaml.
func TestCLI_Tofu_Remote_RequiresOwnerRepo(t *testing.T) {
	binDir := t.TempDir()
	bin := buildCLI(t, binDir)
	dir := t.TempDir()

	initCmd := exec.Command(bin, "init", "--language", "go")
	initCmd.Dir = dir
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("enclave init failed:\n%s", out)
	}

	// Leave nix_owner/nix_repo as their scaffolded defaults ("").
	tofuCmd := exec.Command(bin, "tofu", "init", "--remote")
	tofuCmd.Dir = dir
	tofuCmd.Stdin = nil // /dev/null — never let the subprocess inherit a TTY
	out, err := tofuCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected --remote without owner/repo to error, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "nix_owner") || !strings.Contains(string(out), "nix_repo") {
		t.Errorf("error message should mention nix_owner/nix_repo, got: %s", out)
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
	// build output — `enclave tofu init` writes it now (verified separately in
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
