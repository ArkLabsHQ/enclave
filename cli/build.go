package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// PCRValues holds the PCR measurements from a built EIF.
type PCRValues struct {
	PCR0 string `json:"PCR0"`
	PCR1 string `json:"PCR1"`
	PCR2 string `json:"PCR2"`
}

// buildConfigJSON is the structure written to build-config.json for Nix to read.
type buildConfigJSON struct {
	Name              string                  `json:"name"`
	Version           string                  `json:"version"`
	Region            string                  `json:"region"`
	Prefix            string                  `json:"prefix"`
	App               buildConfigAppJSON      `json:"app"`
	Secrets           []buildConfigSecretJSON `json:"secrets"`
	Runtime           buildConfigRuntimeJSON  `json:"runtime"`
	MigrationCooldown string                  `json:"migration_cooldown"`
	PreviousPCR0      string                  `json:"previous_pcr0"`
	IsKMSKeyLocked    bool                    `json:"is_kms_key_locked"`
}

type buildConfigAppJSON struct {
	Language             string            `json:"language"`
	NixOwner             string            `json:"nix_owner"`
	NixRepo              string            `json:"nix_repo"`
	NixRev               string            `json:"nix_rev"`
	NixHash              string            `json:"nix_hash"`
	NixVendorHash        string            `json:"nix_vendor_hash"`
	NixSubPackages       []string          `json:"nix_sub_packages"`
	NixProjectFile       string            `json:"nix_project_file"`
	NixSubdir            string            `json:"nix_subdir"`
	NixBuildInputs       []string          `json:"nix_build_inputs"`
	NixNativeBuildInputs []string          `json:"nix_native_build_inputs"`
	BinaryName           string            `json:"binary_name"`
	Env                  map[string]string `json:"env"`
}

type buildConfigSecretJSON struct {
	Name   string `json:"name"`
	EnvVar string `json:"env_var"`
}

type buildConfigRuntimeJSON struct {
	Rev        string `json:"rev"`
	Hash       string `json:"hash"`
	VendorHash string `json:"vendor_hash"`
}

func buildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build the enclave image (EIF)",
		Long:  "Builds a reproducible Enclave Image File using Nix.",
		RunE:  runBuild,
	}
	cmd.Flags().StringP("config", "c", "", "path to enclave.yaml (defaults to enclave/enclave.yaml or ./enclave.yaml). Use to build a test variant: `enclave build --config enclave/enclave_test.yaml`.")
	return cmd
}

func runBuild(cmd *cobra.Command, args []string) error {
	configPath, _ := cmd.Flags().GetString("config")
	cfg, err := loadConfigAt(configPath)
	if err != nil {
		return err
	}
	return runBuildWithConfig(cfg)
}

func runBuildWithConfig(cfg *Config) error {
	if err := cfg.validateRuntime(); err != nil {
		return err
	}

	root, err := findRepoRoot()
	if err != nil {
		return err
	}

	// Warn if vendor/ is git-tracked (causes stale dependency issues in Nix).
	vendorPath := filepath.Join(root, "vendor")
	if _, statErr := os.Stat(vendorPath); statErr == nil {
		gitLsCmd := exec.Command("git", "ls-files", "vendor/")
		gitLsCmd.Dir = root
		if lsOut, lsErr := gitLsCmd.Output(); lsErr == nil && len(strings.TrimSpace(string(lsOut))) > 0 {
			fmt.Println("[build] Warning: vendor/ directory is tracked by git.")
			fmt.Println("        This may cause stale dependency issues in Nix builds.")
			fmt.Println("        Consider adding 'vendor/' to .gitignore and running:")
			fmt.Println("          git rm -r --cached vendor/")
		}
	}

	// Generate build-config.json for Nix to read.
	if err := generateBuildConfig(cfg, root); err != nil {
		return err
	}

	pcrs, err := BuildEIF(cfg, root)
	if err != nil {
		return err
	}

	// Build the host-side supervisor server binary. It embeds gvproxy and
	// the IMDS AF_VSOCK forwarder, so no separate gvproxy binary is shipped.
	if err := buildSupervisorBinary(cfg, root); err != nil {
		return fmt.Errorf("build supervisor server: %w", err)
	}

	fmt.Println()
	fmt.Println("[build] Done:")
	fmt.Printf("  PCR0:    %s\n", pcrs.PCR0)
	fmt.Printf("  PCR1:    %s\n", pcrs.PCR1)
	fmt.Printf("  PCR2:    %s\n", pcrs.PCR2)
	fmt.Printf("  EIF:     .enclave/artifacts/image.eif\n")
	fmt.Printf("  Supervisor: .enclave/artifacts/supervisor\n")
	fmt.Println()
	fmt.Println("Next:")
	fmt.Println("  enclave tofu                # refresh tofu/terraform.tfvars.json with this build's PCR0")
	fmt.Println("  cd tofu && tofu init && tofu apply")
	return nil
}

// nonNilStrings returns an empty slice when xs is nil so JSON marshalling
// emits "[]" instead of "null". Nix's builtins.fromJSON would otherwise
// decode a missing/null field to null, breaking list operations downstream.
func nonNilStrings(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

// generateBuildConfig writes build-config.json from enclave.yaml config.
// Template variables in env values ({{region}}, {{prefix}}, {{version}}) are substituted.
func generateBuildConfig(cfg *Config, root string) error {
	// Resolve template variables in env values.
	resolvedEnv := make(map[string]string)
	for k, v := range cfg.App.Env {
		v = strings.ReplaceAll(v, "{{region}}", cfg.Region)
		v = strings.ReplaceAll(v, "{{prefix}}", cfg.Prefix)
		v = strings.ReplaceAll(v, "{{version}}", cfg.Version)
		resolvedEnv[k] = v
	}

	// Add APP_BINARY_NAME so the runtime can locate the user's app under /app/.
	resolvedEnv["APP_BINARY_NAME"] = cfg.App.BinaryName

	// Convert secrets config.
	var secrets []buildConfigSecretJSON
	for _, s := range cfg.Secrets {
		secrets = append(secrets, buildConfigSecretJSON(s))
	}

	bc := buildConfigJSON{
		Name:    cfg.Name,
		Version: cfg.Version,
		Region:  cfg.Region,
		Prefix:  cfg.Prefix,
		App: buildConfigAppJSON{
			Language:             cfg.App.Language,
			NixOwner:             cfg.App.NixOwner,
			NixRepo:              cfg.App.NixRepo,
			NixRev:               cfg.App.NixRev,
			NixHash:              cfg.App.NixHash,
			NixVendorHash:        cfg.App.NixVendorHash,
			NixSubPackages:       cfg.App.NixSubPackages,
			NixProjectFile:       cfg.App.NixProjectFile,
			NixSubdir:            cfg.App.NixSubdir,
			NixBuildInputs:       nonNilStrings(cfg.App.NixBuildInputs),
			NixNativeBuildInputs: nonNilStrings(cfg.App.NixNativeBuildInputs),
			BinaryName:           cfg.App.BinaryName,
			Env:                  resolvedEnv,
		},
		Secrets: secrets,
		Runtime: buildConfigRuntimeJSON{
			Rev:        cfg.Runtime.Rev,
			Hash:       cfg.Runtime.Hash,
			VendorHash: cfg.Runtime.VendorHash,
		},
		MigrationCooldown: cfg.MigrationCooldown,
		PreviousPCR0:      cfg.PreviousPCR0,
		IsKMSKeyLocked:    cfg.IsKMSKeyLocked,
	}

	data, err := json.MarshalIndent(bc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal build-config.json: %w", err)
	}

	outDir := filepath.Join(root, ".enclave")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("create .enclave dir: %w", err)
	}
	outPath := filepath.Join(outDir, "build-config.json")
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return fmt.Errorf("write build-config.json: %w", err)
	}

	fmt.Printf("[build] Generated %s\n", outPath)
	return nil
}

// ensureGitTracked stages files with `git add --intent-to-add` so Nix flakes
// can see them. This is a no-op for already tracked files.
func ensureGitTracked(root string, paths ...string) {
	args := append([]string{"add", "--intent-to-add", "--"}, paths...)
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	_ = cmd.Run() // best-effort; ignore errors (e.g. no git repo)
}

// BuildEIF builds the enclave image (EIF) reproducibly using Nix.
func BuildEIF(cfg *Config, root string) (*PCRValues, error) {
	// Refuse to proceed if a pre-refactor flake.nix sits at root — it would
	// be picked up by any ad-hoc `nix build .#eif` invocation and confuse
	// reproducibility. Migration is one-line; we prompt rather than auto-move.
	if _, err := os.Stat(filepath.Join(root, "flake.nix")); err == nil {
		if _, err := os.Stat(filepath.Join(root, "enclave", "flake.nix")); os.IsNotExist(err) {
			return nil, fmt.Errorf("legacy flake.nix at repo root. Move it: " +
				"`mv flake.nix enclave/flake.nix && mv flake.lock enclave/flake.lock 2>/dev/null || true` then re-run")
		}
	}

	// 1. Clean and create artifacts directory under .enclave/.
	artifactsDir := filepath.Join(root, ".enclave", "artifacts")
	if err := os.RemoveAll(artifactsDir); err != nil {
		return nil, fmt.Errorf("clean artifacts: %w", err)
	}
	if err := os.MkdirAll(artifactsDir, 0755); err != nil {
		return nil, fmt.Errorf("create artifacts dir: %w", err)
	}

	fmt.Printf("[build] Building EIF locally with nix (version=%s, region=%s, prefix=%s)\n",
		cfg.Version, cfg.Region, cfg.Prefix)

	// 2. Ensure Nix-visible files are tracked by git (flakes only see tracked files).
	ensureGitTracked(root, "enclave/flake.nix", "enclave/enclave.yaml")

	configPath := filepath.Join(root, ".enclave", "build-config.json")
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("resolve build-config.json path: %w", err)
	}

	// 3. Run nix build locally against ./enclave#eif.
	nixCmd := exec.Command("nix", "build",
		"--impure",
		"--extra-experimental-features", "nix-command flakes",
		"--option", "download-attempts", "3",
		"--out-link", ".enclave/result",
		"./enclave#eif",
	)
	nixCmd.Dir = root
	nixCmd.Stdout = os.Stdout
	nixCmd.Stderr = os.Stderr
	nixCmd.Env = append(os.Environ(),
		"BUILD_CONFIG_PATH="+absConfigPath,
		"VERSION="+cfg.Version,
		"AWS_REGION="+cfg.Region,
		"CDK_PREFIX="+cfg.Prefix,
	)

	if err := nixCmd.Run(); err != nil {
		return nil, fmt.Errorf("nix build failed: %w", err)
	}

	// 3. Copy artifacts from .enclave/result/ to .enclave/artifacts/.
	resultLink := filepath.Join(root, ".enclave", "result")
	for _, name := range []string{"image.eif", "pcr.json"} {
		src := filepath.Join(resultLink, name)
		dst := filepath.Join(artifactsDir, name)
		data, err := os.ReadFile(src)
		if err != nil {
			return nil, fmt.Errorf("read .enclave/result/%s: %w", name, err)
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return nil, fmt.Errorf("write artifacts/%s: %w", name, err)
		}
	}

	// 4. Parse PCR values.
	pcrData, err := os.ReadFile(filepath.Join(artifactsDir, "pcr.json"))
	if err != nil {
		return nil, fmt.Errorf("read pcr.json: %w", err)
	}

	var pcrs PCRValues
	if err := json.Unmarshal(pcrData, &pcrs); err != nil {
		return nil, fmt.Errorf("parse pcr.json: %w", err)
	}

	return &pcrs, nil
}

// buildSupervisorBinary cross-compiles the host-side supervisor server from the SDK
// for Linux amd64 and places the binary in .enclave/artifacts/.
//
// If SUPERVISOR_LOCAL_PATH is set, the binary is built from local source (go build
// ./supervisor/cmd/supervisor inside that path) instead of fetched from the module proxy. Mirrors
// SDK_LOCAL_PATH for the enclave supervisor flake. Used by integration tests
// that need to exercise unreleased supervisor changes against an unreleased SDK.
func buildSupervisorBinary(cfg *Config, root string) error {
	outDir := filepath.Join(root, ".enclave", "artifacts")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("create artifacts dir: %w", err)
	}
	fmt.Println("[build] Building supervisor server binary...")

	if localPath := os.Getenv("SUPERVISOR_LOCAL_PATH"); localPath != "" {
		dst := filepath.Join(outDir, "supervisor")
		cmd := exec.Command("go", "build", "-trimpath", "-o", dst, "./supervisor/cmd/supervisor")
		cmd.Dir = localPath
		cmd.Env = append(os.Environ(),
			"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0",
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("go build supervisor (local path %s): %w", localPath, err)
		}
		return nil
	}

	modulePath := "github.com/ArkLabsHQ/introspector-enclave/supervisor/cmd/supervisor@" + cfg.Runtime.Rev
	cmd := exec.Command("go", "install", "-trimpath", modulePath)
	cmd.Env = append(os.Environ(),
		"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0",
		"GOBIN="+outDir,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go install supervisor: %w", err)
	}
	return nil
}

