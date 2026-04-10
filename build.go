package introspector_enclave

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const DefaultNixImage = "nixos/nix:2.24.9"

// PCRValues holds the PCR measurements from a built EIF.
type PCRValues struct {
	PCR0 string `json:"PCR0"`
	PCR1 string `json:"PCR1"`
	PCR2 string `json:"PCR2"`
}

// buildConfigJSON is the structure written to build-config.json for Nix to read.
type buildConfigJSON struct {
	Name    string                  `json:"name"`
	Version string                  `json:"version"`
	Region  string                  `json:"region"`
	Prefix  string                  `json:"prefix"`
	App               buildConfigAppJSON      `json:"app"`
	Secrets           []buildConfigSecretJSON `json:"secrets"`
	SDK               buildConfigSDKJSON      `json:"sdk"`
	MigrationCooldown string                  `json:"migration_cooldown"`
	PreviousPCR0      string                  `json:"previous_pcr0"`
}

type buildConfigAppJSON struct {
	Language       string            `json:"language"`
	NixOwner       string            `json:"nix_owner"`
	NixRepo        string            `json:"nix_repo"`
	NixRev         string            `json:"nix_rev"`
	NixHash        string            `json:"nix_hash"`
	NixVendorHash  string            `json:"nix_vendor_hash"`
	NixSubPackages []string          `json:"nix_sub_packages"`
	NixProjectFile string            `json:"nix_project_file"`
	NixSubdir      string            `json:"nix_subdir"`
	BinaryName     string            `json:"binary_name"`
	Env            map[string]string `json:"env"`
}

type buildConfigSecretJSON struct {
	Name   string `json:"name"`
	EnvVar string `json:"env_var"`
}

type buildConfigSDKJSON struct {
	Rev        string `json:"rev"`
	Hash       string `json:"hash"`
	VendorHash string `json:"vendor_hash"`
}

func buildCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "build",
		Short: "Build the enclave image (EIF)",
		Long:  "Builds a reproducible Enclave Image File using Nix.",
		RunE:  runBuild,
	}
}

func runBuild(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := cfg.validateSDK(); err != nil {
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

	// Build the host-side management server binary.
	if err := buildMgmtBinary(cfg, root); err != nil {
		return fmt.Errorf("build management server: %w", err)
	}

	// Build the host-side gvproxy binary for outbound networking.
	if err := buildGvproxyBinary(root); err != nil {
		return fmt.Errorf("build gvproxy: %w", err)
	}

	// Generate terraform.tfvars.json so tofu apply can be run directly.
	if err := writeTofuVars(cfg, root); err != nil {
		return fmt.Errorf("generate tfvars: %w", err)
	}

	fmt.Println()
	fmt.Println("[build] Done:")
	fmt.Printf("  PCR0:    %s\n", pcrs.PCR0)
	fmt.Printf("  PCR1:    %s\n", pcrs.PCR1)
	fmt.Printf("  PCR2:    %s\n", pcrs.PCR2)
	fmt.Printf("  EIF:     enclave/artifacts/image.eif\n")
	fmt.Printf("  Mgmt:    enclave/artifacts/enclave-mgmt\n")
	fmt.Printf("  Gvproxy: enclave/artifacts/gvproxy\n")
	fmt.Printf("  Tfvars:  enclave/tofu/terraform.tfvars.json\n")
	fmt.Println()
	fmt.Println("Next:")
	fmt.Println("  cd enclave/tofu")
	fmt.Println("  tofu init")
	fmt.Println("  tofu apply")
	return nil
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

	// Add APP_BINARY_NAME so start.sh and the supervisor can find the app.
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
			Language:       cfg.App.Language,
			NixOwner:       cfg.App.NixOwner,
			NixRepo:        cfg.App.NixRepo,
			NixRev:         cfg.App.NixRev,
			NixHash:        cfg.App.NixHash,
			NixVendorHash:  cfg.App.NixVendorHash,
			NixSubPackages: cfg.App.NixSubPackages,
			NixProjectFile: cfg.App.NixProjectFile,
			NixSubdir:      cfg.App.NixSubdir,
			BinaryName:     cfg.App.BinaryName,
			Env:            resolvedEnv,
		},
		Secrets: secrets,
		SDK: buildConfigSDKJSON{
			Rev:        cfg.SDK.Rev,
			Hash:       cfg.SDK.Hash,
			VendorHash: cfg.SDK.VendorHash,
		},
		MigrationCooldown: cfg.MigrationCooldown,
		PreviousPCR0:      cfg.PreviousPCR0,
	}

	data, err := json.MarshalIndent(bc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal build-config.json: %w", err)
	}

	outPath := filepath.Join(root, "enclave", "build-config.json")
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
	// 1. Clean and create artifacts directory.
	artifactsDir := filepath.Join(root, "enclave", "artifacts")
	if err := os.RemoveAll(artifactsDir); err != nil {
		return nil, fmt.Errorf("clean artifacts: %w", err)
	}
	if err := os.MkdirAll(artifactsDir, 0755); err != nil {
		return nil, fmt.Errorf("create artifacts dir: %w", err)
	}

	fmt.Printf("[build] Building EIF locally with nix (version=%s, region=%s, prefix=%s)\n",
		cfg.Version, cfg.Region, cfg.Prefix)

	// 2. Ensure Nix-visible files are tracked by git (flakes only see tracked files).
	ensureGitTracked(root, "flake.nix", "enclave/build-config.json", "enclave/start.sh", "enclave/enclave.yaml")

	configPath := filepath.Join(root, "enclave", "build-config.json")
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("resolve build-config.json path: %w", err)
	}

	// 3. Run nix build locally.
	nixCmd := exec.Command("nix", "build",
		"--impure",
		"--extra-experimental-features", "nix-command flakes",
		"--option", "download-attempts", "3",
		"--out-link", "flake_result",
		".#eif",
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

	// 3. Copy artifacts from flake_result/ to enclave/artifacts/.
	resultLink := filepath.Join(root, "flake_result")
	for _, name := range []string{"image.eif", "pcr.json"} {
		src := filepath.Join(resultLink, name)
		dst := filepath.Join(artifactsDir, name)
		data, err := os.ReadFile(src)
		if err != nil {
			return nil, fmt.Errorf("read flake_result/%s: %w", name, err)
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

// buildMgmtBinary cross-compiles the host-side management server from the SDK
// for Linux amd64 and places the binary in enclave/artifacts/.
func buildMgmtBinary(cfg *Config, root string) error {
	outDir := filepath.Join(root, "enclave", "artifacts")
	fmt.Println("[build] Building management server binary...")

	// Install the mgmt binary from the SDK at the configured version.
	// GOBIN controls where the binary is placed.
	modulePath := "github.com/ArkLabsHQ/introspector-enclave/mgmt@" + cfg.SDK.Rev
	cmd := exec.Command("go", "install", "-trimpath", modulePath)
	cmd.Env = append(os.Environ(),
		"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0",
		"GOBIN="+outDir,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go install mgmt: %w", err)
	}

	// go install names the binary after the module directory ("mgmt").
	// Rename to "enclave-mgmt" for clarity on the host.
	src := filepath.Join(outDir, "mgmt")
	dst := filepath.Join(outDir, "enclave-mgmt")
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("rename mgmt binary: %w", err)
	}

	return nil
}

// buildGvproxyBinary cross-compiles the gvproxy binary for Linux amd64
// and places it in enclave/artifacts/. This replaces the Docker-based
// gvproxy container — the binary runs directly on the EC2 host.
func buildGvproxyBinary(root string) error {
	outDir := filepath.Join(root, "enclave", "artifacts")
	fmt.Println("[build] Building gvproxy binary...")

	modulePath := "github.com/containers/gvisor-tap-vsock/cmd/gvproxy@v0.7.4"
	cmd := exec.Command("go", "install", "-trimpath", modulePath)
	cmd.Env = append(os.Environ(),
		"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0",
		"GOBIN="+outDir,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go install gvproxy: %w", err)
	}

	return nil
}
