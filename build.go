package introspector_enclave

import (
	"context"
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

// EIFBuildConfig holds the parameters needed to build an EIF.
type EIFBuildConfig struct {
	NixImage string
	Version  string
	Region   string
	Prefix   string
}

// buildConfigJSON is the structure written to build-config.json for Nix to read.
type buildConfigJSON struct {
	Name    string                 `json:"name"`
	Version string                 `json:"version"`
	Region  string                 `json:"region"`
	Prefix  string                 `json:"prefix"`
	App     buildConfigAppJSON     `json:"app"`
	Secrets []buildConfigSecretJSON `json:"secrets"`
	SDK     buildConfigSDKJSON     `json:"sdk"`
}

type buildConfigAppJSON struct {
	Language       string            `json:"language"`
	NixOwner       string            `json:"nix_owner"`
	NixRepo        string            `json:"nix_repo"`
	NixRev         string            `json:"nix_rev"`
	NixHash        string            `json:"nix_hash"`
	NixVendorHash  string            `json:"nix_vendor_hash"`
	NixSubPackages []string          `json:"nix_sub_packages"`
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
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build the enclave image (EIF)",
		Long:  "Builds a reproducible Enclave Image File using Docker + Nix.\nUse --local to build with a local Nix installation instead of Docker.",
		RunE:  runBuild,
	}
	cmd.Flags().Bool("local", false, "Build using local Nix instead of Docker")
	return cmd
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

	// Generate build-config.json for Nix to read.
	if err := generateBuildConfig(cfg, root); err != nil {
		return err
	}

	local, _ := cmd.Flags().GetBool("local")

	var pcrs *PCRValues
	if local {
		pcrs, err = BuildEIFLocal(cfg, root)
	} else {
		pcrs, err = BuildEIF(EIFBuildConfig{
			NixImage: cfg.NixImage,
			Version:  cfg.Version,
			Region:   cfg.Region,
			Prefix:   cfg.Prefix,
		}, root)
	}
	if err != nil {
		return err
	}

	// Build the host-side management server binary.
	if err := buildMgmtBinary(cfg, root); err != nil {
		return fmt.Errorf("build management server: %w", err)
	}

	fmt.Println()
	fmt.Println("[build] Done:")
	fmt.Printf("  PCR0: %s\n", pcrs.PCR0)
	fmt.Printf("  PCR1: %s\n", pcrs.PCR1)
	fmt.Printf("  PCR2: %s\n", pcrs.PCR2)
	fmt.Printf("  EIF:  enclave/artifacts/image.eif\n")
	fmt.Printf("  Mgmt: enclave/artifacts/enclave-mgmt\n")
	fmt.Println()
	fmt.Println("Next: enclave deploy")
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
		secrets = append(secrets, buildConfigSecretJSON{
			Name:   s.Name,
			EnvVar: s.EnvVar,
		})
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
			BinaryName:     cfg.App.BinaryName,
			Env:            resolvedEnv,
		},
		Secrets: secrets,
		SDK: buildConfigSDKJSON{
			Rev:        cfg.SDK.Rev,
			Hash:       cfg.SDK.Hash,
			VendorHash: cfg.SDK.VendorHash,
		},
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

// BuildEIF builds the enclave image (EIF) reproducibly using Docker + Nix.
func BuildEIF(cfg EIFBuildConfig, root string) (*PCRValues, error) {
	nixImage := cfg.NixImage
	if nixImage == "" {
		nixImage = DefaultNixImage
	}

	// 1. Clean and create artifacts directory.
	artifactsDir := filepath.Join(root, "enclave", "artifacts")
	if err := os.RemoveAll(artifactsDir); err != nil {
		return nil, fmt.Errorf("clean artifacts: %w", err)
	}
	if err := os.MkdirAll(artifactsDir, 0755); err != nil {
		return nil, fmt.Errorf("create artifacts dir: %w", err)
	}

	fmt.Printf("[build] Building EIF with %s (version=%s, region=%s, prefix=%s)\n",
		nixImage, cfg.Version, cfg.Region, cfg.Prefix)

	// 2. Ensure Nix-visible files are tracked by git (flakes only see tracked files).
	ensureGitTracked(root, "flake.nix", "enclave/build-config.json", "enclave/start.sh", "enclave/enclave.yaml")

	// 3. Run Nix build inside Docker container.
	nixCmd := "git config --global --add safe.directory /src && " +
		"nix build --impure --extra-experimental-features 'nix-command flakes' --out-link flake_result .#eif && " +
		"cp flake_result/image.eif /src/enclave/artifacts/image.eif && " +
		"cp flake_result/pcr.json /src/enclave/artifacts/pcr.json"

	env := []string{
		"VERSION=" + cfg.Version,
		"AWS_REGION=" + cfg.Region,
		"CDK_PREFIX=" + cfg.Prefix,
	}

	if err := runContainer(context.Background(), nixImage, nixCmd, root, "/src", env); err != nil {
		return nil, fmt.Errorf("docker nix build failed: %w", err)
	}

	// 3. Verify artifacts exist.
	pcrPath := filepath.Join(artifactsDir, "pcr.json")
	if _, err := os.Stat(pcrPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("enclave/artifacts/pcr.json not found after build")
	}
	eifPath := filepath.Join(artifactsDir, "image.eif")
	if _, err := os.Stat(eifPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("enclave/artifacts/image.eif not found after build")
	}

	// 4. Parse PCR values.
	pcrData, err := os.ReadFile(pcrPath)
	if err != nil {
		return nil, fmt.Errorf("read pcr.json: %w", err)
	}

	var pcrs PCRValues
	if err := json.Unmarshal(pcrData, &pcrs); err != nil {
		return nil, fmt.Errorf("parse pcr.json: %w", err)
	}

	return &pcrs, nil
}

// BuildEIFLocal builds the EIF using a local Nix installation (no Docker).
func BuildEIFLocal(cfg *Config, root string) (*PCRValues, error) {
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

	// Install the mgmt binary from the SDK module at the configured rev.
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
