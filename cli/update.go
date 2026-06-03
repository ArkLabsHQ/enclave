package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

func updateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update nix_rev, nix_hash, and nix_vendor_hash after changes",
		Long: `Updates nix_rev, nix_hash (source hash), and nix_vendor_hash (dependency
hash) in enclave.yaml.

Typical workflow:
  1. Edit code and/or update dependencies
  2. git commit && git push
  3. enclave update
  4. enclave build

Use --skip-deps to skip the slow vendor/deps hash recomputation when
only code (not dependencies) has changed.

Use --commit to specify a commit SHA instead of HEAD.

Requires 'nix' in PATH for hash computation.`,
		RunE: runUpdate,
	}
	cmd.Flags().Bool("skip-deps", false, "Skip vendor/deps hash recomputation (code-only changes)")
	cmd.Flags().String("commit", "", "Git commit SHA to compute hashes for (required)")
	_ = cmd.MarkFlagRequired("commit")
	return cmd
}

func runUpdate(cmd *cobra.Command, args []string) error {
	root, err := findRepoRoot()
	if err != nil {
		return err
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	skipDeps, _ := cmd.Flags().GetBool("skip-deps")

	language := cfg.App.Language
	if language == "" {
		language = "go"
	}

	subPackages := cfg.App.NixSubPackages
	if len(subPackages) == 0 {
		subPackages = []string{"."}
	}

	// 1. Resolve commit SHA (from --commit flag or HEAD).
	rev, err := resolveCommit(cmd, root)
	if err != nil {
		return err
	}
	commitFlag, _ := cmd.Flags().GetString("commit")
	if commitFlag != "" {
		fmt.Printf("[update] Using commit: %s\n", rev)
	} else {
		fmt.Printf("[update] HEAD commit: %s\n", rev)
	}

	// 2. Compute nix source hash and (optionally) vendor hash.
	if _, err := exec.LookPath("nix"); err != nil {
		return fmt.Errorf("nix is required but not found in PATH; install from https://nixos.org")
	}

	var nixHash, vendorHash string
	fmt.Println("[update] Computing nix source hash (local)...")
	nixHash, err = computeNixHash(root, rev)
	if err != nil {
		return err
	}
	fmt.Printf("[update] nix_hash: %s\n", nixHash)

	// Write nix_rev + nix_hash to enclave.yaml FIRST so the flake's
	// vendor-hash-check fetches the new source (not the old commit).
	// Without this, computeVendorHash would vendor the OLD Cargo.lock
	// and return a stale hash. See setup.go for the mirroring pattern.
	cfgPath := filepath.Join(root, configFile)
	{
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", configFile, err)
		}
		content := string(data)
		content = replaceYAMLValue(content, "nix_rev", rev)
		content = replaceYAMLValue(content, "nix_hash", nixHash)
		if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("write %s: %w", configFile, err)
		}
	}

	if !skipDeps {
		if cfg.App.Vendor {
			fmt.Println("[update] vendor: true — skipping vendor hash (using committed vendor/)")
		} else if language == "dotnet" {
			fmt.Println("[update] Generating NuGet deps.json...")
			if dErr := generateDotnetDeps(root); dErr != nil {
				fmt.Printf("[update] Warning: could not generate deps.json: %v\n", dErr)
			} else {
				vendorHash = "deps.json"
			}
		} else {
			fmt.Println("[update] Computing deps hash (local trial nix build)...")
			vendorHash, err = computeVendorHash(root, subPackages, language)
			if err != nil {
				fmt.Printf("[update] Warning: could not compute vendor hash: %v\n", err)
				fmt.Println("[update] Will update other fields; you may need to fill nix_vendor_hash manually.")
			}
		}
	} else {
		fmt.Println("[update] Skipping deps hash (--skip-deps)")
	}
	if vendorHash != "" && vendorHash != "deps.json" {
		fmt.Printf("[update] nix_vendor_hash: %s\n", vendorHash)
	}

	// Write nix_vendor_hash if it was computed.
	if vendorHash != "" && language != "dotnet" {
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", configFile, err)
		}
		content := string(data)
		content = replaceYAMLValue(content, "nix_vendor_hash", vendorHash)
		if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("write %s: %w", configFile, err)
		}
	}

	fmt.Println()
	fmt.Printf("[update] Updated %s\n", configFile)
	fmt.Printf("  nix_rev:  %s\n", rev)
	fmt.Printf("  nix_hash: %s\n", nixHash)
	if vendorHash != "" && vendorHash != "deps.json" {
		fmt.Printf("  nix_vendor_hash: %s\n", vendorHash)
	}
	fmt.Println()
	fmt.Println("Next: enclave build")
	return nil
}

