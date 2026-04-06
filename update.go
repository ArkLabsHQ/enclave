package introspector_enclave

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

Requires 'nix' in PATH, or falls back to Docker for hash computation.`,
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
	var nixHash, vendorHash string
	if _, err := exec.LookPath("nix"); err == nil {
		fmt.Println("[update] Computing nix source hash (local)...")
		nixHash, err = computeNixHash(root, rev)
		if err != nil {
			return err
		}

		if !skipDeps {
			if language == "dotnet" {
				fmt.Println("[update] Generating NuGet deps.json (local)...")
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
	} else {
		fmt.Println("[update] nix not found locally, using Docker...")
		nixImage := cfg.NixImage
		if nixImage == "" {
			nixImage = DefaultNixImage
		}

		if skipDeps {
			fmt.Println("[update] Skipping deps hash (--skip-deps)")
			nixHash, err = computeNixHashDocker(root, rev, nixImage)
			if err != nil {
				return err
			}
		} else {
			if language == "dotnet" {
				nixHash, err = computeHashesDotnetDocker(root, rev, nixImage)
				if err != nil {
					return err
				}
				vendorHash = "deps.json"
			} else {
				nixHash, vendorHash, err = computeHashesDocker(root, rev, subPackages, nixImage, language)
				if err != nil {
					return err
				}
			}
		}
	}
	fmt.Printf("[update] nix_hash: %s\n", nixHash)
	if vendorHash != "" && vendorHash != "deps.json" {
		fmt.Printf("[update] nix_vendor_hash: %s\n", vendorHash)
	}

	// 3. Update enclave.yaml.
	cfgPath := filepath.Join(root, configFile)
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", configFile, err)
	}

	content := string(data)
	content = replaceYAMLValue(content, "nix_rev", rev)
	content = replaceYAMLValue(content, "nix_hash", nixHash)
	if vendorHash != "" && language != "dotnet" {
		content = replaceYAMLValue(content, "nix_vendor_hash", vendorHash)
	}

	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", configFile, err)
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

// computeNixHashDocker computes the nix source hash inside a Docker container.
func computeNixHashDocker(root, rev, nixImage string) (string, error) {
	resultFile := ".enclave-update-result"

	// Load config to get GitHub owner/repo for the tarball URL.
	cfg, cfgErr := loadConfig()
	if cfgErr != nil {
		return "", fmt.Errorf("load config: %w", cfgErr)
	}
	tarballURL := fmt.Sprintf("https://github.com/%s/%s/archive/%s.tar.gz", cfg.App.NixOwner, cfg.App.NixRepo, rev)

	script := fmt.Sprintf(`set -e
git config --global --add safe.directory /src
SOURCE_HASH_BASE32=$(nix-prefetch-url --unpack --type sha256 "%s" 2>/dev/null | tail -1)
SOURCE_HASH=$(nix --extra-experimental-features nix-command hash convert --hash-algo sha256 --to sri "$SOURCE_HASH_BASE32")
echo "$SOURCE_HASH" > /src/%s
`, tarballURL, resultFile)

	if err := runContainer(context.Background(), nixImage, script, root, "/src", nil); err != nil {
		return "", fmt.Errorf("docker hash computation failed: %w", err)
	}

	resultPath := filepath.Join(root, resultFile)
	defer func() { _ = os.Remove(resultPath) }()

	data, err := os.ReadFile(resultPath)
	if err != nil {
		return "", fmt.Errorf("read hash result: %w", err)
	}

	hash := strings.TrimSpace(string(data))
	if hash == "" {
		return "", fmt.Errorf("empty hash from Docker computation")
	}

	return hash, nil
}
