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
	return &cobra.Command{
		Use:   "update",
		Short: "Update nix_rev and nix_hash after code changes",
		Long: `Updates nix_rev (to current HEAD) and nix_hash (source hash) in enclave.yaml.

This is the fast path for code-only changes — it skips the slow vendor/deps
hash recomputation. Use 'enclave setup' instead when dependencies change.

Typical workflow:
  1. Edit code
  2. git commit && git push
  3. enclave update
  4. enclave build

Requires 'nix' in PATH, or falls back to Docker for hash computation.`,
		RunE: runUpdate,
	}
}

func runUpdate(cmd *cobra.Command, args []string) error {
	root, err := findRepoRoot()
	if err != nil {
		return err
	}

	// 1. Get HEAD commit SHA.
	rev, err := gitRevParseHEAD(root)
	if err != nil {
		return err
	}
	fmt.Printf("[update] HEAD commit: %s\n", rev)

	// 2. Compute nix source hash.
	var nixHash string
	if _, err := exec.LookPath("nix"); err == nil {
		// Local nix available — fast path.
		fmt.Println("[update] Computing nix source hash (local)...")
		nixHash, err = computeNixHash(root, rev)
		if err != nil {
			return err
		}
	} else {
		// Fall back to Docker.
		fmt.Println("[update] nix not found locally, using Docker...")
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		nixImage := cfg.NixImage
		if nixImage == "" {
			nixImage = DefaultNixImage
		}
		nixHash, err = computeNixHashDocker(root, rev, nixImage)
		if err != nil {
			return err
		}
	}
	fmt.Printf("[update] nix_hash: %s\n", nixHash)

	// 3. Update nix_rev and nix_hash in enclave.yaml.
	cfgPath := filepath.Join(root, configFile)
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

	fmt.Println()
	fmt.Printf("[update] Updated %s\n", configFile)
	fmt.Printf("  nix_rev:  %s\n", rev)
	fmt.Printf("  nix_hash: %s\n", nixHash)
	fmt.Println()
	fmt.Println("Next: enclave build")
	return nil
}

// computeNixHashDocker computes the nix source hash inside a Docker container.
func computeNixHashDocker(root, rev, nixImage string) (string, error) {
	resultFile := ".enclave-update-result"

	script := fmt.Sprintf(`set -e
git config --global --add safe.directory /src
TMPDIR=$(mktemp -d)
git archive --format=tar.gz --prefix=source/ %s | tar xz -C "$TMPDIR"
SOURCE_HASH=$(nix hash path "$TMPDIR/source")
rm -rf "$TMPDIR"
echo "$SOURCE_HASH" > /src/%s
`, rev, resultFile)

	if err := runContainer(context.Background(), nixImage, script, root, "/src", nil); err != nil {
		return "", fmt.Errorf("docker hash computation failed: %w", err)
	}

	resultPath := filepath.Join(root, resultFile)
	defer os.Remove(resultPath)

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
