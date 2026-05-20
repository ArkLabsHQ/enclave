package cli

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

func upgradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upgrade",
		Short: "Sync the pinned runtime version to this CLI",
		Long: `Rewrites the runtime: block in enclave.yaml (rev, hash, vendor_hash) to
the runtime coordinates this CLI was built with.

The runtime is the enclave supervisor — it handles attestation, secrets,
PCR extension, and signing. The CLI and runtime are released together, so
after upgrading the CLI itself (e.g. 'go install ...@latest') run
'enclave upgrade' in your project to move enclave.yaml onto the matching
runtime, then 'enclave build'.`,
		RunE: runUpgrade,
	}
}

func runUpgrade(cmd *cobra.Command, args []string) error {
	// 1. Resolve enclave.yaml the same way loadConfig does.
	cfgPath, err := resolveUpgradeConfigPath()
	if err != nil {
		return err
	}

	// 2. Load the current config.
	cfg, err := loadConfigAt(cfgPath)
	if err != nil {
		return err
	}

	// 3. Target = the runtime coordinates baked into this CLI binary
	//    (set via ldflags or the embedded runtime-hashes.json — see version.go).
	if runtimeRev == "" || runtimeHash == "" || runtimeVendorHash == "" {
		return fmt.Errorf("this CLI build carries no runtime coordinates; cannot upgrade")
	}

	// 4. Idempotency: already on the CLI's runtime.
	if cfg.Runtime.Rev == runtimeRev &&
		cfg.Runtime.Hash == runtimeHash &&
		cfg.Runtime.VendorHash == runtimeVendorHash {
		fmt.Printf("[upgrade] Already on runtime %s — nothing to do.\n", runtimeRev)
		return nil
	}

	// 5. Replace the three values within the runtime: block only.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", cfgPath, err)
	}
	content := string(data)
	for _, kv := range []struct{ key, val string }{
		{"rev", runtimeRev},
		{"hash", runtimeHash},
		{"vendor_hash", runtimeVendorHash},
	} {
		content, err = replaceRuntimeBlockValue(content, kv.key, kv.val)
		if err != nil {
			return err
		}
	}
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", cfgPath, err)
	}

	// 6. Report current -> target.
	fmt.Printf("[upgrade] CLI runtime: %s\n", runtimeRev)
	fmt.Println()
	fmt.Printf("[upgrade] Updated runtime in %s\n", cfgPath)
	fmt.Printf("  rev:         %s -> %s\n", orUnset(cfg.Runtime.Rev), runtimeRev)
	fmt.Printf("  hash:        %s -> %s\n", orUnset(cfg.Runtime.Hash), runtimeHash)
	fmt.Printf("  vendor_hash: %s -> %s\n", orUnset(cfg.Runtime.VendorHash), runtimeVendorHash)
	fmt.Println()
	fmt.Println("Next: enclave build")
	return nil
}

// resolveUpgradeConfigPath returns the enclave.yaml path using the same
// resolution as loadConfigAt: the ENCLAVE_CONFIG override, else the config
// found by walking up from cwd (canonical enclave/enclave.yaml or bare layout).
func resolveUpgradeConfigPath() (string, error) {
	if p := os.Getenv("ENCLAVE_CONFIG"); p != "" {
		return p, nil
	}
	root, err := findRepoRoot()
	if err != nil {
		return "", err
	}
	return resolveConfigPath(root), nil
}

// replaceRuntimeBlockValue replaces the quoted value of key (one of
// rev/hash/vendor_hash) inside the top-level runtime: mapping of content,
// preserving indentation and any inline comment. Replacement is scoped to the
// runtime: block so it never collides with similarly-named keys elsewhere —
// notably nix_rev / nix_hash / nix_vendor_hash under app:. It returns an error
// if there is no runtime: block or the key is absent from it.
func replaceRuntimeBlockValue(content, key, newValue string) (string, error) {
	lines := strings.Split(content, "\n")

	// Locate the top-level (indent 0) runtime: key.
	runtimeIdx := -1
	runtimeIndent := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if lineIndent(line) == 0 && yamlKeyOf(trimmed) == "runtime" {
			runtimeIdx = i
			break
		}
	}
	if runtimeIdx == -1 {
		return "", fmt.Errorf("no 'runtime:' block found in enclave.yaml; run 'enclave init' to regenerate it")
	}

	// Scan the block body: lines indented deeper than runtime:, stopping at
	// the first non-blank line indented back to runtime:'s level or shallower.
	// Groups: 1=indent+key+colon, 2=post-colon spacing, 3=value, 4=trailing+comment.
	valueRe := regexp.MustCompile(`^(\s*` + regexp.QuoteMeta(key) + `:)(\s*)("[^"]*"|\S*)(\s*(#.*)?)$`)
	for i := runtimeIdx + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if lineIndent(line) <= runtimeIndent {
			break // left the runtime: block
		}
		if yamlKeyOf(trimmed) != key {
			continue
		}
		m := valueRe.FindStringSubmatch(line)
		if m == nil {
			return "", fmt.Errorf("runtime.%s line has unexpected format: %q", key, line)
		}
		sep := m[2]
		if sep == "" {
			sep = " " // a bare "key:" has no spacing — keep the result valid YAML
		}
		lines[i] = m[1] + sep + `"` + newValue + `"` + m[4]
		return strings.Join(lines, "\n"), nil
	}
	return "", fmt.Errorf("key 'runtime.%s' not found in enclave.yaml", key)
}

// lineIndent returns the number of leading space/tab characters of line.
func lineIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

// yamlKeyOf returns the mapping key of a trimmed YAML line (the text before
// the first ':'), or "" if the line has no ':'.
func yamlKeyOf(trimmed string) string {
	idx := strings.IndexByte(trimmed, ':')
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(trimmed[:idx])
}
