package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

func vendorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vendor",
		Short: "Vendor the upstream app's dependencies into ./vendor for offline builds",
		Long: `Resolves the language from enclave.yaml, then shells out to
'cargo vendor' (Rust) or 'go mod vendor' (Go) in the upstream app's
checked-out source tree. After running, commit vendor/ and push, then
run 'enclave setup' to refresh nix_rev / nix_hash, then flip
'app.vendor: true' in enclave.yaml.

The framework does NOT vendor for you automatically — the upstream
repo lives outside the framework's working tree. Use --path to point at
your local checkout of the upstream app.`,
		RunE: runVendor,
	}
	cmd.Flags().String("path", ".", "path to the upstream app's checked-out source")
	return cmd
}

func runVendor(cmd *cobra.Command, args []string) error {
	appPath, _ := cmd.Flags().GetString("path")

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	name, vendorArgs, err := vendorCommandFor(cfg.App.Language)
	if err != nil {
		return err
	}

	cwd, err := resolveVendorCwd(appPath, cfg.App.NixSubdir)
	if err != nil {
		return err
	}

	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%q not found on PATH — install the %s toolchain before running `enclave vendor`", name, cfg.App.Language)
	}

	fmt.Printf("[vendor] Running `%s %s` in %s...\n", name, joinArgs(vendorArgs), cwd)
	c := exec.Command(name, vendorArgs...)
	c.Dir = cwd
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, joinArgs(vendorArgs), err)
	}

	fmt.Println()
	fmt.Println("[vendor] Done. Next steps (order matters):")
	fmt.Println("  1. git add vendor/ && git commit -m 'vendor deps' && git push")
	fmt.Println("  2. Edit enclave/enclave.yaml: set `app.vendor: true` and clear `app.nix_vendor_hash`")
	fmt.Println("  3. From the framework project root, run `enclave setup` to refresh nix_rev/nix_hash")
	fmt.Println("     (setup sees vendor: true and skips the hash-discovery step — required if you're")
	fmt.Println("      recovering from a yanked upstream dep, since hash discovery would re-fetch it)")
	fmt.Println("  4. `enclave build` — Nix uses the committed vendor/; no upstream fetch for app deps")
	return nil
}

// vendorCommandFor returns the toolchain command + args that vendor deps for
// the given language. Returns an error for languages without a clean
// vendor-mode equivalent. Pure function so tests can exercise routing
// without spawning processes.
func vendorCommandFor(language string) (cmd string, args []string, err error) {
	switch language {
	case "rust":
		return "cargo", []string{"vendor"}, nil
	case "go":
		return "go", []string{"mod", "vendor"}, nil
	case "nodejs":
		return "", nil, fmt.Errorf("vendor mode is not supported for language=nodejs (buildNpmPackage has no clean vendor-mode equivalent — npmDepsHash is mandatory)")
	case "dotnet":
		return "", nil, fmt.Errorf("vendor mode is not needed for language=dotnet — nugetDeps already manifests every package with content-addressed fetches")
	default:
		return "", nil, fmt.Errorf("unknown language %q (expected go|rust|nodejs|dotnet)", language)
	}
}

// resolveVendorCwd returns the directory where the vendor command should run.
// For Rust with nix_subdir set, cargoVendorDir is relative to cargoRoot, so
// the vendor command must run in that subdir.
func resolveVendorCwd(appPath, nixSubdir string) (string, error) {
	abs, err := filepath.Abs(appPath)
	if err != nil {
		return "", fmt.Errorf("resolve --path: %w", err)
	}
	if nixSubdir != "" {
		return filepath.Join(abs, nixSubdir), nil
	}
	return abs, nil
}

func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
