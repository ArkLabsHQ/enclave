package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const configTemplate = `# Enclave configuration
# Edit this file then run: enclave init

name: my-app                     # App name (used in stack name, EIF name)
version: 0.0.1                   # Build version (semver, baked into binary via ldflags)
region: us-east-1                # AWS region
account: ""                      # AWS account ID (required)
prefix: dev                      # Deployment prefix (stack = {prefix}Nitro{Name})
instance_type: m6i.xlarge        # EC2 instance type
migration_cooldown: "1m"         # Cooldown before migration proceeds
is_kms_key_locked: false         # false (default): grant AWS root kms:PutKeyPolicy on the locked key — recovery from lockout works by adding a new PCR0 condition.
                                 # true:             strict mode — the locked policy is frozen; even root cannot rewrite it. Only the attested enclave can decrypt.

# Runtime coordinates for the enclave supervisor binary.
# The supervisor handles attestation, secrets, PCR extension, and signing
# middleware automatically. Your app is a plain HTTP server with zero runtime imports.
runtime:
  rev: ""                        # runtime git commit SHA (required)
  hash: ""                       # Nix source hash: nix-prefetch-url --unpack (required)
  vendor_hash: ""                # Go vendor hash (required)

app:
  language: "go"                 # App language: go, nodejs, dotnet, rust
  source: nix                    # "nix" = fetch from GitHub via Nix

  # GitHub coordinates for the app to run inside the enclave.
  # Your app is a plain HTTP server that listens on ENCLAVE_APP_PORT (default 7074).
  # Secrets are passed as environment variables. No runtime imports needed.
  nix_owner: ""                  # GitHub owner (required)
  nix_repo: ""                   # GitHub repo name (required)
  nix_rev: ""                    # Git commit SHA (required)
  nix_hash: ""                   # Nix source hash: nix-prefetch-url --unpack (required)
  nix_vendor_hash: ""            # Go vendor hash (required)
  nix_sub_packages:              # Go sub-packages to build
    - "."
  nix_subdir: ""                 # Subdirectory for monorepo (e.g. "server")
  binary_name: ""                # Output binary name (defaults to 'name')
  release_tag: "eif-latest"      # GitHub Release tag used by 'enclave tofu --remote'

  # Environment variables baked into the EIF as build-time defaults
  # (each value contributes to PCR0). Tofu can override any key here
  # at deploy time via -var 'env_values={"MY_KEY":"new-value"}' without
  # rebuilding the EIF — the runtime overlays the SSM value on top of
  # the baked default at boot.
  # Template vars: {{region}}, {{prefix}}, {{version}}
  env:
    # MY_APP_DATA_DIR: /app/data
    # MY_APP_REGION: "{{region}}"

# Secrets managed by KMS inside the enclave.
# Each secret is generated as 32 random bytes, encrypted with KMS,
# stored in SSM, and decrypted at boot via attestation.
# The decrypted value (hex-encoded) is set as the specified env var.
secrets:
  - name: signing_key
    env_var: APP_SIGNING_KEY
  # - name: api_token
  #   env_var: APP_API_TOKEN
`

func initCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Validate enclave.yaml or create a template",
		Long: `Reads and validates enclave.yaml in the current directory.
If no enclave.yaml exists, writes a commented template as a starting point.

Use --language to set the app language (go, nodejs, dotnet, rust).
The language is stored in enclave.yaml and used by all other commands.`,
		RunE: runInit,
	}
	cmd.Flags().String("language", "go", "App language: go, nodejs, dotnet, rust")
	return cmd
}

func runInit(cmd *cobra.Command, args []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(cwd, configFile)

	// If enclave/enclave.yaml doesn't exist, create the directory, write the
	// config template, and scaffold all framework files needed by Nix and tofu.
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		language, _ := cmd.Flags().GetString("language")
		switch language {
		case "go", "nodejs", "dotnet", "rust":
			// valid
		default:
			return fmt.Errorf("unsupported language: %s (supported: go, nodejs, dotnet, rust)", language)
		}

		enclaveDir := filepath.Join(cwd, "enclave")
		if err := os.MkdirAll(enclaveDir, 0755); err != nil {
			return fmt.Errorf("create enclave/ directory: %w", err)
		}

		// Select the config template based on language.
		cfg := configTemplate
		switch language {
		case "nodejs":
			cfg = strings.Replace(cfg,
				`  language: "go"                 # App language: go, nodejs, dotnet, rust`,
				`  language: "nodejs"             # App language: go, nodejs, dotnet, rust`, 1)
		case "dotnet":
			cfg = strings.Replace(cfg,
				`  language: "go"                 # App language: go, nodejs, dotnet, rust`,
				`  language: "dotnet"             # App language: go, nodejs, dotnet, rust`, 1)
		case "rust":
			cfg = strings.Replace(cfg,
				`  language: "go"                 # App language: go, nodejs, dotnet, rust`,
				`  language: "rust"               # App language: go, nodejs, dotnet, rust`, 1)
		}

		// Substitute runtime coordinates if baked in via ldflags (release builds).
		if runtimeRev != "" {
			cfg = strings.Replace(cfg,
				`  rev: ""                        # runtime git commit SHA (required)`,
				fmt.Sprintf(`  rev: "%s"`, runtimeRev), 1)
			cfg = strings.Replace(cfg,
				`  hash: ""                       # Nix source hash: nix-prefetch-url --unpack (required)`,
				fmt.Sprintf(`  hash: "%s"`, runtimeHash), 1)
			cfg = strings.Replace(cfg,
				`  vendor_hash: ""                # Go vendor hash (required)`,
				fmt.Sprintf(`  vendor_hash: "%s"`, runtimeVendorHash), 1)
		}
		if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
			return fmt.Errorf("write %s: %w", configFile, err)
		}
		fmt.Printf("Created %s (language: %s)\n", configFile, language)

		// Write build-time framework files (flake.nix + CI workflows). The
		// OpenTofu deployment scaffold lives under ./tofu/ and is emitted by
		// `enclave tofu`, not here, so users can iterate on build and
		// deployment independently.
		for _, f := range getInitFiles(language) {
			destPath := filepath.Join(cwd, f.RelPath)
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return fmt.Errorf("create directory for %s: %w", f.RelPath, err)
			}
			if err := os.WriteFile(destPath, []byte(f.Content), f.Mode); err != nil {
				return fmt.Errorf("write %s: %w", f.RelPath, err)
			}
			fmt.Printf("Created %s\n", f.RelPath)
		}

		// Ensure .enclave/ (CLI-managed build outputs) is gitignored at root.
		if err := ensureGitignoreEntry(cwd, ".enclave/"); err != nil {
			return fmt.Errorf("update root .gitignore: %w", err)
		}

		fmt.Println()
		fmt.Println("Edit enclave/enclave.yaml with your app and runtime details.")
		fmt.Println("Your app is a plain HTTP server listening on ENCLAVE_APP_PORT (default 7074).")
		fmt.Println("No runtime imports needed — the supervisor handles attestation automatically.")
		fmt.Println("Then run 'enclave setup' to compute hashes and 'enclave build' to build.")
		fmt.Println("Before deploying, run 'enclave tofu' to generate the OpenTofu module.")
		return nil
	}

	// enclave.yaml exists — load and validate.
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Validate app-specific fields for nix source.
	var errors []string
	if cfg.Name == "" {
		errors = append(errors, "'name' is required")
	}
	if cfg.App.Source == "nix" {
		if cfg.App.NixOwner == "" {
			errors = append(errors, "'app.nix_owner' is required")
		}
		if cfg.App.NixRepo == "" {
			errors = append(errors, "'app.nix_repo' is required")
		}
		if cfg.App.NixRev == "" {
			errors = append(errors, "'app.nix_rev' is required")
		}
		if cfg.App.NixHash == "" {
			errors = append(errors, "'app.nix_hash' is required")
		}
		if cfg.App.NixVendorHash == "" {
			errors = append(errors, "'app.nix_vendor_hash' is required")
		}
	}
	if cfg.Runtime.Rev == "" {
		errors = append(errors, "'runtime.rev' is required")
	}
	if cfg.Runtime.Hash == "" {
		errors = append(errors, "'runtime.hash' is required")
	}
	if cfg.Runtime.VendorHash == "" {
		errors = append(errors, "'runtime.vendor_hash' is required")
	}
	if len(errors) > 0 {
		fmt.Println("Validation errors:")
		for _, e := range errors {
			fmt.Printf("  - %s\n", e)
		}
		return fmt.Errorf("enclave.yaml has %d validation error(s)", len(errors))
	}

	// Print summary.
	fmt.Println("enclave.yaml is valid.")
	fmt.Println()
	fmt.Printf("  Name:        %s\n", cfg.Name)
	fmt.Printf("  Version:     %s\n", cfg.Version)
	fmt.Printf("  Region:      %s\n", cfg.Region)
	fmt.Printf("  Account:     %s\n", cfg.Account)
	fmt.Printf("  Prefix:      %s\n", cfg.Prefix)
	fmt.Printf("  Instance:    %s\n", cfg.InstanceType)
	fmt.Println()
	fmt.Printf("  Runtime Rev:     %.12s\n", cfg.Runtime.Rev)
	fmt.Println()
	fmt.Printf("  Language:    %s\n", cfg.App.Language)
	fmt.Printf("  App Source:  %s\n", cfg.App.Source)
	fmt.Printf("  App Repo:    %s/%s\n", cfg.App.NixOwner, cfg.App.NixRepo)
	fmt.Printf("  App Rev:     %s\n", cfg.App.NixRev)
	fmt.Printf("  Binary:      %s\n", cfg.App.BinaryName)
	if len(cfg.App.Env) > 0 {
		fmt.Printf("  Env vars:    %d\n", len(cfg.App.Env))
	}
	if len(cfg.Secrets) > 0 {
		fmt.Printf("  Secrets:     %d\n", len(cfg.Secrets))
		for _, s := range cfg.Secrets {
			fmt.Printf("    - %s -> %s\n", s.Name, s.EnvVar)
		}
	}
	fmt.Println()
	fmt.Println("Next: enclave build")
	return nil
}

// ensureGitignoreEntry appends `entry` to <dir>/.gitignore if it's not
// already present. Creates the file if missing. Idempotent.
func ensureGitignoreEntry(dir, entry string) error {
	path := filepath.Join(dir, ".gitignore")
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == entry {
			return nil
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}
	_, err = f.WriteString(entry + "\n")
	return err
}
