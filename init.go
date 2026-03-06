package introspector_enclave

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
version: dev                     # Build version (baked into binary via ldflags)
region: us-east-1                # AWS region
account: ""                      # AWS account ID (required)
prefix: dev                      # Deployment prefix (stack = {prefix}Nitro{Name})
instance_type: m6i.xlarge        # EC2 instance type
nix_image: nixos/nix:2.24.9      # Docker image for reproducible builds

# SDK coordinates for the enclave supervisor binary.
# The supervisor handles attestation, secrets, PCR extension, and signing
# middleware automatically. Your app is a plain HTTP server with zero SDK imports.
sdk:
  rev: ""                        # SDK git commit SHA (required)
  hash: ""                       # Nix source hash: nix-prefetch-url --unpack (required)
  vendor_hash: ""                # Go vendor hash (required)

app:
  language: "go"                 # App language: go, nodejs, dotnet
  source: nix                    # "nix" = fetch from GitHub via Nix

  # GitHub coordinates for the app to run inside the enclave.
  # Your app is a plain HTTP server that listens on ENCLAVE_APP_PORT (default 7074).
  # Secrets are passed as environment variables. No SDK imports needed.
  nix_owner: ""                  # GitHub owner (required)
  nix_repo: ""                   # GitHub repo name (required)
  nix_rev: ""                    # Git commit SHA (required)
  nix_hash: ""                   # Nix source hash: nix-prefetch-url --unpack (required)
  nix_vendor_hash: ""            # Go vendor hash (required)
  nix_sub_packages:              # Go sub-packages to build
    - "."
  binary_name: ""                # Output binary name (defaults to 'name')

  # Environment variables baked into the EIF.
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
	return &cobra.Command{
		Use:   "init",
		Short: "Validate enclave.yaml or create a template",
		Long: `Reads and validates enclave.yaml in the current directory.
If no enclave.yaml exists, writes a commented template as a starting point.`,
		RunE: runInit,
	}
}

func runInit(cmd *cobra.Command, args []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(cwd, configFile)

	// If enclave/enclave.yaml doesn't exist, create the directory, write the
	// config template, and scaffold all framework files needed by CDK and Nix.
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		enclaveDir := filepath.Join(cwd, "enclave")
		if err := os.MkdirAll(enclaveDir, 0755); err != nil {
			return fmt.Errorf("create enclave/ directory: %w", err)
		}
		// Substitute SDK coordinates if baked in via ldflags (release builds).
		cfg := configTemplate
		if sdkRev != "" {
			cfg = strings.Replace(cfg,
				`  rev: ""                        # SDK git commit SHA (required)`,
				fmt.Sprintf(`  rev: "%s"`, sdkRev), 1)
			cfg = strings.Replace(cfg,
				`  hash: ""                       # Nix source hash: nix-prefetch-url --unpack (required)`,
				fmt.Sprintf(`  hash: "%s"`, sdkHash), 1)
			cfg = strings.Replace(cfg,
				`  vendor_hash: ""                # Go vendor hash (required)`,
				fmt.Sprintf(`  vendor_hash: "%s"`, sdkVendorHash), 1)
		}
		if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
			return fmt.Errorf("write %s: %w", configFile, err)
		}
		fmt.Printf("Created %s\n", configFile)

		// Write framework files (gvproxy, systemd units, scripts, user_data, start.sh).
		for _, f := range getFrameworkFiles("go") {
			destPath := filepath.Join(cwd, f.RelPath)
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return fmt.Errorf("create directory for %s: %w", f.RelPath, err)
			}
			if err := os.WriteFile(destPath, []byte(f.Content), f.Mode); err != nil {
				return fmt.Errorf("write %s: %w", f.RelPath, err)
			}
			fmt.Printf("Created %s\n", f.RelPath)
		}

		fmt.Println()
		fmt.Println("Edit enclave/enclave.yaml with your app and SDK details.")
		fmt.Println("Your app is a plain HTTP server listening on ENCLAVE_APP_PORT (default 7074).")
		fmt.Println("No SDK imports needed — the supervisor handles attestation automatically.")
		fmt.Println("Set 'app.language' to your language (go, nodejs, dotnet) and run 'enclave setup --language <lang>'.")
		fmt.Println("Then run 'enclave init' again to validate.")
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
	if cfg.SDK.Rev == "" {
		errors = append(errors, "'sdk.rev' is required")
	}
	if cfg.SDK.Hash == "" {
		errors = append(errors, "'sdk.hash' is required")
	}
	if cfg.SDK.VendorHash == "" {
		errors = append(errors, "'sdk.vendor_hash' is required")
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
	fmt.Printf("  SDK Rev:     %.12s\n", cfg.SDK.Rev)
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
