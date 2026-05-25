package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// tofuCmd groups the OpenTofu lifecycle subcommands. With no subcommand it
// prints help; the work lives in `enclave tofu init` (scaffold) and
// `enclave tofu update` (refresh tfvars).
func tofuCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tofu",
		Short: "Scaffold and maintain the OpenTofu module under ./tofu/",
		Long: `OpenTofu lifecycle subcommands for an enclave deployment.

  enclave tofu init    scaffold the module tree + tfvars + backend.tf
  enclave tofu update  refresh tfvars from enclave.yaml (modules untouched)`,
	}
	cmd.AddCommand(tofuInitCmd())
	cmd.AddCommand(tofuUpdateCmd())
	return cmd
}

// tofuInitCmd performs the initial scaffold of ./tofu/ with merge-only-new
// semantics: existing module files are left untouched so operator
// customizations to kms.tf, ec2.tf, etc. survive re-runs.
func tofuInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate the OpenTofu module scaffold into ./tofu/",
		Long: `Writes the OpenTofu deployment scaffold (backend bootstrap, enclave
module, state migration script, cloud-init template) into ./tofu/.

Safe to re-run: existing files are skipped so local customizations are
preserved. To regenerate a specific file, delete it first then re-run.

By default, terraform.tfvars.json points at the EIF and supervisor binary
that 'enclave build' produced under .enclave/artifacts/ — tofu uploads
those files directly to S3. Pass --remote to leave those paths empty so
the tofu module pulls image.eif and supervisor from the GitHub Release
identified by app.nix_owner / app.nix_repo / app.release_tag in
enclave.yaml at apply time, then mirrors them to S3.`,
		RunE: runTofuInit,
	}
	cmd.Flags().Bool("remote", false,
		"Pull EIF + supervisor from the GitHub Release at apply time instead of using local files")
	return cmd
}

// resolveEnclaveConfig finds enclave.yaml honoring $ENCLAVE_CONFIG, then the
// flat ./enclave.yaml layout, then the ./enclave/enclave.yaml subdir layout.
// projectRoot is the current working directory — tofu output files are
// written relative to it.
func resolveEnclaveConfig() (configPath, projectRoot string, err error) {
	projectRoot, err = os.Getwd()
	if err != nil {
		return "", "", err
	}
	configPath = os.Getenv("ENCLAVE_CONFIG")
	if configPath != "" {
		return configPath, projectRoot, nil
	}
	flat := filepath.Join(projectRoot, "enclave.yaml")
	subdir := filepath.Join(projectRoot, "enclave", "enclave.yaml")
	if _, err := os.Stat(flat); err == nil {
		return flat, projectRoot, nil
	}
	if _, err := os.Stat(subdir); err == nil {
		return subdir, projectRoot, nil
	}
	return flat, projectRoot, nil
}

func runTofuInit(cmd *cobra.Command, args []string) error {
	configPath, root, err := resolveEnclaveConfig()
	if err != nil {
		return err
	}

	remote, _ := cmd.Flags().GetBool("remote")

	cfg, err := loadConfigAt(configPath)
	if err != nil {
		return err
	}
	if remote && (cfg.App.NixOwner == "" || cfg.App.NixRepo == "") {
		return fmt.Errorf("--remote requires app.nix_owner and app.nix_repo to be set in enclave.yaml " +
			"(tofu pulls artifacts from github.com/<owner>/<repo>/releases/download/<release_tag>/)")
	}
	language := cfg.App.Language
	if language == "" {
		language = "go"
	}

	var created, skipped []string
	for _, f := range getTofuFiles(language) {
		dest := filepath.Join(root, f.RelPath)
		if _, err := os.Stat(dest); err == nil {
			skipped = append(skipped, f.RelPath)
			continue
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", f.RelPath, err)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return fmt.Errorf("create directory for %s: %w", f.RelPath, err)
		}
		if err := os.WriteFile(dest, []byte(f.Content), f.Mode); err != nil {
			return fmt.Errorf("write %s: %w", f.RelPath, err)
		}
		created = append(created, f.RelPath)
	}

	for _, p := range created {
		fmt.Printf("Created %s\n", p)
	}
	for _, p := range skipped {
		fmt.Printf("Skipped %s (already exists)\n", p)
	}
	fmt.Printf("\nCreated %d files, skipped %d existing.\n", len(created), len(skipped))

	// terraform.tfvars.json is derived from enclave.yaml; always overwrite.
	if err := writeTofuVars(cfg, root, remote); err != nil {
		return fmt.Errorf("write terraform.tfvars.json: %w", err)
	}
	if err := writeBackendConfig(cfg, root); err != nil {
		return fmt.Errorf("write backend.tf: %w", err)
	}
	if remote {
		fmt.Printf("Wrote    tofu/terraform.tfvars.json — remote artifacts: github.com/%s/%s @ %s\n",
			cfg.App.NixOwner, cfg.App.NixRepo, cfg.App.ReleaseTag)
		fmt.Println("\nNext: cd tofu && tofu init && tofu apply")
	} else {
		fmt.Println("Wrote    tofu/terraform.tfvars.json (from enclave.yaml)")
		fmt.Println("\nNext: enclave build  →  cd tofu && tofu init && tofu apply")
	}
	fmt.Println("\nTip: after editing enclave.yaml, run 'enclave tofu update' to refresh tfvars only.")
	return nil
}

// tofuUpdateCmd refreshes tofu/terraform.tfvars.json from the current
// enclave.yaml. Module files and backend.tf are left untouched.
func tofuUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Refresh tofu/terraform.tfvars.json from enclave.yaml",
		Long: `Regenerates tofu/terraform.tfvars.json from the current enclave.yaml.
Run after editing enclave.yaml (tls settings, route53_zone_id, runtime version,
secrets list) to sync the tfvars before running 'tofu apply'.

Module files (tofu/main.tf, tofu/modules/...) and tofu/backend.tf are left
untouched. Use 'enclave tofu init' for the initial scaffold.`,
		RunE: runTofuUpdate,
	}
	cmd.Flags().Bool("remote", false,
		"Leave eif_path/supervisor_binary_path empty so tofu apply pulls from GitHub Release")
	return cmd
}

func runTofuUpdate(cmd *cobra.Command, _ []string) error {
	configPath, root, err := resolveEnclaveConfig()
	if err != nil {
		return err
	}

	// Precondition: an initial scaffold must already exist. Running 'update'
	// before 'enclave tofu init' would silently write tfvars into an empty dir.
	mainTF := filepath.Join(root, "tofu", "main.tf")
	if _, err := os.Stat(mainTF); os.IsNotExist(err) {
		return fmt.Errorf("tofu/main.tf not found — run 'enclave tofu init' first to scaffold the module")
	} else if err != nil {
		return fmt.Errorf("stat %s: %w", mainTF, err)
	}

	cfg, err := loadConfigAt(configPath)
	if err != nil {
		return err
	}

	remote, _ := cmd.Flags().GetBool("remote")
	if remote && (cfg.App.NixOwner == "" || cfg.App.NixRepo == "") {
		return fmt.Errorf("--remote requires app.nix_owner and app.nix_repo to be set in enclave.yaml")
	}

	if err := writeTofuVars(cfg, root, remote); err != nil {
		return fmt.Errorf("write terraform.tfvars.json: %w", err)
	}
	fmt.Printf("Refreshed tofu/terraform.tfvars.json from %s\n", configPath)
	return nil
}
