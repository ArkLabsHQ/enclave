package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// tofuCmd scaffolds the OpenTofu module tree under ./tofu/ with
// merge-only-new semantics: files that already exist are left untouched
// so the user's customizations to kms.tf, ec2.tf, etc. survive re-runs.
func tofuCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tofu",
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
		RunE: runTofuScaffold,
	}
	cmd.Flags().Bool("remote", false,
		"Pull EIF + supervisor from the GitHub Release at apply time instead of using local files")
	return cmd
}

func runTofuScaffold(cmd *cobra.Command, args []string) error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}

	remote, _ := cmd.Flags().GetBool("remote")

	// PWD-rooted: don't walk up to a parent .git, so sub-projects inside
	// a larger repo resolve to their own directory.
	configPath := os.Getenv("ENCLAVE_CONFIG")
	if configPath == "" {
		flat := filepath.Join(root, "enclave.yaml")
		subdir := filepath.Join(root, "enclave", "enclave.yaml")
		if _, err := os.Stat(flat); err == nil {
			configPath = flat
		} else if _, err := os.Stat(subdir); err == nil {
			configPath = subdir
		} else {
			configPath = flat
		}
	}
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
	if remote {
		fmt.Printf("Wrote    tofu/terraform.tfvars.json — remote artifacts: github.com/%s/%s @ %s\n",
			cfg.App.NixOwner, cfg.App.NixRepo, cfg.App.ReleaseTag)
		fmt.Println("\nNext: cd tofu && tofu init && tofu apply")
	} else {
		fmt.Println("Wrote    tofu/terraform.tfvars.json (from enclave.yaml)")
		fmt.Println("\nNext: enclave build  →  cd tofu && tofu init && tofu apply")
	}
	return nil
}
