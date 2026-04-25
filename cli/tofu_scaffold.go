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
	return &cobra.Command{
		Use:   "tofu",
		Short: "Generate the OpenTofu module scaffold into ./tofu/",
		Long: `Writes the OpenTofu deployment scaffold (backend bootstrap, enclave
module, state migration script, cloud-init template) into ./tofu/.

Safe to re-run: existing files are skipped so local customizations are
preserved. To regenerate a specific file, delete it first then re-run.`,
		RunE: runTofuScaffold,
	}
}

func runTofuScaffold(cmd *cobra.Command, args []string) error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}

	// Load config so writeTofuVars below can read region/app_name/secrets etc.
	// loadConfig already returns a "(run 'enclave init' to create one)" hint
	// when enclave.yaml is absent — no need to wrap further.
	cfg, err := loadConfig()
	if err != nil {
		return err
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

	// Render tofu/terraform.tfvars.json from enclave.yaml so `tofu apply` can
	// resolve templatefile() references in user_data.sh.tftpl (region,
	// app_name, deployment, migration_cooldown, previous_pcr0, etc.) without
	// additional flags. Always overwrites — tfvars is derived state, not
	// user-editable scaffolding. Re-run after editing enclave.yaml or after
	// `enclave build` (to pick up a fresh PCR0).
	if err := writeTofuVars(cfg, root); err != nil {
		return fmt.Errorf("write terraform.tfvars.json: %w", err)
	}
	fmt.Println("Wrote    tofu/terraform.tfvars.json (from enclave.yaml)")

	fmt.Println("\nNext: enclave build  →  cd tofu && tofu init && tofu apply")
	return nil
}
