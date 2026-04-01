package introspector_enclave

import (
	"fmt"

	"github.com/spf13/cobra"
)

func tfvarsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tfvars",
		Short: "Generate terraform.tfvars.json from enclave.yaml",
		Long: `Translates enclave.yaml configuration into a terraform.tfvars.json file
that OpenTofu can consume directly.

After running this command, deploy with:
  cd enclave/tofu
  tofu init -backend-config="..."
  tofu apply`,
		RunE: runTfvars,
	}
}

func runTfvars(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	root, err := findRepoRoot()
	if err != nil {
		return err
	}

	if err := writeTofuVars(cfg, root); err != nil {
		return err
	}

	fmt.Printf("[tfvars] Written to enclave/tofu/terraform.tfvars.json\n")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  cd enclave/tofu")
	fmt.Println("  tofu init")
	fmt.Println("  tofu plan")
	fmt.Println("  tofu apply")
	return nil
}
