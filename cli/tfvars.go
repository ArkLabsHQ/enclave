package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func tfvarsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tfvars",
		Short: "Generate terraform.tfvars.json from enclave.yaml",
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := findRepoRoot()
			if err != nil {
				return err
			}
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if err := writeTofuVars(cfg, root); err != nil {
				return err
			}
			fmt.Println("Generated enclave/tofu/terraform.tfvars.json")
			return nil
		},
	}
}
