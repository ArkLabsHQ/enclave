package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func descriptorCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "descriptor",
		Short: "Emit the deployment descriptor (genesis PCR0 + canonical bucket names)",
		Long: "Reads the genesis enclave's attested deployment descriptor from SSM and writes\n" +
			"it as JSON for out-of-band publication. Anyone can then run\n" +
			"`enclave verify-lineage --descriptor <file>` with no AWS credentials.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDescriptor(cmd.Context(), out)
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "deployment-descriptor.json", "Output file")
	return cmd
}

func runDescriptor(ctx context.Context, out string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ac, err := newAWSClients(ctx, cfg.Region, cfg.Profile)
	if err != nil {
		return err
	}
	deployment := cfg.Deployment
	if deployment == "" {
		deployment = "dev"
	}
	raw := readSSMParamSilent(ctx, ac.ssmClient, deployment, cfg.Name, "GenesisDescriptor")
	if raw == "" {
		return fmt.Errorf("no GenesisDescriptor in SSM — has the enclave booted at genesis yet?")
	}
	if !json.Valid([]byte(raw)) {
		return fmt.Errorf("GenesisDescriptor is not valid JSON")
	}
	if err := os.WriteFile(out, []byte(raw), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Printf("[descriptor] wrote %s\n", out)
	fmt.Println("[descriptor] publish this out-of-band; verify genesis_pcr0 against a reproducible v1 build.")
	return nil
}
