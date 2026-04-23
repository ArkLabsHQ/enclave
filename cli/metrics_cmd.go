package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
)

func metricsCmd() *cobra.Command {
	var (
		source string
		asJSON bool
	)

	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Show enclave metrics",
		Long:  "Retrieves metric snapshots from the enclave supervisor via the management server.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMetricsCmd(source, asJSON)
		},
	}

	cmd.Flags().StringVar(&source, "source", "", "filter by source (supervisor, app, runtime)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output raw JSON")

	return cmd
}

func runMetricsCmd(source string, asJSON bool) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := cfg.validateAccount(); err != nil {
		return err
	}

	root, err := findRepoRoot()
	if err != nil {
		return err
	}

	outputs, err := loadTofuOutputs(root)
	if err != nil {
		return err
	}

	ctx := context.Background()
	ac, err := newAWSClients(ctx, cfg.Region, cfg.Profile)
	if err != nil {
		return err
	}

	instanceID := outputs.getOutput("instance_id")
	if instanceID == "" {
		return fmt.Errorf("instance_id not found in tofu outputs")
	}

	params := url.Values{}
	if source != "" {
		params.Set("source", source)
	}

	curlURL := "http://localhost:8443/enclave-metrics"
	if q := params.Encode(); q != "" {
		curlURL += "?" + q
	}

	curlCmd := fmt.Sprintf("curl -sf '%s' 2>/dev/null || echo '{}'", curlURL)
	output := ac.runCommandOutput(ctx, instanceID, curlCmd)
	if output == "" {
		output = "{}"
	}

	if asJSON {
		fmt.Println(output)
		return nil
	}

	var snapshot map[string]any
	if err := json.Unmarshal([]byte(output), &snapshot); err != nil {
		return fmt.Errorf("failed to parse metrics: %w", err)
	}

	if len(snapshot) == 0 {
		fmt.Println("No metrics available.")
		return nil
	}

	for section, metrics := range snapshot {
		if source != "" && section != source {
			continue
		}
		fmt.Printf("%s:\n", section)
		if m, ok := metrics.(map[string]any); ok {
			for name, val := range m {
				fmt.Printf("  %-40s %v\n", name, val)
			}
		}
		fmt.Println()
	}

	return nil
}
