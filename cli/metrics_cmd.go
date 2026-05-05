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
		source     string
		asJSON     bool
		instanceID string
		region     string
	)

	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Show enclave metrics",
		Long:  "Retrieves metric snapshots from the enclave supervisor via SSM RunCommand.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMetricsCmd(source, asJSON, instanceID, region)
		},
	}

	cmd.Flags().StringVar(&source, "source", "", "filter by source (supervisor, app, runtime)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output raw JSON")
	cmd.Flags().StringVar(&instanceID, "instance-id", "", "EC2 instance ID (required)")
	cmd.Flags().StringVar(&region, "region", "", "AWS region (required)")
	_ = cmd.MarkFlagRequired("instance-id")
	_ = cmd.MarkFlagRequired("region")

	return cmd
}

func runMetricsCmd(source string, asJSON bool, instanceID, region string) error {
	ctx := context.Background()
	ac, err := newAWSClients(ctx, region, "")
	if err != nil {
		return err
	}

	params := url.Values{}
	if source != "" {
		params.Set("source", source)
	}

	curlURL := "http://localhost:8443/enclave-metrics"
	if q := params.Encode(); q != "" {
		curlURL += "?" + q
	}

	curlCmd := fmt.Sprintf("curl -sfS '%s'", curlURL)
	output, err := ac.runCommand(ctx, instanceID, curlCmd)
	if err != nil {
		return fmt.Errorf("read metrics from supervisor on %s: %w", instanceID, err)
	}
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
