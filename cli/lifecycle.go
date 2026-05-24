package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func startCmd() *cobra.Command {
	return lifecycleCmd("start",
		"Start the enclave on the remote instance",
		"Starts the Nitro Enclave via the supervisor server on the EC2 instance.")
}

func stopCmd() *cobra.Command {
	return lifecycleCmd("stop",
		"Stop the enclave on the remote instance",
		"Stops the Nitro Enclave via the supervisor server on the EC2 instance.")
}

// lifecycleCmd builds an `enclave {start,stop}` command. Both POST to the
// supervisor's /<action> endpoint on the EC2 instance via SSM RunCommand;
// they take --instance-id, --region, and optionally --profile (matching
// `enclave log` / `enclave metrics`) — no enclave.yaml or tofu outputs
// needed.
func lifecycleCmd(action, short, long string) *cobra.Command {
	var (
		instanceID string
		region     string
		profile    string
	)
	cmd := &cobra.Command{
		Use:   action,
		Short: short,
		Long:  long,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLifecycle(action, instanceID, region, profile)
		},
	}
	cmd.Flags().StringVar(&instanceID, "instance-id", "", "EC2 instance ID (required)")
	cmd.Flags().StringVar(&region, "region", "", "AWS region (required)")
	cmd.Flags().StringVar(&profile, "profile", "", "AWS named profile (optional; defaults to AWS_PROFILE env var or the default credential chain)")
	_ = cmd.MarkFlagRequired("instance-id")
	_ = cmd.MarkFlagRequired("region")
	return cmd
}

func runLifecycle(action, instanceID, region, profile string) error {
	ctx := context.Background()
	ac, err := newAWSClients(ctx, region, profile)
	if err != nil {
		return err
	}
	curlCmd := fmt.Sprintf("curl -sf -X POST http://localhost:8443/%s", action)
	return ac.runOnHost(ctx, instanceID, fmt.Sprintf("%s enclave", action), []string{curlCmd})
}
