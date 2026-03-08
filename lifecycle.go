package introspector_enclave

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func startCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the enclave on the remote instance",
		Long:  "Starts the Nitro Enclave via the management server on the EC2 instance.",
		RunE:  runStart,
	}
}

func stopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the enclave on the remote instance",
		Long:  "Stops the Nitro Enclave via the management server on the EC2 instance.",
		RunE:  runStop,
	}
}

func runStart(cmd *cobra.Command, args []string) error {
	return enclaveLifecycleAction("start")
}

func runStop(cmd *cobra.Command, args []string) error {
	return enclaveLifecycleAction("stop")
}

// enclaveLifecycleAction calls the management server's start or stop endpoint
// on the EC2 instance via SSM Run Command.
func enclaveLifecycleAction(action string) error {
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

	outputs, err := loadCDKOutputs(root)
	if err != nil {
		return err
	}

	ctx := context.Background()
	ac, err := newAWSClients(ctx, cfg.Region, cfg.Profile)
	if err != nil {
		return err
	}

	stack := cfg.stackName()
	instanceID := outputs.getOutput(stack, "InstanceID", "InstanceId", "Instance ID")
	if instanceID == "" {
		return fmt.Errorf("InstanceID not found in cdk-outputs.json")
	}

	curlCmd := fmt.Sprintf("curl -sf -X POST http://localhost:8443/%s", action)
	return ac.runOnHost(ctx, instanceID, fmt.Sprintf("%s enclave", action), []string{curlCmd})
}
