package introspector_enclave

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func destroyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "destroy",
		Short: "Tear down the CDK stack",
		Long:  "Destroys all AWS infrastructure created by 'enclave deploy'.",
		RunE:  runDestroy,
	}
	cmd.Flags().Bool("force", false, "Skip confirmation prompt")
	return cmd
}

func runDestroy(cmd *cobra.Command, args []string) error {
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

	force, _ := cmd.Flags().GetBool("force")
	if !force {
		fmt.Printf("This will destroy stack %s in %s. Continue? [y/N] ", cfg.stackName(), cfg.Region)
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(answer)) != "y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	fmt.Printf("[destroy] Destroying stack %s\n", cfg.stackName())

	// Stop the enclave and schedule KMS key deletion via the management server.
	// The locked key policy only grants ScheduleKeyDeletion to the EC2 instance
	// role, so we must do this while the instance is still running.
	if err := teardownViaManagementServer(cfg, root); err != nil {
		fmt.Printf("[destroy] Warning: could not complete teardown: %v\n", err)
		fmt.Println("[destroy] The key will be retained as an orphan. Continuing with stack deletion.")
	}

	// Synthesize the CDK template to resolve the KMS key's logical ID.
	// The locked key policy prevents CloudFormation from deleting the key,
	// so we must retain it via --retain-resources. Key deletion is already
	// scheduled above via the management server.
	kmsLogicalID, err := findKMSKeyLogicalID(cfg, root)
	if err != nil {
		return fmt.Errorf("resolve KMS key logical ID: %w", err)
	}
	fmt.Printf("[destroy] Retaining KMS key (logical ID: %s)\n", kmsLogicalID)

	env := cfg.configEnv()
	stack := cfg.stackName()

	// First attempt: delete without --retain-resources.
	fmt.Println("[destroy] Deleting stack...")
	_ = runCmd("aws", []string{
		"cloudformation", "delete-stack",
		"--stack-name", stack,
		"--region", cfg.Region,
	}, root, env)

	fmt.Println("[destroy] Waiting for stack deletion...")
	waitErr := runCmd("aws", []string{
		"cloudformation", "wait", "stack-delete-complete",
		"--stack-name", stack,
		"--region", cfg.Region,
	}, root, env)

	if waitErr != nil {
		// Stack likely entered DELETE_FAILED because CloudFormation can't
		// delete the KMS key (locked policy). Retry with --retain-resources.
		fmt.Printf("[destroy] Stack deletion failed, retaining KMS key %s and retrying...\n", kmsLogicalID)
		if err := runCmd("aws", []string{
			"cloudformation", "delete-stack",
			"--stack-name", stack,
			"--retain-resources", kmsLogicalID,
			"--region", cfg.Region,
		}, root, env); err != nil {
			return err
		}

		fmt.Println("[destroy] Waiting for stack deletion...")
		return runCmd("aws", []string{
			"cloudformation", "wait", "stack-delete-complete",
			"--stack-name", stack,
			"--region", cfg.Region,
		}, root, env)
	}

	return nil
}

// findKMSKeyLogicalID synthesizes the CDK stack and parses the CloudFormation
// template to find the logical ID of the AWS::KMS::Key resource. This avoids
// hardcoding the CDK-generated logical ID (e.g. "EncryptionKey1B843E66").
func findKMSKeyLogicalID(cfg *Config, root string) (string, error) {
	// CDK synthesis requires all asset paths to exist. During destroy the
	// build artifacts may be absent, so create empty placeholders.
	placeholders := []string{
		filepath.Join(root, "enclave", "artifacts", "image.eif"),
		filepath.Join(root, "enclave", "artifacts", "enclave-mgmt"),
	}
	for _, p := range placeholders {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				return "", fmt.Errorf("create placeholder dir: %w", err)
			}
			if err := os.WriteFile(p, nil, 0644); err != nil {
				return "", fmt.Errorf("create placeholder %s: %w", filepath.Base(p), err)
			}
		}
	}

	if err := synthCDKStack(cfg, root); err != nil {
		return "", fmt.Errorf("synthesize stack: %w", err)
	}

	templatePath := filepath.Join(root, "enclave", "cdk.out", cfg.stackName()+".template.json")
	data, err := os.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("read template: %w", err)
	}

	var template struct {
		Resources map[string]struct {
			Type string `json:"Type"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal(data, &template); err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	for logicalID, res := range template.Resources {
		if res.Type == "AWS::KMS::Key" {
			return logicalID, nil
		}
	}
	return "", fmt.Errorf("no AWS::KMS::Key resource found in template")
}

// teardownViaManagementServer stops the enclave and schedules KMS key deletion
// by calling the localhost management server endpoints via SSM Run Command.
func teardownViaManagementServer(cfg *Config, root string) error {
	ctx := context.Background()

	ac, err := newAWSClients(ctx, cfg.Region, cfg.Profile)
	if err != nil {
		return fmt.Errorf("create AWS clients: %w", err)
	}

	// Try CDK outputs first, fall back to SSM (stored during deploy).
	var instanceID string
	outputs, err := loadCDKOutputs(root)
	if err == nil {
		stack := cfg.stackName()
		instanceID = outputs.getOutput(stack, "InstanceID", "InstanceId", "Instance ID")
	}
	if instanceID == "" {
		instanceID, _ = ac.getParameter(ctx, cfg.ssmParam("InstanceID"))
	}
	if instanceID == "" {
		return fmt.Errorf("InstanceID not found in cdk-outputs.json or SSM")
	}

	// Stop the enclave (ignore errors if already stopped).
	fmt.Println("[destroy] Stopping enclave...")
	_ = ac.runOnHost(ctx, instanceID, "stop enclave", []string{
		"curl -sf -X POST http://localhost:8443/stop || true",
	})

	// Schedule KMS key deletion.
	fmt.Println("[destroy] Scheduling KMS key deletion...")
	return ac.runOnHost(ctx, instanceID, "schedule KMS key deletion", []string{
		"curl -sf -X POST http://localhost:8443/schedule-key-deletion",
	})
}
