package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// awsClients holds initialized AWS SDK v2 clients for a specific region.
type awsClients struct {
	region    string
	ec2Client *ec2.Client
	kmsClient *kms.Client
	ssmClient *ssm.Client
	s3Client  *s3.Client
}

func newAWSClients(ctx context.Context, region, profile string) (*awsClients, error) {
	return newAWSClientsWithEnv(ctx, region, profile, nil)
}

// newAWSClientsWithEnv creates AWS clients, optionally overriding endpoints
// from the app env map (AWS_ENDPOINT_URL_KMS, AWS_ENDPOINT_URL_SSM, etc).
func newAWSClientsWithEnv(ctx context.Context, region, profile string, appEnv map[string]string) (*awsClients, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
	}
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	ac := &awsClients{region: region}
	ac.ec2Client = ec2.NewFromConfig(cfg)

	if ep := appEnv["AWS_ENDPOINT_URL_KMS"]; ep != "" {
		ac.kmsClient = kms.NewFromConfig(cfg, func(o *kms.Options) { o.BaseEndpoint = aws.String(ep) })
	} else {
		ac.kmsClient = kms.NewFromConfig(cfg)
	}

	if ep := appEnv["AWS_ENDPOINT_URL_SSM"]; ep != "" {
		ac.ssmClient = ssm.NewFromConfig(cfg, func(o *ssm.Options) { o.BaseEndpoint = aws.String(ep) })
	} else {
		ac.ssmClient = ssm.NewFromConfig(cfg)
	}

	if ep := appEnv["AWS_ENDPOINT_URL_S3"]; ep != "" {
		ac.s3Client = s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(ep)
			o.UsePathStyle = true
		})
	} else {
		ac.s3Client = s3.NewFromConfig(cfg)
	}

	return ac, nil
}

// --- EC2 ---

func (ac *awsClients) getInstanceState(ctx context.Context, instanceID string) (string, error) {
	out, err := ac.ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return "", err
	}
	if len(out.Reservations) == 0 || len(out.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("instance %s not found", instanceID)
	}
	return string(out.Reservations[0].Instances[0].State.Name), nil
}

// runOnHost runs commands on the EC2 host via SSM Run Command and waits for completion.
func (ac *awsClients) runOnHost(ctx context.Context, instanceID, desc string, commands []string) error {
	fmt.Printf("[deploy] Running on host: %s\n", desc)

	out, err := ac.ssmClient.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  []string{instanceID},
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters:   map[string][]string{"commands": commands},
	})
	if err != nil {
		return fmt.Errorf("send SSM command: %w", err)
	}

	commandID := *out.Command.CommandId

	// Poll for completion (max 5 minutes).
	for i := 0; i < 60; i++ {
		time.Sleep(5 * time.Second)

		inv, err := ac.ssmClient.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  aws.String(commandID),
			InstanceId: aws.String(instanceID),
		})
		if err != nil {
			continue // invocation may not be ready yet
		}

		switch inv.Status {
		case ssmtypes.CommandInvocationStatusSuccess:
			fmt.Printf("[deploy] Done: %s\n", desc)
			return nil
		case ssmtypes.CommandInvocationStatusFailed,
			ssmtypes.CommandInvocationStatusTimedOut,
			ssmtypes.CommandInvocationStatusCancelled,
			ssmtypes.CommandInvocationStatusCancelling:
			if inv.StandardErrorContent != nil && *inv.StandardErrorContent != "" {
				fmt.Fprintf(os.Stderr, "%s\n", *inv.StandardErrorContent)
			}
			return fmt.Errorf("host command failed (%s): %s", inv.Status, desc)
		}
		// InProgress, Pending, Delayed — keep polling.
	}

	return fmt.Errorf("timed out waiting for host command: %s", desc)
}

// runCommandOutput runs a single command on the host and returns its stdout (best-effort).
func (ac *awsClients) runCommandOutput(ctx context.Context, instanceID, command string) string {
	out, err := ac.ssmClient.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  []string{instanceID},
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters:   map[string][]string{"commands": {command}},
	})
	if err != nil {
		return ""
	}

	commandID := *out.Command.CommandId
	for i := 0; i < 5; i++ {
		time.Sleep(3 * time.Second)
		inv, err := ac.ssmClient.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  aws.String(commandID),
			InstanceId: aws.String(instanceID),
		})
		if err != nil {
			continue
		}
		if inv.Status == ssmtypes.CommandInvocationStatusSuccess {
			if inv.StandardOutputContent != nil {
				return strings.TrimSpace(*inv.StandardOutputContent)
			}
			return ""
		}
	}
	return ""
}

// runCommand runs a command on the host via SSM and returns its stdout. Unlike
// runCommandOutput, this surfaces SSM-level errors and non-zero exit codes
// (with stderr) instead of silently returning an empty string. Use it when an
// empty result must be distinguishable from a failed invocation.
func (ac *awsClients) runCommand(ctx context.Context, instanceID, command string) (string, error) {
	out, err := ac.ssmClient.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  []string{instanceID},
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters:   map[string][]string{"commands": {command}},
	})
	if err != nil {
		return "", fmt.Errorf("ssm SendCommand: %w", err)
	}
	commandID := *out.Command.CommandId

	deadline := time.Now().Add(30 * time.Second)
	for {
		if time.Now().After(deadline) {
			return "", fmt.Errorf("ssm command %s did not complete within 30s", commandID)
		}
		time.Sleep(2 * time.Second)
		inv, err := ac.ssmClient.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  aws.String(commandID),
			InstanceId: aws.String(instanceID),
		})
		if err != nil {
			// InvocationDoesNotExist races for a beat after SendCommand.
			continue
		}
		switch inv.Status {
		case ssmtypes.CommandInvocationStatusPending,
			ssmtypes.CommandInvocationStatusInProgress,
			ssmtypes.CommandInvocationStatusDelayed:
			continue
		case ssmtypes.CommandInvocationStatusSuccess:
			stdout := ""
			if inv.StandardOutputContent != nil {
				stdout = strings.TrimSpace(*inv.StandardOutputContent)
			}
			return stdout, nil
		default:
			stderr := ""
			if inv.StandardErrorContent != nil {
				stderr = strings.TrimSpace(*inv.StandardErrorContent)
			}
			if stderr == "" {
				return "", fmt.Errorf("ssm command on %s ended with status=%s (no stderr)", instanceID, inv.Status)
			}
			return "", fmt.Errorf("ssm command on %s ended with status=%s: %s", instanceID, inv.Status, stderr)
		}
	}
}
