package introspector_enclave

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
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
	return &awsClients{
		region:    region,
		ec2Client: ec2.NewFromConfig(cfg),
		kmsClient: kms.NewFromConfig(cfg),
		ssmClient: ssm.NewFromConfig(cfg),
		s3Client:  s3.NewFromConfig(cfg),
	}, nil
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

func (ac *awsClients) waitInstanceReady(ctx context.Context, instanceID string) error {
	waiter := ec2.NewInstanceStatusOkWaiter(ac.ec2Client)
	return waiter.Wait(ctx, &ec2.DescribeInstanceStatusInput{
		InstanceIds: []string{instanceID},
	}, 10*time.Minute)
}

// --- KMS ---

func (ac *awsClients) getKeyState(ctx context.Context, keyID string) (string, error) {
	out, err := ac.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return "", err
	}
	return string(out.KeyMetadata.KeyState), nil
}

func (ac *awsClients) getKeyPolicy(ctx context.Context, keyID string) (string, error) {
	out, err := ac.kmsClient.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return "", err
	}
	if out.Policy == nil {
		return "", nil
	}
	return *out.Policy, nil
}

func (ac *awsClients) putKeyPolicy(ctx context.Context, keyID, policy string, bypassLockout bool) error {
	_, err := ac.kmsClient.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{
		KeyId:                          aws.String(keyID),
		Policy:                         aws.String(policy),
		BypassPolicyLockoutSafetyCheck: bypassLockout,
	})
	return err
}

func (ac *awsClients) createKey(ctx context.Context, description string) (string, error) {
	out, err := ac.kmsClient.CreateKey(ctx, &kms.CreateKeyInput{
		Description: aws.String(description),
	})
	if err != nil {
		return "", err
	}
	return *out.KeyMetadata.KeyId, nil
}

// --- SSM ---

func (ac *awsClients) getParameter(ctx context.Context, name string) (string, error) {
	out, err := ac.ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name: aws.String(name),
	})
	if err != nil {
		return "", err
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", nil
	}
	return *out.Parameter.Value, nil
}

func (ac *awsClients) putParameter(ctx context.Context, name, value string) error {
	_, err := ac.ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(name),
		Value:     aws.String(value),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	return err
}

func (ac *awsClients) resetParameter(ctx context.Context, name string) error {
	return ac.putParameter(ctx, name, "UNSET")
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

// --- S3 ---

func (ac *awsClients) ensureBucket(ctx context.Context, bucket string) error {
	input := &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}
	if ac.region != "us-east-1" {
		input.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(ac.region),
		}
	}
	_, err := ac.s3Client.CreateBucket(ctx, input)
	if err != nil {
		var baoby *s3types.BucketAlreadyOwnedByYou
		var bae *s3types.BucketAlreadyExists
		if errors.As(err, &baoby) || errors.As(err, &bae) {
			return nil
		}
		return err
	}
	return nil
}

func (ac *awsClients) putBucketPolicy(ctx context.Context, bucket, policy string) error {
	_, err := ac.s3Client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucket),
		Policy: aws.String(policy),
	})
	return err
}

func (ac *awsClients) uploadFile(ctx context.Context, bucket, key, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = ac.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   f,
	})
	return err
}

// Suppress unused import warnings for types used only in method signatures.
var (
	_ ec2types.InstanceStateName
	_ kmstypes.KeyState
)
