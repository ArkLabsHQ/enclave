package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// selfApplyKMSPolicy applies the PCR0-restricted KMS key policy from inside
// the enclave. The enclave reads its own PCR0 from NSM hardware (unforgeable),
// derives its role ARN and account ID via STS, and calls PutKeyPolicy to
// restrict Decrypt to its own attestation identity.
//
// This is idempotent: if the policy already contains the correct PCR0, or if
// the key is locked (no PutKeyPolicy permission), the function returns nil.
func selfApplyKMSPolicy(ctx context.Context) error {
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	ssmClient := newSSMClient(awsCfg)
	kmsClient := newKMSClient(awsCfg)
	stsClient := newSTSClient(awsCfg)

	keyID, err := getKMSKeyID(ctx, ssmClient)
	if err != nil {
		return fmt.Errorf("get KMS key ID: %w", err)
	}

	// Get own PCR0 from NSM hardware.
	pcr0 := getPCR0()
	if pcr0 == "" {
		return fmt.Errorf("could not read PCR0 from NSM")
	}

	// Read current key policy to determine state.
	currentPolicy, err := kmsClient.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
		KeyId:      aws.String(keyID),
		PolicyName: aws.String("default"),
	})
	if err != nil {
		return fmt.Errorf("get current KMS key policy: %w", err)
	}

	// Parse and inspect the policy JSON to determine state.
	policyText := ""
	if currentPolicy.Policy != nil {
		policyText = *currentPolicy.Policy
	}

	hasPCR0, hasPutKeyPolicy := parseKMSPolicyState(policyText, pcr0)

	if hasPCR0 {
		slog.Info("KMS policy already contains PCR0, skipping", "pcr0", pcr0[:16])
		return nil
	}

	// Modifiable when: policy is empty (fresh key), or grants PutKeyPolicy or kms:*.
	if policyText != "" && !hasPutKeyPolicy {
		return fmt.Errorf("KMS key is locked to a different PCR0 (this enclave: %s...)", pcr0[:16])
	}

	// Get caller identity for role ARN and account ID.
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("sts get-caller-identity: %w", err)
	}

	roleARN, err := assumedRoleARNToRoleARN(*identity.Arn)
	if err != nil {
		return fmt.Errorf("resolve IAM role ARN: %w", err)
	}

	accountID := *identity.Account

	policy := buildKMSPolicy(accountID, roleARN, pcr0)

	// Retry with backoff to handle IAM propagation delay on fresh deploy.
	// BypassPolicyLockoutSafetyCheck is required because we're removing
	// PutKeyPolicy from everyone — the key becomes immutably locked.
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}
		_, err = kmsClient.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{
			KeyId:                          aws.String(keyID),
			Policy:                         aws.String(policy),
			PolicyName:                     aws.String("default"),
			BypassPolicyLockoutSafetyCheck: true,
		})
		if err == nil {
			slog.Info("applied PCR0-restricted KMS policy", "pcr0", pcr0[:16])
			return nil
		}
		lastErr = err
		slog.Warn("PutKeyPolicy attempt failed", "attempt", attempt+1, "error", err)
	}

	return fmt.Errorf("kms put-key-policy after retries: %w", lastErr)
}

// assumedRoleARNToRoleARN converts an STS assumed-role ARN to an IAM role ARN.
// If the ARN is already an IAM principal (role, user, root), it is returned as-is.
//
//	arn:aws:sts::123456789012:assumed-role/MyRole/i-abc123
//	→ arn:aws:iam::123456789012:role/MyRole
//
//	arn:aws:iam::000000000000:root → returned as-is
func assumedRoleARNToRoleARN(arn string) (string, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return "", fmt.Errorf("invalid ARN: %s", arn)
	}
	service := parts[2]  // "iam" or "sts"
	resource := parts[5] // assumed-role/ROLE_NAME/SESSION_NAME or role/NAME or root

	// Already an IAM ARN — valid KMS policy principal as-is.
	if service == "iam" {
		return arn, nil
	}

	segments := strings.SplitN(resource, "/", 3)
	if len(segments) < 2 || segments[0] != "assumed-role" {
		return "", fmt.Errorf("not an assumed-role ARN: %s", arn)
	}
	roleName := segments[1]
	account := parts[4]
	partition := parts[1]
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, account, roleName), nil
}

// parseKMSPolicyState parses a KMS key policy JSON and returns:
//   - hasPCR0: whether any statement's Condition references the given PCR0 value
//   - hasPutKeyPolicy: whether any statement grants "kms:PutKeyPolicy" or "kms:*"
func parseKMSPolicyState(policyJSON, pcr0 string) (hasPCR0, hasPutKeyPolicy bool) {
	if policyJSON == "" {
		return false, false
	}

	var policy struct {
		Statement []struct {
			Action    json.RawMessage        `json:"Action"`
			Condition map[string]interface{} `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return false, false
	}

	for _, stmt := range policy.Statement {
		// Check if this statement's condition references our PCR0.
		for _, condOps := range stmt.Condition {
			if ops, ok := condOps.(map[string]interface{}); ok {
				for key, val := range ops {
					if strings.Contains(strings.ToLower(key), "pcr0") {
						if s, ok := val.(string); ok && s == pcr0 {
							hasPCR0 = true
						}
					}
				}
			}
		}

		// Check if this statement grants PutKeyPolicy or kms:*.
		actions := parseActions(stmt.Action)
		for _, a := range actions {
			if a == "kms:PutKeyPolicy" || a == "kms:*" {
				hasPutKeyPolicy = true
			}
		}
	}
	return
}

// parseActions extracts action strings from a JSON value that can be
// either a single string or an array of strings.
func parseActions(raw json.RawMessage) []string {
	if raw == nil {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err == nil {
		return multi
	}
	return nil
}

// buildKMSPolicy builds a locked KMS key policy: Decrypt is restricted to the
// enclave's PCR0 via attestation, Encrypt/GenerateDataKey are unrestricted for
// the EC2 role, GetKeyPolicy allows the enclave to verify the lock on reboot,
// and ScheduleKeyDeletion is allowed for old-key cleanup during migration.
// No PutKeyPolicy is granted to anyone — the key is immutably locked to this PCR0.
// The account root is granted DescribeKey so tofu and IAM users can inspect the key.
func buildKMSPolicy(accountID, ec2RoleARN, pcr0 string) string {
	return fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAccountDescribe",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::%s:root"},
      "Action": ["kms:DescribeKey", "kms:GetKeyPolicy"],
      "Resource": "*"
    },
    {
      "Sid": "EnclaveDecryptWithAttestation",
      "Effect": "Allow",
      "Principal": {"AWS": %q},
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": %q
        }
      }
    },
    {
      "Sid": "EnclaveOperations",
      "Effect": "Allow",
      "Principal": {"AWS": %q},
      "Action": ["kms:Encrypt", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GenerateDataKey"],
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyDeletion",
      "Effect": "Allow",
      "Principal": {"AWS": %q},
      "Action": "kms:ScheduleKeyDeletion",
      "Resource": "*"
    }
  ]
}`, accountID, ec2RoleARN, pcr0, ec2RoleARN, ec2RoleARN)
}
