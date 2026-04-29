package runtime

import (
	"encoding/json"
	"fmt"
	"strings"
)

// =============================================================================
// KMS policy builder — fluent construction of locked KMS key policies.
// =============================================================================

// KMSPolicyBuilder constructs a locked KMS key policy via chained method
// calls. The locked policy restricts Decrypt to a specific PCR0 via Nitro
// attestation, grants Encrypt/GenerateDataKey/GetKeyPolicy to the enclave
// role, and (in strict mode) revokes PutKeyPolicy from everyone — making
// the key immutably bound to the enclave that built it.
//
// Usage:
//
//	policy := NewKMSPolicyBuilder().
//	    ForRole(ec2RoleARN).
//	    LockedToPCR0(pcr0).
//	    WithRootRecovery(accountID). // omit for strict mode
//	    Build()
//
// Driven by the ENCLAVE_KMS_KEY_LOCKED env var: callers should skip
// WithRootRecovery when ENCLAVE_KMS_KEY_LOCKED=true, include it otherwise.
// The choice is permanent at first lock — cannot be added or removed after.
type KMSPolicyBuilder struct {
	roleARN         string
	pcr0            string
	recoveryAccount string
}

// NewKMSPolicyBuilder returns an empty builder.
func NewKMSPolicyBuilder() *KMSPolicyBuilder {
	return &KMSPolicyBuilder{}
}

// ForRole sets the EC2 instance role ARN that's granted Encrypt /
// GenerateDataKey / GetKeyPolicy / ScheduleKeyDeletion. Required.
func (b *KMSPolicyBuilder) ForRole(arn string) *KMSPolicyBuilder {
	b.roleARN = arn
	return b
}

// LockedToPCR0 sets the PCR0 hash that gates Decrypt via Nitro
// attestation condition. Required.
func (b *KMSPolicyBuilder) LockedToPCR0(pcr0 string) *KMSPolicyBuilder {
	b.pcr0 = pcr0
	return b
}

// WithRootRecovery grants the AWS account root user kms:PutKeyPolicy /
// GetKeyPolicy / DescribeKey, so an operator can rewrite the policy
// after a lockout (typically by adding a new PCR0 condition). Skip this
// call for strict mode where the key is immutably locked.
func (b *KMSPolicyBuilder) WithRootRecovery(account string) *KMSPolicyBuilder {
	b.recoveryAccount = account
	return b
}

// Build assembles the JSON policy document.
func (b *KMSPolicyBuilder) Build() string {
	base := fmt.Sprintf(`    {
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
      "Action": ["kms:Encrypt", "kms:GetKeyPolicy", "kms:GenerateDataKey"],
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyDeletion",
      "Effect": "Allow",
      "Principal": {"AWS": %q},
      "Action": "kms:ScheduleKeyDeletion",
      "Resource": "*"
    }`, b.roleARN, b.pcr0, b.roleARN, b.roleARN)

	if b.recoveryAccount != "" {
		base += fmt.Sprintf(`,
    {
      "Sid": "RootRecovery",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::%s:root"},
      "Action": [
        "kms:PutKeyPolicy",
        "kms:GetKeyPolicy",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }`, b.recoveryAccount)
	}

	return `{
  "Version": "2012-10-17",
  "Statement": [
` + base + `
  ]
}`
}

// =============================================================================
// Pure helpers — ARN parsing and KMS policy JSON inspection.
// Stateless utilities used alongside the builder; live here because they
// share the policy-construction concern, not the *KMS lifecycle.
// =============================================================================

// assumedRoleARNToRoleARN converts an STS assumed-role ARN to an IAM role ARN.
// If the ARN is already an IAM principal (role, user, root), returned as-is.
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

// arnAccount returns the AWS account ID from any AWS ARN — segment [4]
// of "arn:partition:service:region:account:resource". Works for STS
// assumed-role, IAM role, IAM user, and root ARNs alike.
func arnAccount(arn string) (string, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return "", fmt.Errorf("invalid ARN: %s", arn)
	}
	if parts[4] == "" {
		return "", fmt.Errorf("ARN has empty account segment: %s", arn)
	}
	return parts[4], nil
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
						if s, ok := val.(string); ok && strings.EqualFold(s, pcr0) {
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
