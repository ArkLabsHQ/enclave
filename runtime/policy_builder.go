package runtime

import (
	"encoding/json"
	"fmt"
	"strings"
)

// =============================================================================
// KMS policy builder — fluent construction of locked KMS key policies.
// =============================================================================

// KMSPolicyBuilder builds the locked KMS key policy passed to CreateKey.
// Decrypt is PCR0-attestation-gated; the EC2 role gets Encrypt /
// GenerateDataKey / GetKeyPolicy / ScheduleKeyDeletion (no PutKeyPolicy).
// WithRootRecovery is the only path to mutate the policy post-creation.
type KMSPolicyBuilder struct {
	roleARN         string
	pcr0Values      []string
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

// LockedToPCR0Values gates Decrypt on the Nitro attestation condition,
// admitting any of the given PCR0 hashes (implicit OR). At least one is
// required; CreateMigrationKey passes [oldPCR0, newPCR0].
func (b *KMSPolicyBuilder) LockedToPCR0Values(pcr0s []string) *KMSPolicyBuilder {
	b.pcr0Values = pcr0s
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
	condVal, _ := json.Marshal(b.pcr0Values)
	roleJSON, _ := json.Marshal(b.roleARN)
	base := fmt.Sprintf(`    {
      "Sid": "EnclaveDecryptWithAttestation",
      "Effect": "Allow",
      "Principal": {"AWS": %s},
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": %s
        }
      }
    },
    {
      "Sid": "EnclaveOperations",
      "Effect": "Allow",
      "Principal": {"AWS": %s},
      "Action": ["kms:Encrypt", "kms:GetKeyPolicy", "kms:GenerateDataKey"],
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyDeletion",
      "Effect": "Allow",
      "Principal": {"AWS": %s},
      "Action": "kms:ScheduleKeyDeletion",
      "Resource": "*"
    }`, roleJSON, condVal, roleJSON, roleJSON)

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

// policyAdmitsPCR0: true iff some kms:RecipientAttestation:PCR0 condition
// matches pcr0 (single value or array, case-insensitive).
func policyAdmitsPCR0(policyJSON, pcr0 string) bool {
	if policyJSON == "" {
		return false
	}
	var policy struct {
		Statement []struct {
			Condition map[string]interface{} `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return false
	}
	for _, stmt := range policy.Statement {
		if conditionAdmitsPCR0(stmt.Condition, pcr0) {
			return true
		}
	}
	return false
}

// verifyKeyPolicyPosture enforces a genuine enclave key policy beyond admitting
// our PCR0 (issue #131): kms:Decrypt only under a RecipientAttestation:PCR0
// condition that admits us (no un-gated decrypt path), and kms:PutKeyPolicy held
// by nobody when locked / root-only when unlocked. Wildcards count as granting
// both. Migration-safe: a [old, new] PCR0 set still passes if ours is in it.
func verifyKeyPolicyPosture(policyJSON, pcr0 string, locked bool) error {
	if policyJSON == "" {
		return fmt.Errorf("empty KMS key policy")
	}
	var policy struct {
		Statement []struct {
			Effect    string                 `json:"Effect"`
			Principal json.RawMessage        `json:"Principal"`
			Action    json.RawMessage        `json:"Action"`
			Condition map[string]interface{} `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return fmt.Errorf("parse KMS key policy: %w", err)
	}

	admitsOurPCR0 := false
	for _, stmt := range policy.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		actions := normalizePolicyStrings(stmt.Action)

		if actionsGrant(actions, "kms:Decrypt") {
			if !conditionHasPCR0(stmt.Condition) {
				return fmt.Errorf("policy grants kms:Decrypt without a RecipientAttestation:PCR0 condition")
			}
			if conditionAdmitsPCR0(stmt.Condition, pcr0) {
				admitsOurPCR0 = true
			}
		}

		if actionsGrant(actions, "kms:PutKeyPolicy") {
			if locked {
				return fmt.Errorf("policy grants kms:PutKeyPolicy but ENCLAVE_KMS_KEY_LOCKED is set (policy must be immutable)")
			}
			if !principalsAllRoot(stmt.Principal) {
				return fmt.Errorf("policy grants kms:PutKeyPolicy to a non-root principal")
			}
		}
	}
	if !admitsOurPCR0 {
		return fmt.Errorf("policy does not admit our PCR0 for kms:Decrypt")
	}
	return nil
}

// conditionHasPCR0 reports whether a statement Condition carries any
// RecipientAttestation:PCR0 constraint (regardless of the values it admits).
func conditionHasPCR0(cond map[string]interface{}) bool {
	for _, condOps := range cond {
		ops, ok := condOps.(map[string]interface{})
		if !ok {
			continue
		}
		for key := range ops {
			if strings.Contains(strings.ToLower(key), "pcr0") {
				return true
			}
		}
	}
	return false
}

// conditionAdmitsPCR0 reports whether a statement Condition has a PCR0
// constraint that admits pcr0 (single value or array, case-insensitive).
func conditionAdmitsPCR0(cond map[string]interface{}, pcr0 string) bool {
	for _, condOps := range cond {
		ops, ok := condOps.(map[string]interface{})
		if !ok {
			continue
		}
		for key, val := range ops {
			if !strings.Contains(strings.ToLower(key), "pcr0") {
				continue
			}
			switch v := val.(type) {
			case string:
				if strings.EqualFold(v, pcr0) {
					return true
				}
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok && strings.EqualFold(s, pcr0) {
						return true
					}
				}
			}
		}
	}
	return false
}

// normalizePolicyStrings decodes an IAM Action/Principal-AWS field, which may be
// a single JSON string or an array of strings, into a slice.
func normalizePolicyStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

// actionsGrant reports whether actions include want, treating the kms:* and *
// wildcards as granting everything.
func actionsGrant(actions []string, want string) bool {
	for _, a := range actions {
		if strings.EqualFold(a, want) || a == "kms:*" || a == "*" {
			return true
		}
	}
	return false
}

// principalsAllRoot reports whether every AWS principal in a statement is an
// account-root ARN (…:root). Returns false for a missing, wildcard, or
// non-root principal.
func principalsAllRoot(raw json.RawMessage) bool {
	var p struct {
		AWS json.RawMessage `json:"AWS"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return false
	}
	arns := normalizePolicyStrings(p.AWS)
	if len(arns) == 0 {
		return false
	}
	for _, a := range arns {
		if !strings.HasSuffix(a, ":root") {
			return false
		}
	}
	return true
}
