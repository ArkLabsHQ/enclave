package runtime

import (
	"encoding/json"
	"fmt"
	"strings"
)

// BuildKMSPolicy gates Decrypt/GenerateDataKey on PCR0.
// Optional root recovery can mutate policy post-creation.
func BuildKMSPolicy(roleARN string, pcr0Values []string, recoveryAccount string) (string, error) {
	roleARN, err := assumedRoleARNToRoleARN(roleARN)
	if err != nil {
		return "", fmt.Errorf("invalid role ARN: %w", err)
	}

	statements := []kmsPolicyStatement{
		{
			Sid:       "EnclaveAttestedOperations",
			Effect:    "Allow",
			Principal: kmsPolicyPrincipal{AWS: roleARN},
			Action:    []string{"kms:Decrypt", "kms:GenerateDataKey"},
			Resource:  "*",
			Condition: &kmsPolicyConditions{
				StringEqualsIgnoreCase: map[string][]string{
					"kms:RecipientAttestation:PCR0": pcr0Values,
				},
			},
		},
		{
			Sid:       "EnclaveOperations",
			Effect:    "Allow",
			Principal: kmsPolicyPrincipal{AWS: roleARN},
			Action:    []string{"kms:Encrypt", "kms:GetKeyPolicy"},
			Resource:  "*",
		},
		{
			Sid:       "AllowKeyDeletion",
			Effect:    "Allow",
			Principal: kmsPolicyPrincipal{AWS: roleARN},
			Action:    []string{"kms:ScheduleKeyDeletion"},
			Resource:  "*",
		},
	}

	if recoveryAccount != "" {
		recoveryAccount, err := arnAccount(recoveryAccount)
		if err != nil {
			return "", fmt.Errorf("invalid recovery account ARN: %w", err)
		}

		statements = append(statements, kmsPolicyStatement{
			Sid:       "RootRecovery",
			Effect:    "Allow",
			Principal: kmsPolicyPrincipal{AWS: "arn:aws:iam::" + recoveryAccount + ":root"},
			Action:    []string{"kms:PutKeyPolicy", "kms:GetKeyPolicy", "kms:DescribeKey"},
			Resource:  "*",
		})
	}

	policy, _ := json.Marshal(kmsPolicyDocument{
		Version:   "2012-10-17",
		Statement: statements,
	})

	return string(policy), nil
}

// VerifyKeyPolicyPosture checks Decrypt PCR0 gates and PutKeyPolicy posture.
// Action wildcards are treated as granting both.
func VerifyKeyPolicyPosture(policyJSON string, expectedPCR0s []string, locked bool) error {
	if policyJSON == "" {
		return fmt.Errorf("empty KMS key policy")
	}
	if len(expectedPCR0s) == 0 {
		return fmt.Errorf("empty expected PCR0 set")
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

	admittedPCR0s := map[string]bool{}
	for _, stmt := range policy.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		actions := normalizePolicyStrings(stmt.Action)

		if actionsGrant(actions, "kms:Decrypt") {
			pcr0s, ok := pcr0ConditionValues(stmt.Condition)
			if !ok {
				return fmt.Errorf(
					"policy grants kms:Decrypt without a RecipientAttestation:PCR0 condition",
				)
			}
			for _, pcr0 := range pcr0s {
				admittedPCR0s[strings.ToLower(pcr0)] = true
			}
		}

		if actionsGrant(actions, "kms:PutKeyPolicy") {
			if locked {
				return fmt.Errorf(
					"policy grants kms:PutKeyPolicy but ENCLAVE_KMS_KEY_LOCKED is set (policy must be immutable)",
				)
			}
			if !principalsAllRoot(stmt.Principal) {
				return fmt.Errorf("policy grants kms:PutKeyPolicy to a non-root principal")
			}
		}
	}
	if !samePCR0Set(admittedPCR0s, expectedPCR0s) {
		return fmt.Errorf("policy PCR0 set does not match expected PCR0 set")
	}
	return nil
}

type kmsPolicyDocument struct {
	Version   string               `json:"Version"`
	Statement []kmsPolicyStatement `json:"Statement"`
}

type kmsPolicyStatement struct {
	Sid       string               `json:"Sid"`
	Effect    string               `json:"Effect"`
	Principal kmsPolicyPrincipal   `json:"Principal"`
	Action    []string             `json:"Action"`
	Resource  string               `json:"Resource"`
	Condition *kmsPolicyConditions `json:"Condition,omitempty"`
}

type kmsPolicyPrincipal struct {
	AWS string `json:"AWS"`
}

type kmsPolicyConditions struct {
	StringEqualsIgnoreCase map[string][]string `json:"StringEqualsIgnoreCase"`
}

// assumedRoleARNToRoleARN maps STS assumed-role ARNs to IAM role ARNs; IAM ARNs pass through.
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

// arnAccount returns ARN segment [4], the AWS account ID.
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

// pcr0ConditionValues returns the exact PCR0 values from the KMS attestation
// condition this runtime builds. AWS policies may encode the value as either a
// string or an array of strings; any other shape is rejected.
func pcr0ConditionValues(cond map[string]interface{}) ([]string, bool) {
	ops, ok := cond["StringEqualsIgnoreCase"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	val, ok := ops["kms:RecipientAttestation:PCR0"]
	if !ok {
		return nil, false
	}

	switch v := val.(type) {
	case string:
		if v == "" {
			return nil, false
		}
		return []string{v}, true
	case []interface{}:
		values := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok || s == "" {
				return nil, false
			}
			values = append(values, s)
		}
		return values, len(values) > 0
	case []string:
		for _, s := range v {
			if s == "" {
				return nil, false
			}
		}
		return v, len(v) > 0
	default:
		return nil, false
	}
}

func samePCR0Set(admitted map[string]bool, expected []string) bool {
	want := make(map[string]bool, len(expected))
	for _, pcr0 := range expected {
		if pcr0 == "" {
			return false
		}
		want[strings.ToLower(pcr0)] = true
	}
	if len(admitted) != len(want) {
		return false
	}
	for pcr0 := range want {
		if !admitted[pcr0] {
			return false
		}
	}
	return true
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
