package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

const kmsPolicyVersion = "2012-10-17"

var (
	attestedActions   = []string{"kms:Decrypt", "kms:GenerateDataKey"}
	operationsActions = []string{"kms:Encrypt", "kms:GetKeyPolicy", "kms:DescribeKey"}
	deletionActions   = []string{"kms:ScheduleKeyDeletion"}
	recoveryActions   = []string{"kms:PutKeyPolicy", "kms:GetKeyPolicy", "kms:DescribeKey"}
)

// KMSPolicy gates Decrypt and GenerateDataKey on one PCR0, with optional root recovery.
type KMSPolicy struct {
	Version    string
	attested   *kmsPolicyStatement
	operations *kmsPolicyStatement
	deletion   *kmsPolicyStatement
	recovery   *kmsPolicyStatement // nil when locked
}

// NewKMSPolicy builds a caller-role policy; empty recoveryARN disables recovery.
func NewKMSPolicy(callerARN, pcr0, recoveryARN string) (*KMSPolicy, error) {
	role, err := assumedRoleARNToRoleARN(callerARN)
	if err != nil {
		return nil, fmt.Errorf("invalid role ARN: %w", err)
	}
	if strings.TrimSpace(pcr0) == "" {
		return nil, fmt.Errorf("empty PCR0")
	}

	condition := &kmsPolicyConditions{}
	condition.StringEqualsIgnoreCase.PCR0 = policyStrings{strings.ToLower(pcr0)}

	policy := &KMSPolicy{
		Version: kmsPolicyVersion,
		attested: newKMSPolicyStatement(
			"EnclaveAttestedOperations",
			role,
			attestedActions,
			condition,
		),
		operations: newKMSPolicyStatement("EnclaveOperations", role, operationsActions, nil),
		deletion:   newKMSPolicyStatement("AllowKeyDeletion", role, deletionActions, nil),
	}
	if recoveryARN != "" {
		account, err := arnAccount(recoveryARN)
		if err != nil {
			return nil, fmt.Errorf("invalid recovery account ARN: %w", err)
		}
		policy.recovery = newKMSPolicyStatement(
			"RootRecovery",
			"arn:aws:iam::"+account+":root",
			recoveryActions,
			nil,
		)
	}
	return policy, nil
}

// ParseAndVerifyKMSPolicy checks expected permissions; requireLocked forbids recovery.
func ParseAndVerifyKMSPolicy(raw, callerARN, pcr0 string, requireLocked bool) (*KMSPolicy, error) {
	recoveryARN := ""
	if !requireLocked {
		recoveryARN = callerARN
	}
	want, err := NewKMSPolicy(callerARN, pcr0, recoveryARN)
	if err != nil {
		return nil, err
	}
	return decodeKMSPolicy(raw, want, requireLocked)
}

func decodeKMSPolicy(raw string, want *KMSPolicy, requireLocked bool) (*KMSPolicy, error) {
	version, statements, err := decodeKMSPolicyDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("parse KMS key policy: %w", err)
	}
	policy := &KMSPolicy{Version: version}
	for i, rawStatement := range statements {
		checker := json.NewDecoder(bytes.NewReader(rawStatement))
		if err := validatePolicyJSONSyntax(checker); err != nil {
			return nil, fmt.Errorf("statement %d: %w", i, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(rawStatement))
		decoder.DisallowUnknownFields()
		stmt := &kmsPolicyStatement{}
		if err := decoder.Decode(stmt); err != nil {
			return nil, fmt.Errorf("statement %d: %w", i, err)
		}
		if err := stmt.normalize(); err != nil {
			return nil, fmt.Errorf("statement %d: %w", i, err)
		}
		var slot **kmsPolicyStatement
		switch {
		case sameActions(stmt.Action, attestedActions):
			if want != nil {
				if err := stmt.verifyStatement(want.attested); err != nil {
					return nil, fmt.Errorf("attested statement: %w", err)
				}
			}
			slot = &policy.attested
		case sameActions(stmt.Action, operationsActions):
			if want != nil {
				if err := stmt.verifyStatement(want.operations); err != nil {
					return nil, fmt.Errorf("operations statement: %w", err)
				}
			}
			slot = &policy.operations
		case sameActions(stmt.Action, deletionActions):
			if want != nil {
				if err := stmt.verifyStatement(want.deletion); err != nil {
					return nil, fmt.Errorf("deletion statement: %w", err)
				}
			}
			slot = &policy.deletion
		case sameActions(stmt.Action, recoveryActions):
			if requireLocked {
				return nil, fmt.Errorf("locked policy cannot permit recovery")
			}
			if want != nil {
				if err := stmt.verifyStatement(want.recovery); err != nil {
					return nil, fmt.Errorf("recovery statement: %w", err)
				}
			}
			slot = &policy.recovery
		default:
			return nil, fmt.Errorf("unexpected statement with actions %v", stmt.Action)
		}
		if *slot != nil {
			return nil, fmt.Errorf("duplicate statement with actions %v", stmt.Action)
		}
		*slot = stmt
	}
	if err := policy.validateStructure(); err != nil {
		return nil, err
	}
	return policy, nil
}

// Locked reports whether root recovery is absent, without verifying permissions.
func (p *KMSPolicy) Locked() bool {
	return p.recovery == nil
}

// Encode returns the KMS policy JSON.
func (p *KMSPolicy) Encode() (string, error) {
	if err := p.validateStructure(); err != nil {
		return "", err
	}
	doc := struct {
		Version   string                `json:"Version"`
		Statement []*kmsPolicyStatement `json:"Statement"`
	}{
		Version:   p.Version,
		Statement: []*kmsPolicyStatement{p.attested, p.operations, p.deletion},
	}
	if !p.Locked() {
		doc.Statement = append(doc.Statement, p.recovery)
	}
	policy, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	return string(policy), nil
}

// Verify checks caller and PCR0 permissions; requireLocked forbids recovery.
func (p *KMSPolicy) Verify(callerARN, pcr0 string, requireLocked bool) error {
	if err := p.validateStructure(); err != nil {
		return err
	}
	raw, err := p.Encode()
	if err != nil {
		return err
	}
	_, err = ParseAndVerifyKMSPolicy(raw, callerARN, pcr0, requireLocked)
	return err
}

func (p *KMSPolicy) validateStructure() error {
	if p == nil {
		return fmt.Errorf("nil KMS policy")
	}
	if p.Version != kmsPolicyVersion {
		return fmt.Errorf("unsupported policy version %q", p.Version)
	}
	for _, slot := range []struct {
		name      string
		statement *kmsPolicyStatement
	}{
		{"attested operations", p.attested},
		{"enclave operations", p.operations},
		{"key deletion", p.deletion},
	} {
		if slot.statement == nil {
			return fmt.Errorf("missing %s statement", slot.name)
		}
	}
	return nil
}

type kmsPolicyStatement struct {
	Sid       string `json:"Sid"`
	Effect    string `json:"Effect"`
	Principal struct {
		AWS policyStrings `json:"AWS"`
	} `json:"Principal"`
	Action    policyStrings        `json:"Action"`
	Resource  policyStrings        `json:"Resource"`
	Condition *kmsPolicyConditions `json:"Condition,omitempty"`
}

type kmsPolicyConditions struct {
	StringEqualsIgnoreCase struct {
		PCR0 policyStrings `json:"kms:RecipientAttestation:PCR0"`
	} `json:"StringEqualsIgnoreCase"`
}

// verifyStatement compares permissions, ignoring Sid.
func (stmt *kmsPolicyStatement) verifyStatement(want *kmsPolicyStatement) error {
	if stmt.Effect != want.Effect {
		return fmt.Errorf("effect does not match")
	}
	if !slices.Equal(stmt.Principal.AWS, want.Principal.AWS) {
		return fmt.Errorf("principal does not match caller identity or caller account")
	}
	if !sameActions(stmt.Action, want.Action) {
		return fmt.Errorf("actions do not match")
	}
	if !slices.Equal(stmt.Resource, want.Resource) {
		return fmt.Errorf("resource does not match")
	}
	if want.Condition == nil {
		if stmt.Condition != nil {
			return fmt.Errorf("unexpected condition")
		}
		return nil
	}
	if stmt.Condition == nil {
		return fmt.Errorf("missing attestation condition")
	}
	if !sameActions(
		stmt.Condition.StringEqualsIgnoreCase.PCR0,
		want.Condition.StringEqualsIgnoreCase.PCR0,
	) {
		return fmt.Errorf("PCR0 does not match")
	}
	return nil
}

func (stmt *kmsPolicyStatement) normalize() error {
	for _, action := range stmt.Action {
		for i := 0; i < len(action); i++ {
			if action[i] >= 0x80 {
				return fmt.Errorf("non-ASCII action %q is unsupported", action)
			}
		}
	}
	if err := stmt.Action.normalize(true); err != nil {
		return fmt.Errorf("action: %w", err)
	}
	if err := stmt.Resource.normalize(false); err != nil {
		return fmt.Errorf("resource: %w", err)
	}
	if len(stmt.Resource) != 1 {
		return fmt.Errorf("expected one resource per statement")
	}
	if err := stmt.Principal.AWS.normalize(false); err != nil {
		return fmt.Errorf("principal: %w", err)
	}
	if len(stmt.Principal.AWS) != 1 {
		return fmt.Errorf("expected one principal per statement")
	}
	for _, action := range stmt.Action {
		if strings.ContainsAny(action, "*?") {
			return fmt.Errorf("wildcard action %q is unsupported", action)
		}
	}
	if strings.ContainsAny(stmt.Principal.AWS[0], "*?") {
		return fmt.Errorf("wildcard principal is unsupported")
	}
	if stmt.Condition != nil {
		if err := stmt.Condition.StringEqualsIgnoreCase.PCR0.normalize(true); err != nil {
			return fmt.Errorf("PCR0: %w", err)
		}
		if len(stmt.Condition.StringEqualsIgnoreCase.PCR0) != 1 {
			return fmt.Errorf("expected exactly one PCR0")
		}
	}
	return nil
}

type policyStrings []string

func (values *policyStrings) UnmarshalJSON(raw []byte) error {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		*values = policyStrings{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return fmt.Errorf("expected a string or string array: %w", err)
	}
	*values = many
	return nil
}

func (values *policyStrings) normalize(foldCase bool) error {
	if len(*values) == 0 {
		return fmt.Errorf("empty or missing string set")
	}
	for i, value := range *values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("empty string value")
		}
		if foldCase {
			(*values)[i] = strings.ToLower(value)
		}
	}
	slices.Sort(*values)
	*values = slices.Compact(*values)
	return nil
}

func newKMSPolicyStatement(
	sid, principal string,
	actions []string,
	condition *kmsPolicyConditions,
) *kmsPolicyStatement {
	stmt := &kmsPolicyStatement{
		Sid:       sid,
		Effect:    "Allow",
		Action:    slices.Clone(actions),
		Resource:  policyStrings{"*"},
		Condition: condition,
	}
	stmt.Principal.AWS = policyStrings{principal}
	return stmt
}

// decodeKMSPolicyDocument validates the envelope and returns raw statements.
func decodeKMSPolicyDocument(raw string) (string, []json.RawMessage, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return "", nil, err
	}
	if token != json.Delim('{') {
		return "", nil, fmt.Errorf("expected policy object")
	}
	var version string
	var statements []json.RawMessage
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return "", nil, err
		}
		key, ok := token.(string)
		if !ok {
			return "", nil, fmt.Errorf("invalid object key")
		}
		if seen[key] {
			return "", nil, fmt.Errorf("duplicate JSON key %q", key)
		}
		seen[key] = true
		if key != "Version" && key != "Statement" {
			return "", nil, fmt.Errorf("unsupported policy field %q", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return "", nil, err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return "", nil, fmt.Errorf("null policy values are unsupported")
		}
		switch key {
		case "Version":
			if err := json.Unmarshal(value, &version); err != nil {
				return "", nil, err
			}
		case "Statement":
			if err := json.Unmarshal(value, &statements); err != nil {
				return "", nil, err
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return "", nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return "", nil, fmt.Errorf("unexpected trailing JSON")
	}
	return version, statements, nil
}

// sameActions compares duplicate-free action sets, ignoring case.
func sameActions(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, action := range want {
		if !slices.ContainsFunc(got, func(g string) bool { return strings.EqualFold(g, action) }) {
			return false
		}
	}
	return true
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

// validatePolicyJSONSyntax rejects duplicate keys, nulls, and unsupported field names.
func validatePolicyJSONSyntax(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("null policy values are unsupported")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	keys := map[string]bool{}
	for d.More() {
		if delim == '{' {
			token, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return fmt.Errorf("invalid object key")
			}
			if keys[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[key] = true
			// Require exact field names; encoding/json also accepts case variants.
			switch key {
			case "Version", "Statement", "Sid", "Effect", "Principal", "AWS",
				"Action", "Resource", "Condition", "StringEqualsIgnoreCase",
				"kms:RecipientAttestation:PCR0":
			default:
				return fmt.Errorf("unsupported policy field %q", key)
			}
		}
		if err := validatePolicyJSONSyntax(d); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}
