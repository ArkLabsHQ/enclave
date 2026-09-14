package runtime

import (
	"encoding/json"
	"strings"
	"testing"

	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/stretchr/testify/require"
)

const (
	testRoleARN         = "arn:aws:iam::123456789012:role/ec2"
	testAssumedRoleARN  = "arn:aws:sts::123456789012:assumed-role/ec2/i-abc123"
	testRecoveryRootARN = "arn:aws:iam::123456789012:root"
)

func TestBuildKMSPolicy_LockedGolden(t *testing.T) {
	const pcr0 = "abc123"
	got := mustBuildKMSPolicy(t, testRoleARN, pcr0, "")

	want := `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnclaveAttestedOperations",
      "Effect": "Allow",
      "Principal": {
        "AWS": ["arn:aws:iam::123456789012:role/ec2"]
      },
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": ["*"],
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": [
            "abc123"
          ]
        }
      }
    },
    {
      "Sid": "EnclaveOperations",
      "Effect": "Allow",
      "Principal": {
        "AWS": ["arn:aws:iam::123456789012:role/ec2"]
      },
      "Action": [
        "kms:Encrypt",
        "kms:GetKeyPolicy",
        "kms:DescribeKey"
      ],
      "Resource": ["*"]
    },
    {
      "Sid": "AllowKeyDeletion",
      "Effect": "Allow",
      "Principal": {
        "AWS": ["arn:aws:iam::123456789012:role/ec2"]
      },
      "Action": [
        "kms:ScheduleKeyDeletion"
      ],
      "Resource": ["*"]
    }
  ]
}`

	require.JSONEq(t, want, got)
}

func TestBuildKMSPolicy_RecoveryGolden(t *testing.T) {
	got := mustBuildKMSPolicy(t, testAssumedRoleARN, "newpcr0", testAssumedRoleARN)

	want := `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnclaveAttestedOperations",
      "Effect": "Allow",
      "Principal": {
        "AWS": ["arn:aws:iam::123456789012:role/ec2"]
      },
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": ["*"],
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": [
            "newpcr0"
          ]
        }
      }
    },
    {
      "Sid": "EnclaveOperations",
      "Effect": "Allow",
      "Principal": {
        "AWS": ["arn:aws:iam::123456789012:role/ec2"]
      },
      "Action": [
        "kms:Encrypt",
        "kms:GetKeyPolicy",
        "kms:DescribeKey"
      ],
      "Resource": ["*"]
    },
    {
      "Sid": "AllowKeyDeletion",
      "Effect": "Allow",
      "Principal": {
        "AWS": ["arn:aws:iam::123456789012:role/ec2"]
      },
      "Action": [
        "kms:ScheduleKeyDeletion"
      ],
      "Resource": ["*"]
    },
    {
      "Sid": "RootRecovery",
      "Effect": "Allow",
      "Principal": {
        "AWS": ["arn:aws:iam::123456789012:root"]
      },
      "Action": [
        "kms:PutKeyPolicy",
        "kms:GetKeyPolicy",
        "kms:DescribeKey"
      ],
      "Resource": ["*"]
    }
  ]
}`

	require.JSONEq(t, want, got)
}

func TestBuildKMSPolicy_InvalidInputs(t *testing.T) {
	_, err := NewKMSPolicy("not-an-arn", "abc123", "")
	require.Error(t, err)

	_, err = NewKMSPolicy(testRoleARN, "abc123", "123456789012")
	require.Error(t, err)

	_, err = NewKMSPolicy(testRoleARN, "", "")
	require.Error(t, err)
}

// TestArnAccount verifies extraction of segment [4] from various ARN forms.
func TestArnAccount(t *testing.T) {
	cases := []struct {
		name string
		arn  string
		want string
	}{
		{"assumed-role", "arn:aws:sts::123456789012:assumed-role/MyRole/i-abc", "123456789012"},
		{"iam role", "arn:aws:iam::000000000000:role/Foo", "000000000000"},
		{"root", "arn:aws:iam::555555555555:root", "555555555555"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := arnAccount(tc.arn)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	_, err := arnAccount("not-an-arn")
	require.Error(t, err)
}

const (
	ppRole  = "arn:aws:iam::111122223333:role/enclave"
	ppRoot  = "arn:aws:iam::111122223333:root"
	ppPCR0  = "abc123def456"
	ppOther = "999888777666aaa"
)

func TestKMSPolicyVerifyPosture(t *testing.T) {
	pcr0 := strings.Repeat("a", 96)
	otherPCR0 := strings.Repeat("b", 96)

	locked := mustBuildKMSPolicy(t, testRoleARN, pcr0, "")
	unlocked := mustBuildKMSPolicy(t, testRoleARN, pcr0, testRecoveryRootARN)

	requireKeyPolicyPosture(t, locked, pcr0, true)
	requireKeyPolicyPosture(t, locked, strings.ToUpper(pcr0), true)
	requireKeyPolicyPosture(t, unlocked, pcr0, false)
	requireKeyPolicyPosture(t, locked, pcr0, false)
	require.Error(t, verifyKeyPolicyPosture(t, unlocked, pcr0, true))
	require.Error(t, verifyKeyPolicyPosture(t, locked, otherPCR0, false))
	require.Error(t, verifyKeyPolicyPosture(t, locked, "", false))
}

func TestKMSPolicyRoundTrip(t *testing.T) {
	for _, recovery := range []string{"", testRecoveryRootARN} {
		pcr0 := strings.Repeat("A", 96)
		want, err := NewKMSPolicy(testAssumedRoleARN, pcr0, recovery)
		require.NoError(t, err)
		raw, err := want.Encode()
		require.NoError(t, err)
		got := mustDecodeKMSPolicy(t, raw)
		require.Equal(t, kmsPolicyVersion, want.Version)
		require.Equal(t, want.Version, got.Version)
		require.Equal(t, recovery == "", got.Locked())
		require.Equal(t, want.attested.Sid, got.attested.Sid)
		require.NoError(t, got.Verify(testAssumedRoleARN, pcr0, recovery == ""))
	}
}

// ppPolicy assembles statements into a KMS policy JSON document.
func ppPolicy(t *testing.T, statements ...map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"Version":   "2012-10-17",
		"Statement": statements,
	})
	require.NoError(t, err)
	return string(b)
}

// ppAllow builds an Allow statement. principal/condition are omitted when nil so
// the parsed statement faithfully mirrors a real policy.
func ppAllow(action, principal any, condition map[string]any) map[string]any {
	return ppStmt("Allow", action, principal, condition)
}

func ppStmt(effect string, action, principal any, condition map[string]any) map[string]any {
	s := map[string]any{"Effect": effect, "Action": action, "Resource": "*"}
	if principal != nil {
		s["Principal"] = map[string]any{"AWS": principal}
	}
	if condition != nil {
		s["Condition"] = condition
	}
	return s
}

// ppPCR0Cond is a RecipientAttestation:PCR0 condition admitting the given
// value(s) — pass a string or a []string/[]any.
func ppPCR0Cond(values any) map[string]any {
	return map[string]any{
		"StringEqualsIgnoreCase": map[string]any{
			"kms:RecipientAttestation:PCR0": values,
		},
	}
}

func ppOps() map[string]any {
	return ppAllow([]string{"kms:Encrypt", "kms:GetKeyPolicy", "kms:DescribeKey"}, ppRole, nil)
}

func ppDelete() map[string]any {
	return ppAllow("kms:ScheduleKeyDeletion", ppRole, nil)
}

func ppRootRecovery(principal any) map[string]any {
	return ppAllow(
		[]string{"kms:PutKeyPolicy", "kms:GetKeyPolicy", "kms:DescribeKey"},
		principal,
		nil,
	)
}

func mustBuildKMSPolicy(t *testing.T, roleARN, pcr0, recoveryARN string) string {
	t.Helper()
	policy, err := NewKMSPolicy(roleARN, pcr0, recoveryARN)
	require.NoError(t, err)
	raw, err := policy.Encode()
	require.NoError(t, err)
	return raw
}

func mustDecodeKMSPolicy(t *testing.T, raw string) *KMSPolicy {
	t.Helper()
	policy, err := decodeKMSPolicy(raw, nil, false)
	require.NoError(t, err)
	return policy
}

// verifyKMSPolicy parses and checks permissions.
func verifyKMSPolicy(raw, callerARN, pcr0 string, locked bool) error {
	_, err := ParseAndVerifyKMSPolicy(raw, callerARN, pcr0, locked)
	return err
}

// verifyKeyPolicyPosture checks PCR0 and lock state using the policy's role.
func verifyKeyPolicyPosture(t *testing.T, raw, pcr0 string, locked bool) error {
	t.Helper()
	policy := mustDecodeKMSPolicy(t, raw)
	return policy.Verify(policy.attested.Principal.AWS[0], pcr0, locked)
}

func requireKeyPolicyPosture(t *testing.T, raw, pcr0 string, locked bool) {
	t.Helper()
	require.NoError(t, verifyKeyPolicyPosture(t, raw, pcr0, locked))
}

// Policy mutations must not alter permission templates.
func TestKMSPolicyActionIsolation(t *testing.T) {
	policy, err := NewKMSPolicy(testRoleARN, "abc123", testRecoveryRootARN)
	require.NoError(t, err)
	for _, stmt := range []*kmsPolicyStatement{
		policy.attested, policy.operations, policy.deletion, policy.recovery,
	} {
		stmt.Action[0] = "kms:CreateGrant"
	}
	require.Error(t, policy.Verify(testRoleARN, "abc123", false))

	fresh, err := NewKMSPolicy(testRoleARN, "abc123", testRecoveryRootARN)
	require.NoError(t, err)
	require.Equal(t, policyStrings{"kms:Decrypt", "kms:GenerateDataKey"}, fresh.attested.Action)
	require.Equal(t, policyStrings{"kms:Encrypt", "kms:GetKeyPolicy", "kms:DescribeKey"}, fresh.operations.Action)
	require.Equal(t, policyStrings{"kms:ScheduleKeyDeletion"}, fresh.deletion.Action)
	require.Equal(t, policyStrings{"kms:PutKeyPolicy", "kms:GetKeyPolicy", "kms:DescribeKey"}, fresh.recovery.Action)
	require.NoError(t, fresh.Verify(testRoleARN, "abc123", false))
}

func TestKMSPolicyIncomplete(t *testing.T) {
	for _, policy := range []*KMSPolicy{nil, {}} {
		_, err := policy.Encode()
		require.Error(t, err)
		require.Error(t, policy.Verify(testRoleARN, "abc123", true))
	}
	for _, slot := range []string{"attested", "operations", "deletion"} {
		t.Run(slot, func(t *testing.T) {
			policy, err := NewKMSPolicy(testRoleARN, "abc123", "")
			require.NoError(t, err)
			switch slot {
			case "attested":
				policy.attested = nil
			case "operations":
				policy.operations = nil
			case "deletion":
				policy.deletion = nil
			}
			_, err = policy.Encode()
			require.ErrorContains(t, err, "missing")
			require.ErrorContains(t, policy.Verify(testRoleARN, "abc123", true), "missing")
		})
	}
}

func TestKMSPolicyUnsupportedStoredVersion(t *testing.T) {
	policy, err := NewKMSPolicy(testRoleARN, "abc123", "")
	require.NoError(t, err)
	policy.Version = "2008-10-17"
	_, err = policy.Encode()
	require.ErrorContains(t, err, "unsupported policy version")
	require.ErrorContains(t, policy.Verify(testRoleARN, "abc123", true), "unsupported policy version")
}

func TestKMSPolicyStructure(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any, []any)
	}{
		{"extra data key grant", func(d map[string]any, s []any) {
			d["Statement"] = append(s, ppAllow("kms:GenerateDataKey", ppRole, nil))
		}},
		{"extra deny", func(d map[string]any, s []any) {
			d["Statement"] = append(s, ppStmt("Deny", "kms:Decrypt", ppRole, nil))
		}},
		{"missing statement", func(d map[string]any, s []any) { d["Statement"] = s[:2] }},
		{"duplicate statement", func(d map[string]any, s []any) { d["Statement"] = append(s, s[0]) }},
		{"changed principal", func(_ map[string]any, s []any) { s[1].(map[string]any)["Principal"] = map[string]any{"AWS": ppRoot} }},
		{"wildcard principal", func(_ map[string]any, s []any) { s[0].(map[string]any)["Principal"] = map[string]any{"AWS": "*"} }},
		{"wildcard in all role principals", func(_ map[string]any, s []any) {
			for _, value := range s {
				value.(map[string]any)["Principal"] = map[string]any{"AWS": "arn:aws:iam::111122223333:role/*"}
			}
		}},
		{"STS principal in all role statements", func(_ map[string]any, s []any) {
			for _, value := range s {
				value.(map[string]any)["Principal"] = map[string]any{"AWS": "arn:aws:sts::111122223333:assumed-role/enclave/session"}
			}
		}},
		{"second conditional statement", func(_ map[string]any, s []any) {
			s[1].(map[string]any)["Condition"] = ppPCR0Cond(ppPCR0)
		}},
		{"extra principal", func(_ map[string]any, s []any) {
			s[0].(map[string]any)["Principal"] = map[string]any{"AWS": []string{ppRole, ppRoot}}
		}},
		{"missing condition", func(_ map[string]any, s []any) { delete(s[0].(map[string]any), "Condition") }},
		{"extra condition", func(_ map[string]any, s []any) {
			s[0].(map[string]any)["Condition"].(map[string]any)["Bool"] = map[string]any{"aws:SecureTransport": "true"}
		}},
		{"changed operator", func(_ map[string]any, s []any) {
			s[0].(map[string]any)["Condition"] = map[string]any{"StringEquals": map[string]any{"kms:RecipientAttestation:PCR0": ppPCR0}}
		}},
		{"extra resource", func(_ map[string]any, s []any) { s[1].(map[string]any)["Resource"] = []string{"*", "other"} }},
		{"changed resource", func(_ map[string]any, s []any) { s[1].(map[string]any)["Resource"] = "other" }},
		{"missing data key action", func(_ map[string]any, s []any) { s[0].(map[string]any)["Action"] = "kms:Decrypt" }},
		{"NotAction", func(_ map[string]any, s []any) { s[1].(map[string]any)["NotAction"] = "kms:Decrypt" }},
		{"null NotAction", func(_ map[string]any, s []any) { s[1].(map[string]any)["NotAction"] = nil }},
		{"NotPrincipal", func(_ map[string]any, s []any) { s[1].(map[string]any)["NotPrincipal"] = map[string]any{"AWS": ppRoot} }},
		{"unknown field", func(d map[string]any, _ []any) { d["Unknown"] = true }},
		{"wrong version", func(d map[string]any, _ []any) { d["Version"] = "2008-10-17" }},
		{"empty action", func(_ map[string]any, s []any) { s[1].(map[string]any)["Action"] = []any{} }},
		{"null action entry", func(_ map[string]any, s []any) { s[1].(map[string]any)["Action"] = []any{nil} }},
		{"empty PCR0", func(_ map[string]any, s []any) { s[0].(map[string]any)["Condition"] = ppPCR0Cond("") }},
		{"two PCR0s", func(_ map[string]any, s []any) {
			s[0].(map[string]any)["Condition"] = ppPCR0Cond([]string{ppPCR0, ppOther})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]any
			require.NoError(t, json.Unmarshal([]byte(mustBuildKMSPolicy(t, ppRole, ppPCR0, "")), &doc))
			tc.mutate(doc, doc["Statement"].([]any))
			raw, err := json.Marshal(doc)
			require.NoError(t, err)
			require.Error(t, verifyKMSPolicy(string(raw), ppRole, ppPCR0, false))
		})
	}
	for _, action := range []string{"kms:Dec*", "kms:Put*", "kms:Decryp?", "KMS:*", "*", "kms:CreateGrant"} {
		for _, array := range []bool{false, true} {
			t.Run(action+map[bool]string{false: "/string", true: "/array"}[array], func(t *testing.T) {
				var value any = action
				if array {
					value = []string{action}
				}
				raw := ppPolicy(t, ppAllow([]string{"kms:Decrypt", "kms:GenerateDataKey"}, ppRole, ppPCR0Cond(ppPCR0)), ppOps(), ppDelete(), ppAllow(value, ppRoot, nil))
				require.Error(t, verifyKMSPolicy(raw, ppRole, ppPCR0, false))
			})
		}
	}
}

func TestKMSPolicyNormalization(t *testing.T) {
	raw := ppPolicy(t,
		ppRootRecovery([]string{ppRoot}),
		ppDelete(),
		ppAllow([]string{"KMS:DescribeKey", "kms:GetKeyPolicy", "kms:Encrypt", "kms:Encrypt"}, []string{ppRole}, nil),
		ppAllow([]string{"kms:GenerateDataKey", "KMS:Decrypt"}, ppRole, ppPCR0Cond([]string{strings.ToUpper(ppPCR0), ppPCR0})),
	)
	policy := mustDecodeKMSPolicy(t, raw)
	require.Equal(t, ppPCR0, policy.attested.Condition.StringEqualsIgnoreCase.PCR0[0])
	require.Equal(t, ppRoot, policy.recovery.Principal.AWS[0])
	require.NoError(t, policy.Verify(ppRole, ppPCR0, false))
	require.Error(t, policy.Verify(ppRole, ppOther, false))
	require.Error(t, policy.Verify(ppRole, ppPCR0, true))
	require.Error(t, policy.Verify(ppRole, "", false))
}

func TestKMSPolicyStrictJSON(t *testing.T) {
	valid := mustBuildKMSPolicy(t, ppRole, ppPCR0, "")
	for _, raw := range []string{
		"", "null", "{", valid + "{}",
		strings.Replace(valid, `"Effect":"Allow"`, `"Effect":"Deny","Effect":"Allow"`, 1),
		strings.Replace(valid, `"Version":"2012-10-17"`, `"Version":"2012-10-17","Version":"2012-10-17"`, 1),
		strings.Replace(valid, `"Statement":`, `"Statement":[],"Statement":`, 1),
		strings.Replace(valid, `"Version":"2012-10-17"`, `"Version":null`, 1),
		`{"Version":"2012-10-17","Statement":null}`,
		`{"Version":"2012-10-17","Statement":[null]}`,
		strings.Replace(valid, `"Action":`, `"action":`, 1),
		strings.Replace(valid, `"Effect":"Allow"`, `"Effect":null`, 1),
		strings.Replace(valid, `"Sid":"EnclaveOperations"`, `"Sid":null`, 1),
		strings.Replace(valid, `"Sid":"EnclaveOperations"`, `"Condition":null`, 1),
		strings.Replace(valid, `"Sid":"EnclaveOperations"`, `"Condition":{}`, 1),
		strings.Replace(valid, `"Version":`, `"Action":"kms:Encrypt","Version":`, 1),
		strings.Replace(valid, `"AWS":`, `"Version":"2012-10-17","AWS":`, 1),
		strings.Replace(valid, `"kms:Decrypt"`, `"kms:Decrypt",null`, 1),
		strings.Replace(valid, `"kms:RecipientAttestation:PCR0":`, `"kms:recipientattestation:pcr0":`, 1),
	} {
		require.Error(t, verifyKMSPolicy(raw, ppRole, ppPCR0, false), raw)
	}
}

func TestKMSPolicyIdentity(t *testing.T) {
	raw := mustBuildKMSPolicy(t, ppRole, ppPCR0, ppRoot)
	policy := mustDecodeKMSPolicy(t, raw)
	require.NoError(t, policy.Verify(ppRole, ppPCR0, false))
	require.NoError(t, policy.Verify("arn:aws:sts::111122223333:assumed-role/enclave/session", ppPCR0, false))
	require.ErrorContains(t, policy.Verify("arn:aws:iam::111122223333:role/other", ppPCR0, false), "caller identity")
	otherRecovery := mustBuildKMSPolicy(t, ppRole, ppPCR0, "arn:aws:iam::000000000000:root")
	require.ErrorContains(t, verifyKMSPolicy(otherRecovery, ppRole, ppPCR0, false), "caller account")
}

func TestKMSPolicyRepresentation(t *testing.T) {
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(mustBuildKMSPolicy(t, ppRole, ppPCR0, "")), &doc))
	statements := doc["Statement"].([]any)
	for _, value := range statements {
		stmt := value.(map[string]any)
		stmt["Sid"] = "Renamed"
		stmt["Resource"] = []string{"*"}
	}
	statements[0].(map[string]any)["Condition"] = ppPCR0Cond(ppPCR0)
	raw, err := json.MarshalIndent(doc, "", "  ")
	require.NoError(t, err)
	requireKeyPolicyPosture(t, string(raw), ppPCR0, true)
}

func TestKMSPolicyRejectsNonASCIIActions(t *testing.T) {
	valid := mustBuildKMSPolicy(t, testRoleARN, "abc123", "")
	for _, action := range []string{"Kms:Decrypt", "kmſ:Decrypt", "kms:Décrypt"} {
		t.Run(action, func(t *testing.T) {
			raw := strings.Replace(valid, "kms:Decrypt", action, 1)
			_, err := ParseAndVerifyKMSPolicy(raw, testRoleARN, "abc123", true)
			require.ErrorContains(t, err, "non-ASCII action")
		})
	}
}

func TestFakeKMSRejectsMissingAttestationCondition(t *testing.T) {
	policy, err := NewKMSPolicy(testRoleARN, "abc123", "")
	require.NoError(t, err)
	policy.attested.Condition = nil
	raw, err := policy.Encode()
	require.NoError(t, err)
	fake := newFakeKMS()
	fake.putKey("key-no-condition", raw)
	doc, _, err := kmsTestNSMWithRecipient(t).BuildAttestationDocument(WithPublicKey())
	require.NoError(t, err)
	err = fake.authorizeAttested("key-no-condition", &kmstypes.RecipientInfo{AttestationDocument: doc})
	require.ErrorContains(t, err, "AccessDeniedException")
	require.ErrorContains(t, err, "lacks an attestation condition")
}
