package runtime

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	testRoleARN         = "arn:aws:iam::123456789012:role/ec2"
	testAssumedRoleARN  = "arn:aws:sts::123456789012:assumed-role/ec2/i-abc123"
	testRecoveryRootARN = "arn:aws:iam::123456789012:root"
)

func TestBuildKMSPolicy_LockedGolden(t *testing.T) {
	const pcr0 = "abc123"
	got := mustBuildKMSPolicy(t, testRoleARN, []string{pcr0}, "")

	want := `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnclaveAttestedOperations",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/ec2"
      },
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
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
        "AWS": "arn:aws:iam::123456789012:role/ec2"
      },
      "Action": [
        "kms:Encrypt",
        "kms:GetKeyPolicy",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyDeletion",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/ec2"
      },
      "Action": [
        "kms:ScheduleKeyDeletion"
      ],
      "Resource": "*"
    }
  ]
}`

	require.JSONEq(t, want, got)
}

func TestBuildKMSPolicy_RecoveryMultiPCR0Golden(t *testing.T) {
	got := mustBuildKMSPolicy(
		t,
		testAssumedRoleARN,
		[]string{"oldpcr0", "newpcr0"},
		testAssumedRoleARN,
	)

	want := `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnclaveAttestedOperations",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/ec2"
      },
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": [
            "oldpcr0",
            "newpcr0"
          ]
        }
      }
    },
    {
      "Sid": "EnclaveOperations",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/ec2"
      },
      "Action": [
        "kms:Encrypt",
        "kms:GetKeyPolicy",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyDeletion",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/ec2"
      },
      "Action": [
        "kms:ScheduleKeyDeletion"
      ],
      "Resource": "*"
    },
    {
      "Sid": "RootRecovery",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": [
        "kms:PutKeyPolicy",
        "kms:GetKeyPolicy",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}`

	require.JSONEq(t, want, got)
}

func TestBuildKMSPolicy_InvalidInputs(t *testing.T) {
	_, err := BuildKMSPolicy("not-an-arn", []string{"abc123"}, "")
	require.Error(t, err)

	_, err = BuildKMSPolicy(testRoleARN, []string{"abc123"}, "123456789012")
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

func TestVerifyKeyPolicyPosture_BuiltPolicies(t *testing.T) {
	pcr0 := strings.Repeat("a", 96)
	otherPCR0 := strings.Repeat("b", 96)

	locked := mustBuildKMSPolicy(t, testRoleARN, []string{pcr0}, "")
	unlocked := mustBuildKMSPolicy(t, testRoleARN, []string{pcr0}, testRecoveryRootARN)
	migration := mustBuildKMSPolicy(t, testRoleARN, []string{otherPCR0, pcr0}, "")
	migrationUnlocked := mustBuildKMSPolicy(
		t,
		testRoleARN,
		[]string{otherPCR0, pcr0},
		testRecoveryRootARN,
	)

	require.NoError(t, VerifyKeyPolicyPosture(locked, []string{pcr0}, true))
	require.NoError(t, VerifyKeyPolicyPosture(unlocked, []string{pcr0}, false))
	require.NoError(t, VerifyKeyPolicyPosture(migration, []string{otherPCR0, pcr0}, true))
	require.NoError(t, VerifyKeyPolicyPosture(migrationUnlocked, []string{otherPCR0, pcr0}, false))
	require.NoError(t, VerifyKeyPolicyPosture(locked, []string{pcr0}, false))
	require.Error(t, VerifyKeyPolicyPosture(unlocked, []string{pcr0}, true))
}

// Adding kms:DescribeKey to EnclaveOperations must not fork the fleet: a new
// runtime has to keep adopting keys minted before the action existed, and an old
// runtime has to keep adopting keys minted after it. Both inspectors read only
// kms:Decrypt and kms:PutKeyPolicy, so neither ever sees DescribeKey.
func TestVerifyKeyPolicyPostureIgnoresDescribeKey(t *testing.T) {
	legacyOps := ppAllow([]string{"kms:Encrypt", "kms:GetKeyPolicy"}, ppRole, nil)

	for _, tc := range []struct {
		name string
		ops  map[string]any
	}{
		{"key minted before DescribeKey was granted", legacyOps},
		{"key minted after DescribeKey was granted", ppOps()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := ppPolicy(t, ppDecryptGated(ppPCR0), tc.ops, ppDelete())

			require.NoError(t, VerifyKeyPolicyPosture(policy, []string{ppPCR0}, true))

			admitted, err := KeyPolicyAdmittedPCR0s(policy)
			require.NoError(t, err)
			require.True(t, admitted[ppPCR0])
		})
	}
}

func TestVerifyKeyPolicyPosture_Table(t *testing.T) {
	lowerEffectDecrypt := ppStmt("allow", "kms:Decrypt", ppRole, ppPCR0Cond(ppPCR0))

	cases := []struct {
		name          string
		policy        string
		expectedPCR0s []string
		locked        bool
		wantErr       bool
		errSubstr     string
	}{
		{
			name:          "genuine locked exact PCR0 set",
			policy:        ppPolicy(t, ppDecryptGated(ppPCR0), ppOps(), ppDelete()),
			expectedPCR0s: []string{ppPCR0}, locked: true,
		},
		{
			name: "genuine unlocked exact PCR0 set",
			policy: ppPolicy(
				t,
				ppDecryptGated(ppPCR0),
				ppOps(),
				ppDelete(),
				ppRootRecovery(ppRoot),
			),
			expectedPCR0s: []string{ppPCR0}, locked: false,
		},
		{
			name: "migration exact PCR0 set",
			policy: ppPolicy(
				t,
				ppDecryptGated([]string{ppOther, ppPCR0}),
				ppOps(),
				ppDelete(),
			),
			expectedPCR0s: []string{ppPCR0, ppOther}, locked: true,
		},
		{
			name:          "unexpected extra PCR0 rejected",
			policy:        ppPolicy(t, ppDecryptGated([]string{ppPCR0, ppOther}), ppOps()),
			expectedPCR0s: []string{ppPCR0}, locked: true, wantErr: true, errSubstr: "PCR0 set",
		},
		{
			name:   "missing migration predecessor PCR0 rejected",
			policy: ppPolicy(t, ppDecryptGated(ppPCR0), ppOps()),
			expectedPCR0s: []string{
				ppPCR0,
				ppOther,
			}, locked: true, wantErr: true, errSubstr: "PCR0 set",
		},
		{
			name:          "PCR0 set match is case-insensitive",
			policy:        ppPolicy(t, ppDecryptGated(strings.ToLower(ppPCR0)), ppOps()),
			expectedPCR0s: []string{strings.ToUpper(ppPCR0)}, locked: true,
		},
		{
			name:          "lowercase Effect 'allow' still counts",
			policy:        ppPolicy(t, lowerEffectDecrypt, ppOps()),
			expectedPCR0s: []string{ppPCR0}, locked: true,
		},
		{
			name:          "split gated Decrypt statements exact set",
			policy:        ppPolicy(t, ppDecryptGated(ppOther), ppDecryptGated(ppPCR0), ppOps()),
			expectedPCR0s: []string{ppPCR0, ppOther}, locked: true,
		},
		{
			name:          "split gated Decrypt statements exact set reversed",
			policy:        ppPolicy(t, ppDecryptGated(ppPCR0), ppDecryptGated(ppOther), ppOps()),
			expectedPCR0s: []string{ppPCR0, ppOther}, locked: true,
		},
		{
			name: "Deny on Decrypt is ignored",
			policy: ppPolicy(
				t,
				ppDecryptGated(ppPCR0),
				ppStmt("Deny", "kms:Decrypt", "*", nil),
				ppOps(),
			),
			expectedPCR0s: []string{ppPCR0}, locked: true,
		},
		{
			name: "Deny on PutKeyPolicy is ignored even when locked",
			policy: ppPolicy(
				t,
				ppDecryptGated(ppPCR0),
				ppStmt("Deny", "kms:PutKeyPolicy", ppRole, nil),
				ppOps(),
			),
			expectedPCR0s: []string{ppPCR0}, locked: true,
		},
		{
			name:          "RootRecovery principal as array of root ARNs",
			policy:        ppPolicy(t, ppDecryptGated(ppPCR0), ppRootRecovery([]string{ppRoot})),
			expectedPCR0s: []string{ppPCR0}, locked: false,
		},
		{
			name: "empty policy", policy: "", expectedPCR0s: []string{ppPCR0}, locked: true,
			wantErr: true, errSubstr: "empty",
		},
		{
			name:          "malformed JSON",
			policy:        "{not json",
			expectedPCR0s: []string{ppPCR0},
			locked:        true,
			wantErr:       true,
			errSubstr:     "parse",
		},
		{
			name:          "no statements",
			policy:        ppPolicy(t),
			expectedPCR0s: []string{ppPCR0},
			locked:        true,
			wantErr:       true,
			errSubstr:     "PCR0 set",
		},
		{
			name:          "no Decrypt statement at all",
			policy:        ppPolicy(t, ppOps(), ppDelete()),
			expectedPCR0s: []string{ppPCR0}, locked: true, wantErr: true, errSubstr: "PCR0 set",
		},
		{
			name:   "Decrypt with no condition",
			policy: ppPolicy(t, ppAllow("kms:Decrypt", ppRole, nil), ppOps()),
			expectedPCR0s: []string{
				ppPCR0,
			}, locked: true, wantErr: true, errSubstr: "without a RecipientAttestation:PCR0",
		},
		{
			name: "Decrypt with a non-PCR0 condition",
			policy: ppPolicy(
				t,
				ppAllow(
					"kms:Decrypt",
					ppRole,
					map[string]any{"StringEquals": map[string]any{"aws:SourceVpc": "vpc-1"}},
				),
				ppOps(),
			),
			expectedPCR0s: []string{
				ppPCR0,
			}, locked: true, wantErr: true, errSubstr: "without a RecipientAttestation:PCR0",
		},
		{
			name:          "Decrypt gated to a different PCR0 only",
			policy:        ppPolicy(t, ppDecryptGated(ppOther), ppOps()),
			expectedPCR0s: []string{ppPCR0}, locked: true, wantErr: true, errSubstr: "PCR0 set",
		},
		{
			name:   "wildcard kms:* without condition is an un-gated Decrypt",
			policy: ppPolicy(t, ppAllow("kms:*", ppRole, nil)),
			expectedPCR0s: []string{
				ppPCR0,
			}, locked: true, wantErr: true, errSubstr: "without a RecipientAttestation:PCR0",
		},
		{
			name:   "wildcard * without condition is an un-gated Decrypt",
			policy: ppPolicy(t, ppAllow("*", ppRole, nil)),
			expectedPCR0s: []string{
				ppPCR0,
			}, locked: true, wantErr: true, errSubstr: "without a RecipientAttestation:PCR0",
		},
		{
			name:   "un-gated Decrypt rejected even when another statement admits ours",
			policy: ppPolicy(t, ppDecryptGated(ppPCR0), ppAllow("kms:Decrypt", ppRole, nil)),
			expectedPCR0s: []string{
				ppPCR0,
			}, locked: true, wantErr: true, errSubstr: "without a RecipientAttestation:PCR0",
		},
		{
			name:          "locked mode rejects any PutKeyPolicy even to root",
			policy:        ppPolicy(t, ppDecryptGated(ppPCR0), ppRootRecovery(ppRoot)),
			expectedPCR0s: []string{ppPCR0}, locked: true, wantErr: true, errSubstr: "immutable",
		},
		{
			name: "locked mode rejects PutKeyPolicy to the enclave role",
			policy: ppPolicy(
				t,
				ppDecryptGated(ppPCR0),
				ppAllow("kms:PutKeyPolicy", ppRole, nil),
			),
			expectedPCR0s: []string{ppPCR0}, locked: true, wantErr: true, errSubstr: "immutable",
		},
		{
			name: "unlocked: PutKeyPolicy to the enclave role rejected",
			policy: ppPolicy(
				t,
				ppDecryptGated(ppPCR0),
				ppAllow("kms:PutKeyPolicy", ppRole, nil),
			),
			expectedPCR0s: []string{ppPCR0}, locked: false, wantErr: true, errSubstr: "non-root",
		},
		{
			name: "unlocked: PutKeyPolicy to wildcard principal rejected",
			policy: ppPolicy(
				t,
				ppDecryptGated(ppPCR0),
				ppAllow("kms:PutKeyPolicy", "*", nil),
			),
			expectedPCR0s: []string{ppPCR0}, locked: false, wantErr: true, errSubstr: "non-root",
		},
		{
			name: "unlocked: PutKeyPolicy to mixed root+role principals rejected",
			policy: ppPolicy(
				t,
				ppDecryptGated(ppPCR0),
				ppAllow("kms:PutKeyPolicy", []string{ppRoot, ppRole}, nil),
			),
			expectedPCR0s: []string{ppPCR0}, locked: false, wantErr: true, errSubstr: "non-root",
		},
		{
			name:          "locked: kms:* to root rejected via the PutKeyPolicy path",
			policy:        ppPolicy(t, ppAllow("kms:*", ppRoot, ppPCR0Cond(ppPCR0))),
			expectedPCR0s: []string{ppPCR0}, locked: true, wantErr: true, errSubstr: "immutable",
		},
		{
			name:          "PutKeyPolicy to root is fine but missing Decrypt still fails",
			policy:        ppPolicy(t, ppRootRecovery(ppRoot)),
			expectedPCR0s: []string{ppPCR0}, locked: false, wantErr: true, errSubstr: "PCR0 set",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyKeyPolicyPosture(tc.policy, tc.expectedPCR0s, tc.locked)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errSubstr != "" {
					require.Contains(t, err.Error(), tc.errSubstr)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestNormalizePolicyStrings(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", ``, nil},
		{"single string", `"kms:Decrypt"`, []string{"kms:Decrypt"}},
		{"array", `["a","b"]`, []string{"a", "b"}},
		{"empty array", `[]`, []string{}},
		{"number is neither", `123`, nil},
		{"object is neither", `{"x":1}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var raw json.RawMessage
			if tc.raw != "" {
				raw = json.RawMessage(tc.raw)
			}
			got := normalizePolicyStrings(raw)
			require.Len(
				t,
				got,
				len(tc.want),
				"normalizePolicyStrings(%s) = %v, want %v",
				tc.raw,
				got,
				tc.want,
			)
			for i := range got {
				require.Equal(t, tc.want[i], got[i], "normalizePolicyStrings(%s)[%d]", tc.raw, i)
			}
		})
	}
}

func TestActionsGrant(t *testing.T) {
	cases := []struct {
		name    string
		actions []string
		want    string
		grant   bool
	}{
		{"exact", []string{"kms:Decrypt"}, "kms:Decrypt", true},
		{"case-insensitive", []string{"KMS:DECRYPT"}, "kms:Decrypt", true},
		{"absent", []string{"kms:Encrypt"}, "kms:Decrypt", false},
		{"kms wildcard", []string{"kms:*"}, "kms:Decrypt", true},
		{"kms wildcard grants PutKeyPolicy", []string{"kms:*"}, "kms:PutKeyPolicy", true},
		{"full wildcard", []string{"*"}, "kms:PutKeyPolicy", true},
		{"empty", nil, "kms:Decrypt", false},
		{"among many", []string{"kms:Encrypt", "kms:Decrypt"}, "kms:Decrypt", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.grant, actionsGrant(tc.actions, tc.want))
		})
	}
}

func TestPrincipalsAllRoot(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"single root", `{"AWS":"arn:aws:iam::111122223333:root"}`, true},
		{"array of roots", `{"AWS":["arn:aws:iam::1:root","arn:aws:iam::2:root"]}`, true},
		{"mixed root and role", `{"AWS":["arn:aws:iam::1:root","arn:aws:iam::1:role/x"]}`, false},
		{"single role", `{"AWS":"arn:aws:iam::1:role/x"}`, false},
		{"wildcard", `{"AWS":"*"}`, false},
		{"no AWS key", `{"Service":"kms.amazonaws.com"}`, false},
		{"empty object", `{}`, false},
		{"principal is a bare string", `"*"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, principalsAllRoot(json.RawMessage(tc.raw)))
		})
	}
}

func TestPCR0ConditionValues(t *testing.T) {
	mustCond := func(s string) map[string]interface{} {
		var m map[string]interface{}
		err := json.Unmarshal([]byte(s), &m)
		require.NoError(t, err)
		return m
	}

	cases := []struct {
		name   string
		cond   map[string]interface{}
		want   []string
		wantOK bool
	}{
		{"nil condition", nil, nil, false},
		{"no PCR0 condition", mustCond(`{"StringEquals":{"aws:SourceVpc":"vpc-1"}}`), nil, false},
		{
			"string",
			mustCond(`{"StringEqualsIgnoreCase":{"kms:RecipientAttestation:PCR0":"abc"}}`),
			[]string{"abc"},
			true,
		},
		{
			"array",
			mustCond(`{"StringEqualsIgnoreCase":{"kms:RecipientAttestation:PCR0":["xyz","abc"]}}`),
			[]string{"xyz", "abc"},
			true,
		},
		{
			"empty string",
			mustCond(`{"StringEqualsIgnoreCase":{"kms:RecipientAttestation:PCR0":""}}`),
			nil,
			false,
		},
		{
			"empty array",
			mustCond(`{"StringEqualsIgnoreCase":{"kms:RecipientAttestation:PCR0":[]}}`),
			nil,
			false,
		},
		{
			"non-string array member",
			mustCond(`{"StringEqualsIgnoreCase":{"kms:RecipientAttestation:PCR0":["abc",123]}}`),
			nil,
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotOK := pcr0ConditionValues(tc.cond)
			require.Equal(t, tc.wantOK, gotOK)
			require.Len(t, got, len(tc.want))
			for i := range got {
				require.Equal(t, tc.want[i], got[i])
			}
		})
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

func ppDecryptGated(pcr0 any) map[string]any {
	return ppAllow("kms:Decrypt", ppRole, ppPCR0Cond(pcr0))
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

func mustBuildKMSPolicy(t *testing.T, roleARN string, pcr0s []string, recoveryARN string) string {
	t.Helper()
	policy, err := BuildKMSPolicy(roleARN, pcr0s, recoveryARN)
	require.NoError(t, err)
	return policy
}
