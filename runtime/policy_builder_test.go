package runtime

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestPolicyAdmitsPCR0_Empty verifies an empty policy admits no one.
func TestPolicyAdmitsPCR0_Empty(t *testing.T) {
	if policyAdmitsPCR0("", "deadbeef") {
		t.Fatalf("empty policy must not admit any PCR0")
	}
}

// TestPolicyAdmitsPCR0_LockedMatching verifies a locked policy admits the PCR0
// it was built for.
func TestPolicyAdmitsPCR0_LockedMatching(t *testing.T) {
	targetPCR0 := strings.Repeat("a", 96)
	locked := NewKMSPolicyBuilder().ForRole("arn:aws:iam::123:role/ec2").LockedToPCR0Values([]string{targetPCR0}).Build()
	if !policyAdmitsPCR0(locked, targetPCR0) {
		t.Fatalf("locked policy with matching PCR0: expected admit=true, got false")
	}
}

// TestPolicyAdmitsPCR0_LockedDifferent verifies a policy locked to one PCR0
// does NOT admit a different one.
func TestPolicyAdmitsPCR0_LockedDifferent(t *testing.T) {
	otherPCR0 := strings.Repeat("b", 96)
	myPCR0 := strings.Repeat("c", 96)
	locked := NewKMSPolicyBuilder().ForRole("arn:aws:iam::123:role/ec2").LockedToPCR0Values([]string{otherPCR0}).Build()
	if policyAdmitsPCR0(locked, myPCR0) {
		t.Fatalf("locked to different PCR0: expected admit=false, got true")
	}
}

// TestPolicyAdmitsPCR0_CaseInsensitive verifies PCR0 matching is case-
// insensitive (consistent with the KMS policy's StringEqualsIgnoreCase).
func TestPolicyAdmitsPCR0_CaseInsensitive(t *testing.T) {
	lowerPCR0 := strings.Repeat("a", 96)
	upperPCR0 := strings.ToUpper(lowerPCR0)
	locked := NewKMSPolicyBuilder().ForRole("arn:aws:iam::123:role/ec2").LockedToPCR0Values([]string{lowerPCR0}).Build()
	if !policyAdmitsPCR0(locked, upperPCR0) {
		t.Fatalf("case-insensitive matching: expected admit=true for uppercase query against lowercase policy, got false")
	}
}

// TestBuildKMSPolicy_NoPutKeyPolicy verifies the locked policy grants no
// PutKeyPolicy permission to anyone — this is the security guarantee.
func TestBuildKMSPolicy_NoPutKeyPolicy(t *testing.T) {
	policy := NewKMSPolicyBuilder().ForRole("arn:aws:iam::123:role/ec2").LockedToPCR0Values([]string{strings.Repeat("a", 96)}).Build()
	if strings.Contains(policy, "kms:PutKeyPolicy") {
		t.Fatalf("locked policy must not grant kms:PutKeyPolicy, got:\n%s", policy)
	}
}

// TestBuildKMSPolicy_ContainsPCR0Condition verifies Decrypt is gated on the
// specified PCR0 via kms:RecipientAttestation:PCR0.
func TestBuildKMSPolicy_ContainsPCR0Condition(t *testing.T) {
	pcr0 := strings.Repeat("a", 96)
	policy := NewKMSPolicyBuilder().ForRole("arn:aws:iam::123:role/ec2").LockedToPCR0Values([]string{pcr0}).Build()
	if !strings.Contains(policy, "kms:RecipientAttestation:PCR0") {
		t.Fatalf("locked policy must contain kms:RecipientAttestation:PCR0 condition")
	}
	if !strings.Contains(policy, pcr0) {
		t.Fatalf("locked policy must contain the target PCR0 value")
	}
}

// TestBuildKMSPolicy_AllowsDecryptEncryptDelete verifies the enclave still has
// the operations it needs: Decrypt (gated), Encrypt, GenerateDataKey, and
// ScheduleKeyDeletion (for migration cleanup).
func TestBuildKMSPolicy_AllowsDecryptEncryptDelete(t *testing.T) {
	policy := NewKMSPolicyBuilder().ForRole("arn:aws:iam::123:role/ec2").LockedToPCR0Values([]string{strings.Repeat("a", 96)}).Build()
	for _, must := range []string{"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:ScheduleKeyDeletion"} {
		if !strings.Contains(policy, must) {
			t.Fatalf("locked policy must grant %s", must)
		}
	}
}

// TestBuildKMSPolicy_NoRecovery verifies that an empty recoveryAccount
// produces the historical 3-statement policy with no RootRecovery Sid.
func TestBuildKMSPolicy_NoRecovery(t *testing.T) {
	policy := NewKMSPolicyBuilder().ForRole("arn:aws:iam::123:role/ec2").LockedToPCR0Values([]string{strings.Repeat("a", 96)}).Build()
	if strings.Contains(policy, "RootRecovery") {
		t.Fatalf("strict mode (no recoveryAccount) must not include RootRecovery statement, got:\n%s", policy)
	}
	var parsed struct {
		Statement []map[string]any `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policy), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, policy)
	}
	if got, want := len(parsed.Statement), 3; got != want {
		t.Fatalf("strict mode statement count = %d, want %d:\n%s", got, want, policy)
	}
}

// TestBuildKMSPolicy_RootRecovery verifies the RootRecovery statement is
// emitted with the expected principal, action set, and resource.
func TestBuildKMSPolicy_RootRecovery(t *testing.T) {
	const account = "123456789012"
	policy := NewKMSPolicyBuilder().ForRole("arn:aws:iam::123:role/ec2").LockedToPCR0Values([]string{strings.Repeat("a", 96)}).WithRootRecovery(account).Build()

	var parsed struct {
		Statement []map[string]any `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policy), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, policy)
	}
	if got, want := len(parsed.Statement), 4; got != want {
		t.Fatalf("recovery mode statement count = %d, want %d:\n%s", got, want, policy)
	}

	var rr map[string]any
	for _, s := range parsed.Statement {
		if s["Sid"] == "RootRecovery" {
			rr = s
			break
		}
	}
	if rr == nil {
		t.Fatalf("RootRecovery statement not found:\n%s", policy)
	}

	wantPrincipal := "arn:aws:iam::" + account + ":root"
	gotPrincipal := rr["Principal"].(map[string]any)["AWS"]
	if gotPrincipal != wantPrincipal {
		t.Errorf("RootRecovery principal = %q, want %q", gotPrincipal, wantPrincipal)
	}

	wantActions := []string{
		"kms:PutKeyPolicy",
		"kms:GetKeyPolicy",
		"kms:DescribeKey",
	}
	gotActionsAny := rr["Action"].([]any)
	gotActions := make(map[string]bool, len(gotActionsAny))
	for _, a := range gotActionsAny {
		gotActions[a.(string)] = true
	}
	for _, want := range wantActions {
		if !gotActions[want] {
			t.Errorf("RootRecovery missing action %q, got %v", want, gotActionsAny)
		}
	}
	if got, want := len(gotActionsAny), len(wantActions); got != want {
		t.Errorf("RootRecovery action count = %d, want %d (%v)", got, want, gotActionsAny)
	}

	if rr["Resource"] != "*" {
		t.Errorf("RootRecovery resource = %v, want *", rr["Resource"])
	}
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
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("arnAccount(%q) = %q, want %q", tc.arn, got, tc.want)
			}
		})
	}

	if _, err := arnAccount("not-an-arn"); err == nil {
		t.Error("arnAccount(invalid) should error")
	}
}

// TestBuildKMSPolicy_RecoveryGrantsPutKeyPolicy confirms recovery mode
// gives root the PutKeyPolicy lever (not direct Decrypt). This is the
// load-bearing property of the design: plaintext stays inside the
// attested enclave even during recovery.
func TestBuildKMSPolicy_RecoveryGrantsPutKeyPolicy(t *testing.T) {
	policy := NewKMSPolicyBuilder().ForRole("arn:aws:iam::123:role/ec2").
		LockedToPCR0Values([]string{strings.Repeat("a", 96)}).
		WithRootRecovery("123456789012").Build()
	if !strings.Contains(policy, "kms:PutKeyPolicy") {
		t.Fatalf("recovery mode must grant kms:PutKeyPolicy to root, got:\n%s", policy)
	}

	// Root must NOT be granted Decrypt directly — that would break the
	// "plaintext lives only inside an attested enclave" invariant.
	var parsed struct {
		Statement []map[string]any `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policy), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, stmt := range parsed.Statement {
		if stmt["Sid"] != "RootRecovery" {
			continue
		}
		actions, ok := stmt["Action"].([]any)
		if !ok {
			t.Fatalf("RootRecovery Action is not a list: %v", stmt["Action"])
		}
		for _, a := range actions {
			if a == "kms:Decrypt" {
				t.Fatalf("RootRecovery must not grant kms:Decrypt directly to root; recovery should pivot via PutKeyPolicy")
			}
		}
	}
}
