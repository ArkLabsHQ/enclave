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

// =============================================================================
// Extensive coverage for verifyKeyPolicyPosture (issue #131, Phase D) and the
// helpers it composes. The posture check is the load-bearing guard that an
// accepted KMS key cannot be used to exfiltrate plaintext (un-gated Decrypt) or
// to rewrite the PCR0 gate (PutKeyPolicy), so every branch is exercised here.
// =============================================================================

const (
	ppRole  = "arn:aws:iam::111122223333:role/enclave"
	ppRoot  = "arn:aws:iam::111122223333:root"
	ppPCR0  = "abc123def456"
	ppOther = "999888777666aaa"
)

// ppPolicy assembles statements into a KMS policy JSON document.
func ppPolicy(t *testing.T, statements ...map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"Version":   "2012-10-17",
		"Statement": statements,
	})
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	return string(b)
}

// ppAllow builds an Allow statement. principal/condition are omitted when nil so
// the parsed statement faithfully mirrors a real policy (nil Condition map).
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

// Genuine-shaped statements, mirroring KMSPolicyBuilder.
func ppDecryptGated(pcr0 any) map[string]any {
	return ppAllow("kms:Decrypt", ppRole, ppPCR0Cond(pcr0))
}
func ppOps() map[string]any {
	return ppAllow([]string{"kms:Encrypt", "kms:GetKeyPolicy", "kms:GenerateDataKey"}, ppRole, nil)
}
func ppDelete() map[string]any {
	return ppAllow("kms:ScheduleKeyDeletion", ppRole, nil)
}
func ppRootRecovery(principal any) map[string]any {
	return ppAllow([]string{"kms:PutKeyPolicy", "kms:GetKeyPolicy", "kms:DescribeKey"}, principal, nil)
}

// TestVerifyKeyPolicyPosture_GenuineBuilderPolicies checks the verifier accepts
// exactly what NewKMSPolicyBuilder produces, in the lock mode that matches.
func TestVerifyKeyPolicyPosture_GenuineBuilderPolicies(t *testing.T) {
	pcr0 := strings.Repeat("a", 96)
	role := "arn:aws:iam::111122223333:role/ec2"

	locked := NewKMSPolicyBuilder().ForRole(role).LockedToPCR0Values([]string{pcr0}).Build()
	unlocked := NewKMSPolicyBuilder().ForRole(role).LockedToPCR0Values([]string{pcr0}).WithRootRecovery("111122223333").Build()
	migration := NewKMSPolicyBuilder().ForRole(role).LockedToPCR0Values([]string{strings.Repeat("b", 96), pcr0}).Build()
	migrationUnlocked := NewKMSPolicyBuilder().ForRole(role).LockedToPCR0Values([]string{strings.Repeat("b", 96), pcr0}).WithRootRecovery("111122223333").Build()

	if err := verifyKeyPolicyPosture(locked, pcr0, true); err != nil {
		t.Errorf("genuine locked policy in locked mode must pass: %v", err)
	}
	if err := verifyKeyPolicyPosture(unlocked, pcr0, false); err != nil {
		t.Errorf("genuine unlocked policy in unlocked mode must pass: %v", err)
	}
	if err := verifyKeyPolicyPosture(migration, pcr0, true); err != nil {
		t.Errorf("genuine migration (locked) policy admitting [old, ours] must pass: %v", err)
	}
	if err := verifyKeyPolicyPosture(migrationUnlocked, pcr0, false); err != nil {
		t.Errorf("genuine migration (unlocked) policy must pass: %v", err)
	}
	// A locked policy is stricter than an unlocked deployment requires, so it
	// must also pass when verified in unlocked mode.
	if err := verifyKeyPolicyPosture(locked, pcr0, false); err != nil {
		t.Errorf("locked policy must also pass in unlocked mode: %v", err)
	}
	// But an unlocked policy (grants root PutKeyPolicy) must NOT pass a locked
	// deployment — that's the whole point of the lock posture.
	if err := verifyKeyPolicyPosture(unlocked, pcr0, true); err == nil {
		t.Error("unlocked policy must be rejected in locked mode")
	}
}

func TestVerifyKeyPolicyPosture_Table(t *testing.T) {
	// Effect "allow" lowercase, to exercise case-insensitive Effect matching.
	lowerEffectDecrypt := ppStmt("allow", "kms:Decrypt", ppRole, ppPCR0Cond(ppPCR0))

	cases := []struct {
		name      string
		policy    string
		pcr0      string
		locked    bool
		wantErr   bool
		errSubstr string
	}{
		// ---- accept ----
		{
			name:   "genuine locked admits ours",
			policy: ppPolicy(t, ppDecryptGated(ppPCR0), ppOps(), ppDelete()),
			pcr0:   ppPCR0, locked: true, wantErr: false,
		},
		{
			name:   "genuine unlocked admits ours",
			policy: ppPolicy(t, ppDecryptGated(ppPCR0), ppOps(), ppDelete(), ppRootRecovery(ppRoot)),
			pcr0:   ppPCR0, locked: false, wantErr: false,
		},
		{
			name:   "migration: PCR0 array admits ours among two",
			policy: ppPolicy(t, ppDecryptGated([]string{ppOther, ppPCR0}), ppOps(), ppDelete()),
			pcr0:   ppPCR0, locked: true, wantErr: false,
		},
		{
			name:   "PCR0 array admits ours among several",
			policy: ppPolicy(t, ppDecryptGated([]string{"x", "y", ppPCR0, "z"}), ppOps()),
			pcr0:   ppPCR0, locked: true, wantErr: false,
		},
		{
			name:   "PCR0 match is case-insensitive",
			policy: ppPolicy(t, ppDecryptGated(strings.ToLower(ppPCR0)), ppOps()),
			pcr0:   strings.ToUpper(ppPCR0), locked: true, wantErr: false,
		},
		{
			name:   "lowercase Effect 'allow' still counts",
			policy: ppPolicy(t, lowerEffectDecrypt, ppOps()),
			pcr0:   ppPCR0, locked: true, wantErr: false,
		},
		{
			name:   "two gated Decrypt statements, only one admits ours",
			policy: ppPolicy(t, ppDecryptGated(ppOther), ppDecryptGated(ppPCR0), ppOps()),
			pcr0:   ppPCR0, locked: true, wantErr: false,
		},
		{
			name:   "Deny on Decrypt is ignored (not an un-gated grant)",
			policy: ppPolicy(t, ppDecryptGated(ppPCR0), ppStmt("Deny", "kms:Decrypt", "*", nil), ppOps()),
			pcr0:   ppPCR0, locked: true, wantErr: false,
		},
		{
			name:   "Deny on PutKeyPolicy is ignored even when locked",
			policy: ppPolicy(t, ppDecryptGated(ppPCR0), ppStmt("Deny", "kms:PutKeyPolicy", ppRole, nil), ppOps()),
			pcr0:   ppPCR0, locked: true, wantErr: false,
		},
		{
			name:   "RootRecovery principal as array of root ARNs",
			policy: ppPolicy(t, ppDecryptGated(ppPCR0), ppRootRecovery([]string{ppRoot})),
			pcr0:   ppPCR0, locked: false, wantErr: false,
		},

		// ---- reject: structural ----
		{
			name: "empty policy", policy: "", pcr0: ppPCR0, locked: true,
			wantErr: true, errSubstr: "empty",
		},
		{
			name: "malformed JSON", policy: "{not json", pcr0: ppPCR0, locked: true,
			wantErr: true, errSubstr: "parse",
		},
		{
			name: "no statements", policy: ppPolicy(t), pcr0: ppPCR0, locked: true,
			wantErr: true, errSubstr: "does not admit",
		},
		{
			name:   "no Decrypt statement at all",
			policy: ppPolicy(t, ppOps(), ppDelete()),
			pcr0:   ppPCR0, locked: true, wantErr: true, errSubstr: "does not admit",
		},

		// ---- reject: PCR0 gating ----
		{
			name:   "Decrypt with no condition (un-gated)",
			policy: ppPolicy(t, ppAllow("kms:Decrypt", ppRole, nil), ppOps()),
			pcr0:   ppPCR0, locked: true, wantErr: true, errSubstr: "without a RecipientAttestation:PCR0",
		},
		{
			name:   "Decrypt with a non-PCR0 condition (un-gated)",
			policy: ppPolicy(t, ppAllow("kms:Decrypt", ppRole, map[string]any{"StringEquals": map[string]any{"aws:SourceVpc": "vpc-1"}}), ppOps()),
			pcr0:   ppPCR0, locked: true, wantErr: true, errSubstr: "without a RecipientAttestation:PCR0",
		},
		{
			name:   "Decrypt gated to a different PCR0 only",
			policy: ppPolicy(t, ppDecryptGated(ppOther), ppOps()),
			pcr0:   ppPCR0, locked: true, wantErr: true, errSubstr: "does not admit",
		},
		{
			name:   "wildcard kms:* without condition is an un-gated Decrypt",
			policy: ppPolicy(t, ppAllow("kms:*", ppRole, nil)),
			pcr0:   ppPCR0, locked: true, wantErr: true, errSubstr: "without a RecipientAttestation:PCR0",
		},
		{
			name:   "wildcard * without condition is an un-gated Decrypt",
			policy: ppPolicy(t, ppAllow("*", ppRole, nil)),
			pcr0:   ppPCR0, locked: true, wantErr: true, errSubstr: "without a RecipientAttestation:PCR0",
		},
		{
			name:   "un-gated Decrypt rejected even when another statement admits ours",
			policy: ppPolicy(t, ppDecryptGated(ppPCR0), ppAllow("kms:Decrypt", ppRole, nil)),
			pcr0:   ppPCR0, locked: true, wantErr: true, errSubstr: "without a RecipientAttestation:PCR0",
		},

		// ---- reject: PutKeyPolicy posture ----
		{
			name:   "locked mode rejects any PutKeyPolicy (even to root)",
			policy: ppPolicy(t, ppDecryptGated(ppPCR0), ppRootRecovery(ppRoot)),
			pcr0:   ppPCR0, locked: true, wantErr: true, errSubstr: "immutable",
		},
		{
			name:   "locked mode rejects PutKeyPolicy to the enclave role",
			policy: ppPolicy(t, ppDecryptGated(ppPCR0), ppAllow("kms:PutKeyPolicy", ppRole, nil)),
			pcr0:   ppPCR0, locked: true, wantErr: true, errSubstr: "immutable",
		},
		{
			name:   "unlocked: PutKeyPolicy to the enclave role rejected",
			policy: ppPolicy(t, ppDecryptGated(ppPCR0), ppAllow("kms:PutKeyPolicy", ppRole, nil)),
			pcr0:   ppPCR0, locked: false, wantErr: true, errSubstr: "non-root",
		},
		{
			name:   "unlocked: PutKeyPolicy to wildcard principal rejected",
			policy: ppPolicy(t, ppDecryptGated(ppPCR0), ppAllow("kms:PutKeyPolicy", "*", nil)),
			pcr0:   ppPCR0, locked: false, wantErr: true, errSubstr: "non-root",
		},
		{
			name:   "unlocked: PutKeyPolicy to mixed root+role principals rejected",
			policy: ppPolicy(t, ppDecryptGated(ppPCR0), ppAllow("kms:PutKeyPolicy", []string{ppRoot, ppRole}, nil)),
			pcr0:   ppPCR0, locked: false, wantErr: true, errSubstr: "non-root",
		},
		{
			name:   "locked: kms:* to root rejected via the PutKeyPolicy path",
			policy: ppPolicy(t, ppAllow("kms:*", ppRoot, ppPCR0Cond(ppPCR0))),
			pcr0:   ppPCR0, locked: true, wantErr: true, errSubstr: "immutable",
		},
		{
			name:   "PutKeyPolicy to root is fine but missing Decrypt still fails",
			policy: ppPolicy(t, ppRootRecovery(ppRoot)),
			pcr0:   ppPCR0, locked: false, wantErr: true, errSubstr: "does not admit",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyKeyPolicyPosture(tc.policy, tc.pcr0, tc.locked)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected pass, got error: %v", err)
			}
		})
	}
}

// --- helper unit tests ---

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
			if len(got) != len(tc.want) {
				t.Fatalf("normalizePolicyStrings(%s) = %v, want %v", tc.raw, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("normalizePolicyStrings(%s)[%d] = %q, want %q", tc.raw, i, got[i], tc.want[i])
				}
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
			if got := actionsGrant(tc.actions, tc.want); got != tc.grant {
				t.Fatalf("actionsGrant(%v, %q) = %v, want %v", tc.actions, tc.want, got, tc.grant)
			}
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
			if got := principalsAllRoot(json.RawMessage(tc.raw)); got != tc.want {
				t.Fatalf("principalsAllRoot(%s) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestConditionPCR0Helpers(t *testing.T) {
	mustCond := func(s string) map[string]interface{} {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatalf("unmarshal condition: %v", err)
		}
		return m
	}

	pcr0Single := mustCond(`{"StringEqualsIgnoreCase":{"kms:RecipientAttestation:PCR0":"abc"}}`)
	pcr0Array := mustCond(`{"StringEqualsIgnoreCase":{"kms:RecipientAttestation:PCR0":["xyz","abc"]}}`)
	noPCR0 := mustCond(`{"StringEquals":{"aws:SourceVpc":"vpc-1"}}`)

	// conditionHasPCR0
	if !conditionHasPCR0(pcr0Single) {
		t.Error("conditionHasPCR0 should be true for a single-value PCR0 condition")
	}
	if !conditionHasPCR0(pcr0Array) {
		t.Error("conditionHasPCR0 should be true for an array PCR0 condition")
	}
	if conditionHasPCR0(noPCR0) {
		t.Error("conditionHasPCR0 should be false for a non-PCR0 condition")
	}
	if conditionHasPCR0(nil) {
		t.Error("conditionHasPCR0 should be false for a nil condition")
	}

	// conditionAdmitsPCR0
	if !conditionAdmitsPCR0(pcr0Single, "abc") {
		t.Error("should admit the single matching PCR0")
	}
	if !conditionAdmitsPCR0(pcr0Single, "ABC") {
		t.Error("PCR0 admission must be case-insensitive")
	}
	if conditionAdmitsPCR0(pcr0Single, "zzz") {
		t.Error("must not admit a non-matching PCR0")
	}
	if !conditionAdmitsPCR0(pcr0Array, "abc") {
		t.Error("should admit a PCR0 present in the array")
	}
	if conditionAdmitsPCR0(pcr0Array, "nope") {
		t.Error("must not admit a PCR0 absent from the array")
	}
	if conditionAdmitsPCR0(noPCR0, "abc") {
		t.Error("a non-PCR0 condition admits nothing")
	}
}
