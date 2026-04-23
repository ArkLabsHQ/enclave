package runtime

import (
	"strings"
	"testing"
)

// TestParseKMSPolicyState_Empty verifies an empty policy is treated as fresh.
func TestParseKMSPolicyState_Empty(t *testing.T) {
	hasPCR0, hasPut := parseKMSPolicyState("", "deadbeef")
	if hasPCR0 || hasPut {
		t.Fatalf("empty policy: expected (false, false), got (%v, %v)", hasPCR0, hasPut)
	}
}

// TestParseKMSPolicyState_TransitionalPolicy verifies the transitional policy
// (grants PutKeyPolicy, no PCR0 condition) is detected as modifiable.
func TestParseKMSPolicyState_TransitionalPolicy(t *testing.T) {
	transitional := `{
	  "Version": "2012-10-17",
	  "Statement": [
	    {
	      "Effect": "Allow",
	      "Principal": {"AWS": "arn:aws:iam::123:role/ec2"},
	      "Action": ["kms:Encrypt", "kms:PutKeyPolicy"],
	      "Resource": "*"
	    }
	  ]
	}`
	hasPCR0, hasPut := parseKMSPolicyState(transitional, "aaaa")
	if hasPCR0 {
		t.Fatalf("transitional policy: expected hasPCR0=false, got true")
	}
	if !hasPut {
		t.Fatalf("transitional policy: expected hasPutKeyPolicy=true, got false")
	}
}

// TestParseKMSPolicyState_LockedMatchingPCR0 verifies the locked policy with
// the target PCR0 is correctly detected — this is the idempotency check that
// lets selfApplyKMSPolicy skip PutKeyPolicy on restart.
// Covers plan test #3: "selfApplyKMSPolicy skips PutKeyPolicy when policy already contains target PCR0".
func TestParseKMSPolicyState_LockedMatchingPCR0(t *testing.T) {
	targetPCR0 := strings.Repeat("a", 96)
	locked := buildKMSPolicy("arn:aws:iam::123:role/ec2", targetPCR0)
	hasPCR0, hasPut := parseKMSPolicyState(locked, targetPCR0)
	if !hasPCR0 {
		t.Fatalf("locked policy with matching PCR0: expected hasPCR0=true, got false")
	}
	if hasPut {
		t.Fatalf("locked policy: expected hasPutKeyPolicy=false (no-one can modify), got true")
	}
}

// TestParseKMSPolicyState_LockedDifferentPCR0 verifies we correctly detect
// when a key is locked to a DIFFERENT PCR0 (rebuilds would fail here).
func TestParseKMSPolicyState_LockedDifferentPCR0(t *testing.T) {
	otherPCR0 := strings.Repeat("b", 96)
	myPCR0 := strings.Repeat("c", 96)
	locked := buildKMSPolicy("arn:aws:iam::123:role/ec2", otherPCR0)
	hasPCR0, hasPut := parseKMSPolicyState(locked, myPCR0)
	if hasPCR0 {
		t.Fatalf("locked to different PCR0: expected hasPCR0=false (from my perspective), got true")
	}
	if hasPut {
		t.Fatalf("locked policy: expected hasPutKeyPolicy=false, got true")
	}
}

// TestParseKMSPolicyState_CaseInsensitivePCR0 verifies PCR0 matching is case-
// insensitive (consistent with the KMS policy's StringEqualsIgnoreCase).
func TestParseKMSPolicyState_CaseInsensitivePCR0(t *testing.T) {
	lowerPCR0 := strings.Repeat("a", 96)
	upperPCR0 := strings.ToUpper(lowerPCR0)
	locked := buildKMSPolicy("arn:aws:iam::123:role/ec2", lowerPCR0)
	hasPCR0, _ := parseKMSPolicyState(locked, upperPCR0)
	if !hasPCR0 {
		t.Fatalf("case-insensitive matching: expected hasPCR0=true for uppercase query against lowercase policy, got false")
	}
}

// TestParseKMSPolicyState_KmsStar verifies kms:* grants PutKeyPolicy.
func TestParseKMSPolicyState_KmsStar(t *testing.T) {
	bootstrapPolicy := `{
	  "Version": "2012-10-17",
	  "Statement": [
	    {
	      "Effect": "Allow",
	      "Principal": {"AWS": "arn:aws:iam::123:root"},
	      "Action": "kms:*",
	      "Resource": "*"
	    }
	  ]
	}`
	_, hasPut := parseKMSPolicyState(bootstrapPolicy, "deadbeef")
	if !hasPut {
		t.Fatalf("kms:* should imply PutKeyPolicy, got hasPutKeyPolicy=false")
	}
}

// TestBuildKMSPolicy_NoPutKeyPolicy verifies the locked policy grants no
// PutKeyPolicy permission to anyone — this is the security guarantee.
func TestBuildKMSPolicy_NoPutKeyPolicy(t *testing.T) {
	policy := buildKMSPolicy("arn:aws:iam::123:role/ec2", strings.Repeat("a", 96))
	if strings.Contains(policy, "kms:PutKeyPolicy") {
		t.Fatalf("locked policy must not grant kms:PutKeyPolicy, got:\n%s", policy)
	}
}

// TestBuildKMSPolicy_ContainsPCR0Condition verifies Decrypt is gated on the
// specified PCR0 via kms:RecipientAttestation:PCR0.
func TestBuildKMSPolicy_ContainsPCR0Condition(t *testing.T) {
	pcr0 := strings.Repeat("a", 96)
	policy := buildKMSPolicy("arn:aws:iam::123:role/ec2", pcr0)
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
	policy := buildKMSPolicy("arn:aws:iam::123:role/ec2", strings.Repeat("a", 96))
	for _, must := range []string{"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:ScheduleKeyDeletion"} {
		if !strings.Contains(policy, must) {
			t.Fatalf("locked policy must grant %s", must)
		}
	}
}
