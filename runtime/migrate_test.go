package runtime

import (
	"strings"
	"testing"
)

// --- KMSPolicyBuilder tests ---

func TestPolicyBuilder_LockedToPCR0Values_SingleRendersAsArray(t *testing.T) {
	policy := NewKMSPolicyBuilder().
		ForRole("arn:aws:iam::123:role/MyRole").
		LockedToPCR0Values([]string{"abc123"}).
		Build()
	if !strings.Contains(policy, `["abc123"]`) {
		t.Fatalf("single PCR0 should render as a 1-element JSON array, got:\n%s", policy)
	}
}

func TestPolicyBuilder_LockedToPCR0Values_MultipleIsArray(t *testing.T) {
	policy := NewKMSPolicyBuilder().
		ForRole("arn:aws:iam::123:role/MyRole").
		LockedToPCR0Values([]string{"aaa111", "bbb222"}).
		Build()
	if !strings.Contains(policy, `["aaa111","bbb222"]`) {
		t.Fatalf("multiple PCR0s must appear as JSON array, got:\n%s", policy)
	}
}

// --- policyAdmitsPCR0 tests ---

func TestPolicyAdmitsPCR0_StringMatch(t *testing.T) {
	policy := `{
		"Statement": [{
			"Action": "kms:Decrypt",
			"Condition": {
				"StringEqualsIgnoreCase": {
					"kms:RecipientAttestation:PCR0": "abc123"
				}
			}
		}]
	}`
	if !policyAdmitsPCR0(policy, "abc123") {
		t.Error("expected true for matching string value")
	}
}

func TestPolicyAdmitsPCR0_ArrayMatch(t *testing.T) {
	policy := `{
		"Statement": [{
			"Action": "kms:Decrypt",
			"Condition": {
				"StringEqualsIgnoreCase": {
					"kms:RecipientAttestation:PCR0": ["aaa111", "bbb222"]
				}
			}
		}]
	}`
	if !policyAdmitsPCR0(policy, "bbb222") {
		t.Error("expected true when PCR0 is in array condition")
	}
}

func TestPolicyAdmitsPCR0_ArrayNoMatch(t *testing.T) {
	policy := `{
		"Statement": [{
			"Action": "kms:Decrypt",
			"Condition": {
				"StringEqualsIgnoreCase": {
					"kms:RecipientAttestation:PCR0": ["aaa111", "ccc333"]
				}
			}
		}]
	}`
	if policyAdmitsPCR0(policy, "bbb222") {
		t.Error("expected false when PCR0 not in array")
	}
}

// --- key-scoped ciphertext path tests ---

func TestSecretCiphertextParam_KeyScoped(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "dev")
	t.Setenv("ENCLAVE_APP_NAME", "my-app")
	const keyID = "1234abcd-12ab-34cd-56ef-1234567890ab"
	if got, want := secretCiphertextParam("signing-key", keyID), "/dev/my-app/signing-key/Ciphertext/"+keyID; got != want {
		t.Fatalf("secretCiphertextParam: got %q, want %q", got, want)
	}
	if got, want := storageDEKCiphertextParam(keyID), "/dev/my-app/StorageDEK/Ciphertext/"+keyID; got != want {
		t.Fatalf("storageDEKCiphertextParam: got %q, want %q", got, want)
	}
}
