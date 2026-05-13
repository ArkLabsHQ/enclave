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

func TestPolicyBuilder_WithPutKeyPolicy_AddsAction(t *testing.T) {
	base := NewKMSPolicyBuilder().
		ForRole("arn:aws:iam::123:role/MyRole").
		LockedToPCR0Values([]string{"abc123"}).
		Build()
	if strings.Contains(base, "kms:PutKeyPolicy") {
		t.Fatalf("default policy must not contain PutKeyPolicy")
	}

	withPKP := NewKMSPolicyBuilder().
		ForRole("arn:aws:iam::123:role/MyRole").
		LockedToPCR0Values([]string{"abc123"}).
		WithPutKeyPolicy().
		Build()
	if !strings.Contains(withPKP, "kms:PutKeyPolicy") {
		t.Fatalf("WithPutKeyPolicy must add PutKeyPolicy action")
	}
}

// --- parseKMSPolicyState tests ---

func TestParseKMSPolicyState_StringPCR0Match(t *testing.T) {
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
	hasPCR0, hasPKP := parseKMSPolicyState(policy, "abc123")
	if !hasPCR0 {
		t.Error("expected hasPCR0=true for matching string value")
	}
	if hasPKP {
		t.Error("expected hasPutKeyPolicy=false")
	}
}

func TestParseKMSPolicyState_ArrayPCR0Match(t *testing.T) {
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
	hasPCR0, _ := parseKMSPolicyState(policy, "bbb222")
	if !hasPCR0 {
		t.Error("expected hasPCR0=true when PCR0 is in array condition")
	}
}

func TestParseKMSPolicyState_ArrayPCR0NoMatch(t *testing.T) {
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
	hasPCR0, _ := parseKMSPolicyState(policy, "bbb222")
	if hasPCR0 {
		t.Error("expected hasPCR0=false when PCR0 not in array")
	}
}

func TestParseKMSPolicyState_DetectsPutKeyPolicy(t *testing.T) {
	policy := `{
		"Statement": [
			{
				"Action": "kms:Decrypt",
				"Condition": {
					"StringEqualsIgnoreCase": {
						"kms:RecipientAttestation:PCR0": "abc123"
					}
				}
			},
			{
				"Action": ["kms:Encrypt", "kms:GetKeyPolicy", "kms:GenerateDataKey", "kms:PutKeyPolicy"]
			}
		]
	}`
	hasPCR0, hasPKP := parseKMSPolicyState(policy, "abc123")
	if !hasPCR0 {
		t.Error("expected hasPCR0=true")
	}
	if !hasPKP {
		t.Error("expected hasPutKeyPolicy=true")
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
