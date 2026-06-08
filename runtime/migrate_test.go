package runtime

import (
	"context"
	"strings"
	"testing"
)

// A recorded predecessor with a missing/UNSET attestation must fail closed —
// otherwise blanking the SSM param bypasses the PCR31 commitment check.
func TestVerifyPredecessorCommitment_FailsClosedOnMissingAttestation(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")

	fake := &fakeSSM{params: map[string]string{
		"/prod/myapp/MigrationPreviousPCR0": "aabbcc",
	}}
	m := &Migrator{aws: &AWSClient{SSM: fake}}

	if err := m.VerifyPredecessorCommitment(context.Background(), "ddeeff"); err == nil {
		t.Fatal("must fail closed when predecessor PCR0 is set but attestation is missing")
	}
}

// Genesis (no predecessor) and rolled-back-onto-self must remain no-ops and not
// require an attestation.
func TestVerifyPredecessorCommitment_NoOpWhenGenesisOrSelf(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	ctx := context.Background()

	genesis := &Migrator{aws: &AWSClient{SSM: &fakeSSM{params: map[string]string{}}}}
	if err := genesis.VerifyPredecessorCommitment(ctx, "ddeeff"); err != nil {
		t.Fatalf("genesis should be a no-op, got: %v", err)
	}

	self := &Migrator{aws: &AWSClient{SSM: &fakeSSM{params: map[string]string{
		"/prod/myapp/MigrationPreviousPCR0": "ddeeff",
	}}}}
	if err := self.VerifyPredecessorCommitment(ctx, "ddeeff"); err != nil {
		t.Fatalf("self-handoff should be a no-op, got: %v", err)
	}
}

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
