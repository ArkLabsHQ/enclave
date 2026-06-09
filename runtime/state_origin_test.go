package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"
)

// newFakeSSM returns an empty in-memory SSM. The fakeSSM type (a params-backed
// SSMAPI) is declared in environment_test.go.
func newFakeSSM() *fakeSSM { return &fakeSSM{params: map[string]string{}} }

func (f *fakeSSM) clone() *fakeSSM {
	c := newFakeSSM()
	for k, v := range f.params {
		c.params[k] = v
	}
	return c
}

// genesisState populates an SSM map with the complete runtime-owned state a
// genesis enclave would have written for keyID: the key ID, every secret
// ciphertext, and the storage DEK ciphertext (arbitrary but valid base64).
func genesisState(keyID string, secrets []StaticSecret) *fakeSSM {
	f := newFakeSSM()
	f.params[kmsKeyIDParam()] = keyID
	for i, s := range secrets {
		f.params[secretCiphertextParam(s.Name, keyID)] = base64.StdEncoding.EncodeToString([]byte{byte(i), 0x11, 0x22, 0x33})
	}
	f.params[storageDEKCiphertextParam(keyID)] = base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	return f
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

// signedReceipt builds a verifiable attestation carrying a state-origin payload
// in user_data, for the receipt-verification tests.
func signedReceipt(t *testing.T, pcrs map[uint][]byte, purpose string, stateRoot []byte) signedAttestation {
	t.Helper()
	payload, err := canonicalCBOR.Marshal(stateOriginPayloadV1{Purpose: purpose, StateRoot: stateRoot})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	now := time.Now()
	return buildSignedAttestationCustom(t, pcrs, now.Add(-time.Hour), now.Add(time.Hour), now, payload)
}

var testSecrets = []StaticSecret{{Name: "alpha", EnvVar: "ALPHA"}, {Name: "beta", EnvVar: "BETA"}}

// --- state_root ---

func TestStateRootV1_DeterministicAndSensitive(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	ctx := context.Background()
	keyID := "key-aaaa"
	f := genesisState(keyID, testSecrets)

	r1, err := NewStateOrigin(f, testSecrets).stateRoot(ctx, keyID)
	if err != nil {
		t.Fatalf("compute state_root: %v", err)
	}
	r2, err := NewStateOrigin(f, testSecrets).stateRoot(ctx, keyID)
	if err != nil {
		t.Fatalf("compute state_root (again): %v", err)
	}
	if !bytes.Equal(r1, r2) {
		t.Fatal("state_root must be deterministic for the same inputs")
	}

	// Changing a secret ciphertext must change the root.
	swapped := f.clone()
	swapped.params[secretCiphertextParam("alpha", keyID)] = base64.StdEncoding.EncodeToString([]byte{0x99, 0x99})
	r3, err := NewStateOrigin(swapped, testSecrets).stateRoot(ctx, keyID)
	if err != nil {
		t.Fatalf("compute state_root (swapped): %v", err)
	}
	if bytes.Equal(r1, r3) {
		t.Fatal("changing a ciphertext must change state_root")
	}

	// Changing the storage DEK ciphertext must change the root.
	dekSwap := f.clone()
	dekSwap.params[storageDEKCiphertextParam(keyID)] = base64.StdEncoding.EncodeToString([]byte{0x00})
	r4, err := NewStateOrigin(dekSwap, testSecrets).stateRoot(ctx, keyID)
	if err != nil {
		t.Fatalf("compute state_root (dek swap): %v", err)
	}
	if bytes.Equal(r1, r4) {
		t.Fatal("changing the storage DEK ciphertext must change state_root")
	}

	// A different key ID is a different commitment.
	other := genesisState("key-bbbb", testSecrets)
	r5, err := NewStateOrigin(other, testSecrets).stateRoot(ctx, "key-bbbb")
	if err != nil {
		t.Fatalf("compute state_root (other key): %v", err)
	}
	if bytes.Equal(r1, r5) {
		t.Fatal("a different key ID must change state_root")
	}
}

func TestStateRootV1_MissingCiphertextErrors(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	ctx := context.Background()
	keyID := "key-cccc"
	f := genesisState(keyID, testSecrets)
	delete(f.params, secretCiphertextParam("beta", keyID))
	if _, err := NewStateOrigin(f, testSecrets).stateRoot(ctx, keyID); err == nil {
		t.Fatal("a missing ciphertext must error rather than silently commit to partial state")
	}
}

// --- state-origin receipt verification ---

func TestVerifyStateOriginReceipt(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	pcr0 := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 48))
	stateRoot := []byte("state-root-commitment-bytes")

	att := signedReceipt(t, map[uint][]byte{0: mustDecodeHex(t, pcr0)}, purposeStateOrigin, stateRoot)
	useAttestationRoots(t, att.roots)

	if err := verifyStateOriginReceipt(att.docB64, stateRoot, pcr0, purposeStateOrigin); err != nil {
		t.Fatalf("a genuine receipt must verify: %v", err)
	}

	other := hex.EncodeToString(bytes.Repeat([]byte{0x22}, 48))
	if err := verifyStateOriginReceipt(att.docB64, stateRoot, other, purposeStateOrigin); err == nil {
		t.Fatal("a receipt whose PCR0 isn't ours must be rejected")
	}
	if err := verifyStateOriginReceipt(att.docB64, stateRoot, pcr0, purposeMigrationTransition); err == nil {
		t.Fatal("a receipt with the wrong purpose must be rejected")
	}
	if err := verifyStateOriginReceipt(att.docB64, []byte("different-root"), pcr0, purposeStateOrigin); err == nil {
		t.Fatal("a receipt that doesn't cover the recomputed state_root must be rejected")
	}
}

func TestVerifyStateOriginReceipt_ForgedRejected(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	pcr0 := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 48))
	forged := buildForgedAttestation(t, map[uint][]byte{0: mustDecodeHex(t, pcr0)})
	if err := verifyStateOriginReceipt(forged, []byte("root"), pcr0, purposeStateOrigin); err == nil {
		t.Fatal("an unsigned/forged receipt must be rejected")
	}
}

// --- migration-transition receipt verification ---

func TestVerifyMigrationTransitionReceipt(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	prevPCR0Bytes := bytes.Repeat([]byte{0x99}, 48)
	prevPCR0 := hex.EncodeToString(prevPCR0Bytes)
	ownPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 48))
	stateRoot := []byte("successor-state-root")

	good := signedReceipt(t, map[uint][]byte{
		0:                 prevPCR0Bytes,
		migrationPCRIndex: pcr31Commitment(t, ownPCR0),
	}, purposeMigrationTransition, stateRoot)
	useAttestationRoots(t, good.roots)

	if err := verifyMigrationTransitionReceipt(good.docB64, stateRoot, prevPCR0, ownPCR0); err != nil {
		t.Fatalf("a genuine migration-transition receipt must verify: %v", err)
	}
	// Wrong predecessor identity.
	if err := verifyMigrationTransitionReceipt(good.docB64, stateRoot, hex.EncodeToString(bytes.Repeat([]byte{0x77}, 48)), ownPCR0); err == nil {
		t.Fatal("a receipt not signed by the recorded predecessor must be rejected")
	}
	// Wrong purpose.
	if err := verifyMigrationTransitionReceipt(good.docB64, stateRoot, prevPCR0, ownPCR0); err != nil {
		t.Fatalf("sanity: %v", err)
	}
	wrongPurpose := signedReceipt(t, map[uint][]byte{
		0:                 prevPCR0Bytes,
		migrationPCRIndex: pcr31Commitment(t, ownPCR0),
	}, purposeStateOrigin, stateRoot)
	useAttestationRoots(t, wrongPurpose.roots)
	if err := verifyMigrationTransitionReceipt(wrongPurpose.docB64, stateRoot, prevPCR0, ownPCR0); err == nil {
		t.Fatal("a state-origin-purposed receipt must not pass as a migration transition")
	}

	// PCR31 commits to a different successor.
	wrongTarget := signedReceipt(t, map[uint][]byte{
		0:                 prevPCR0Bytes,
		migrationPCRIndex: pcr31Commitment(t, hex.EncodeToString(bytes.Repeat([]byte{0x33}, 48))),
	}, purposeMigrationTransition, stateRoot)
	useAttestationRoots(t, wrongTarget.roots)
	if err := verifyMigrationTransitionReceipt(wrongTarget.docB64, stateRoot, prevPCR0, ownPCR0); err == nil {
		t.Fatal("a receipt whose PCR31 commits to a different successor must be rejected")
	}
}

// Rollback-onto-self: a failed forward migration rolls the predecessor back onto
// the migration key it created, where MigrationPreviousPCR0 == our own PCR0 and
// the transition receipt's PCR31 commits to the failed target, not us. It must
// still verify (the self-signature + state_root coverage is the proof), but a
// receipt NOT signed by us must still be rejected — skipping PCR31 mustn't open
// a hole.
func TestVerifyMigrationTransitionReceipt_RollbackOntoSelf(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	selfPCR0Bytes := bytes.Repeat([]byte{0xab}, 48)
	selfPCR0 := hex.EncodeToString(selfPCR0Bytes)
	failedTarget := hex.EncodeToString(bytes.Repeat([]byte{0x33}, 48))
	stateRoot := []byte("rolled-back-state-root")

	rec := signedReceipt(t, map[uint][]byte{
		0:                 selfPCR0Bytes,
		migrationPCRIndex: pcr31Commitment(t, failedTarget),
	}, purposeMigrationTransition, stateRoot)
	useAttestationRoots(t, rec.roots)
	if err := verifyMigrationTransitionReceipt(rec.docB64, stateRoot, selfPCR0, selfPCR0); err != nil {
		t.Fatalf("rollback-onto-self receipt (predecessor == own) must verify: %v", err)
	}

	// Recorded predecessor is us, but the receipt is signed by a different PCR0:
	// must be rejected (the PCR0 check still applies).
	forged := signedReceipt(t, map[uint][]byte{
		0:                 bytes.Repeat([]byte{0x77}, 48),
		migrationPCRIndex: pcr31Commitment(t, failedTarget),
	}, purposeMigrationTransition, stateRoot)
	useAttestationRoots(t, forged.roots)
	if err := verifyMigrationTransitionReceipt(forged.docB64, stateRoot, selfPCR0, selfPCR0); err == nil {
		t.Fatal("a receipt not signed by us must be rejected even on rollback-onto-self")
	}
}

// --- end-to-end resume + the ciphertext-swap property ---

func TestResumeReceipt_RoundTripAndSwapFailsClosed(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	ctx := context.Background()
	keyID := "key-resume"
	ownPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 48))

	f := genesisState(keyID, testSecrets)
	stateRoot, err := NewStateOrigin(f, testSecrets).stateRoot(ctx, keyID)
	if err != nil {
		t.Fatalf("compute state_root: %v", err)
	}
	rec := signedReceipt(t, map[uint][]byte{0: mustDecodeHex(t, ownPCR0)}, purposeStateOrigin, stateRoot)
	useAttestationRoots(t, rec.roots)
	f.params[stateOriginReceiptParam(keyID)] = rec.docB64

	if err := NewStateOrigin(f, testSecrets).verifyResume(ctx, keyID, ownPCR0); err != nil {
		t.Fatalf("a genuine resume must verify: %v", err)
	}

	// The core property: a host that re-encrypts attacker-known plaintext under
	// the accepted key and swaps the SSM ciphertext must be detected.
	f.params[secretCiphertextParam("alpha", keyID)] = base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF})
	if err := NewStateOrigin(f, testSecrets).verifyResume(ctx, keyID, ownPCR0); err == nil {
		t.Fatal("a swapped ciphertext must fail closed on resume")
	}
}

// --- startup classification table ---

func TestClassifyStartupState(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	ctx := context.Background()
	keyID := "key-classify"

	withReceipt := func(f *fakeSSM) *fakeSSM {
		f.params[stateOriginReceiptParam(keyID)] = "cmVjZWlwdA==" // value presence only
		return f
	}
	withMigration := func(f *fakeSSM) *fakeSSM {
		f.params[migrationStateOriginReceiptParam(keyID)] = "bXI="
		f.params[migrationPreviousPCR0Param()] = "predpcr0"
		f.params[migrationPreviousPCR0AttestationParam()] = "cHJlZGF0dA=="
		return f
	}

	cases := []struct {
		name    string
		keyID   string
		ssm     *fakeSSM
		want    startupMode
		wantErr bool
	}{
		{"genesis: clean", "", newFakeSSM(), modeGenesis, false},
		{"genesis blocked: lingering predecessor", "", withMigration(newFakeSSM()), 0, true},
		{"resume: complete + receipt", keyID, withReceipt(genesisState(keyID, testSecrets)), modeResume, false},
		{"fail: complete, no receipt", keyID, genesisState(keyID, testSecrets), 0, true},
		{"migration: complete + transition receipt + predecessor", keyID, withMigration(genesisState(keyID, testSecrets)), modeMigration, false},
		{"fail: complete + predecessor but no transition receipt", keyID, func() *fakeSSM {
			f := genesisState(keyID, testSecrets)
			f.params[migrationPreviousPCR0Param()] = "predpcr0"
			f.params[migrationPreviousPCR0AttestationParam()] = "cHJlZGF0dA=="
			return f
		}(), 0, true},
		{"fail: partial ciphertexts", keyID, func() *fakeSSM {
			f := withReceipt(genesisState(keyID, testSecrets))
			delete(f.params, secretCiphertextParam("beta", keyID))
			return f
		}(), 0, true},
		{"fail: receipt but no ciphertexts", keyID, func() *fakeSSM {
			f := newFakeSSM()
			f.params[kmsKeyIDParam()] = keyID
			return withReceipt(f)
		}(), 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode, err := NewStateOrigin(tc.ssm, testSecrets).classify(ctx, tc.keyID)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want fail-closed, got mode=%v", mode)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mode != tc.want {
				t.Fatalf("mode = %v, want %v", mode, tc.want)
			}
		})
	}
}

// verifyKeyPolicyPosture has its own extensive table-driven coverage in
// policy_posture_test.go.
