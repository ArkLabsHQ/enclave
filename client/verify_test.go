package client

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hf/nitrite"
)

// loadTestAttestation reads the real attestation document fixture.
func loadTestAttestation(t *testing.T) []byte {
	t.Helper()
	b64, err := os.ReadFile("testdata/attestation.b64")
	if err != nil {
		t.Fatalf("read attestation fixture: %v", err)
	}
	doc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b64)))
	if err != nil {
		t.Fatalf("decode attestation base64: %v", err)
	}
	return doc
}

func TestVerifyRealAttestationDocument(t *testing.T) {
	doc := loadTestAttestation(t)

	// Verify against AWS Nitro root certs.
	result, err := nitrite.Verify(doc, nitrite.VerifyOptions{
		CurrentTime: time.Now(),
	})
	// Certificate may have expired but signature should be OK.
	if result == nil {
		t.Fatalf("nitrite.Verify returned nil result: %v", err)
	}
	if !result.SignatureOK {
		t.Fatalf("attestation signature not OK: %v", err)
	}
	if result.Document == nil {
		t.Fatal("attestation document is nil")
	}

	// Verify PCR0 matches expected value.
	pcr0, ok := result.Document.PCRs[0]
	if !ok {
		t.Fatal("PCR0 not found in attestation document")
	}
	expectedPCR0 := "834837d8fdff29f35317acc40ba4e1e505b71a3cf7374ebba016a38e05c43784a01f0c1e88bf2b6174e4dbfc6f679ba9"
	if !strings.EqualFold(hex.EncodeToString(pcr0), expectedPCR0) {
		t.Fatalf("PCR0 mismatch: expected %s, got %s", expectedPCR0, hex.EncodeToString(pcr0))
	}

	// Verify nonce matches what we sent.
	expectedNonce := "deadbeefcafebabe1234567890abcdef01020304"
	if hex.EncodeToString(result.Document.Nonce) != expectedNonce {
		t.Fatalf("nonce mismatch: expected %s, got %s", expectedNonce, hex.EncodeToString(result.Document.Nonce))
	}

	// Verify UserData is present (68 bytes for nitriding).
	if len(result.Document.UserData) < 68 {
		t.Fatalf("UserData too short: %d bytes", len(result.Document.UserData))
	}

	// Verify mandatory fields.
	if result.Document.ModuleID == "" {
		t.Fatal("module_id is empty")
	}
	if result.Document.Digest != "SHA384" {
		t.Fatalf("digest is %q, expected SHA384", result.Document.Digest)
	}
	if result.Document.Timestamp == 0 {
		t.Fatal("timestamp is 0")
	}
}

func TestVerifyAttestationRejectsTamperedDocument(t *testing.T) {
	doc := loadTestAttestation(t)

	// Tamper with the document by flipping a byte near the end.
	doc[len(doc)-1] ^= 0xff

	result, err := nitrite.Verify(doc, nitrite.VerifyOptions{
		CurrentTime: time.Now(),
	})
	if err == nil && result != nil && result.SignatureOK {
		t.Fatal("tampered document should not have a valid signature")
	}
}

func TestSchnorrSignatureVerification(t *testing.T) {
	// Real test vector captured from a running enclave.
	// Body includes trailing newline.
	body := []byte("{\"status\":\"ready\"}\n")
	sigHex := "f2f2c20eff91556cd3614fcf230a6e14b4d0574d3f91f8bf33b9acc76d61da40a691821f451e364385cbfed6ba6338e650f1de6fbca58c4a0cc7144185fa6eff"
	pubkeyHex := "028d0bcf2b3384781e74e647351c01c0852775b59f063cde314d67328927d20dd0"

	err := verifySchnorrSignature(body, sigHex, pubkeyHex)
	if err != nil {
		t.Fatalf("Schnorr verification failed: %v", err)
	}
}

func TestSchnorrRejectsWrongBody(t *testing.T) {
	body := []byte("{\"status\":\"tampered\"}\n")
	sigHex := "f2f2c20eff91556cd3614fcf230a6e14b4d0574d3f91f8bf33b9acc76d61da40a691821f451e364385cbfed6ba6338e650f1de6fbca58c4a0cc7144185fa6eff"
	pubkeyHex := "028d0bcf2b3384781e74e647351c01c0852775b59f063cde314d67328927d20dd0"

	err := verifySchnorrSignature(body, sigHex, pubkeyHex)
	if err == nil {
		t.Fatal("expected Schnorr verification to fail with wrong body")
	}
}

func TestSchnorrRejectsWrongPubkey(t *testing.T) {
	body := []byte("{\"status\":\"ready\"}\n")
	sigHex := "f2f2c20eff91556cd3614fcf230a6e14b4d0574d3f91f8bf33b9acc76d61da40a691821f451e364385cbfed6ba6338e650f1de6fbca58c4a0cc7144185fa6eff"
	// Completely different pubkey (different x-coordinate).
	pubkeyHex := "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	err := verifySchnorrSignature(body, sigHex, pubkeyHex)
	if err == nil {
		t.Fatal("expected Schnorr verification to fail with wrong pubkey")
	}
}

func TestKeyBindingAppKeyHash(t *testing.T) {
	doc := loadTestAttestation(t)

	result, _ := nitrite.Verify(doc, nitrite.VerifyOptions{
		CurrentTime: time.Now(),
	})
	if result == nil || result.Document == nil {
		t.Fatal("failed to verify attestation")
	}

	userData := result.Document.UserData
	if len(userData) < 68 {
		t.Fatalf("UserData too short: %d", len(userData))
	}

	// Check multihash prefix at offset 34.
	if userData[34] != 0x12 || userData[35] != 0x20 {
		t.Fatalf("bad multihash prefix at offset 34: %02x %02x", userData[34], userData[35])
	}

	appKeyHash := userData[36:68]

	// appKeyHash should not be all zeros.
	allZero := true
	for _, b := range appKeyHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("appKeyHash is all zeros")
	}

	// Verify SHA256(attestation_pubkey) matches appKeyHash.
	// The pubkey is from the enclave-info response.
	pubkeyHex := "028d0bcf2b3384781e74e647351c01c0852775b59f063cde314d67328927d20dd0"
	pubkeyBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}

	expectedHash := sha256.Sum256(pubkeyBytes)
	if string(expectedHash[:]) != string(appKeyHash) {
		t.Fatalf("appKeyHash mismatch:\n  expected: %s\n  got:      %s",
			hex.EncodeToString(expectedHash[:]),
			hex.EncodeToString(appKeyHash))
	}
}
