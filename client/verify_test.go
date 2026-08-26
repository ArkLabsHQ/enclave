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
	"github.com/stretchr/testify/require"
)

// loadTestAttestation reads the real attestation document fixture.
func loadTestAttestation(t *testing.T) []byte {
	t.Helper()
	b64, err := os.ReadFile("testdata/attestation.b64")
	require.NoError(t, err)
	doc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b64)))
	require.NoError(t, err)
	return doc
}

func TestVerifyRealAttestationDocument(t *testing.T) {
	doc := loadTestAttestation(t)

	// Verify against AWS Nitro root certs.
	result, err := nitrite.Verify(doc, nitrite.VerifyOptions{
		CurrentTime: time.Now(),
	})
	// Certificate may have expired but signature should be OK.
	require.NotNil(t, result, "nitrite.Verify failed: %v", err)
	require.True(t, result.SignatureOK, "attestation signature not OK: %v", err)
	require.NotNil(t, result.Document)

	// Verify PCR0 matches expected value.
	pcr0, ok := result.Document.PCRs[0]
	require.True(t, ok, "PCR0 not found in attestation document")
	expectedPCR0 := "834837d8fdff29f35317acc40ba4e1e505b71a3cf7374ebba016a38e05c43784a01f0c1e88bf2b6174e4dbfc6f679ba9"
	require.Equal(t, expectedPCR0, hex.EncodeToString(pcr0))

	// Verify nonce matches what we sent.
	expectedNonce := "deadbeefcafebabe1234567890abcdef01020304"
	require.Equal(t, expectedNonce, hex.EncodeToString(result.Document.Nonce))

	// Verify UserData is present (68 bytes for nitriding).
	require.GreaterOrEqual(t, len(result.Document.UserData), 68)

	// Verify mandatory fields.
	require.NotEmpty(t, result.Document.ModuleID)
	require.Equal(t, "SHA384", result.Document.Digest)
	require.NotZero(t, result.Document.Timestamp)
}

func TestVerifyAttestationRejectsTamperedDocument(t *testing.T) {
	doc := loadTestAttestation(t)

	// Tamper with the document by flipping a byte near the end.
	doc[len(doc)-1] ^= 0xff

	result, err := nitrite.Verify(doc, nitrite.VerifyOptions{
		CurrentTime: time.Now(),
	})
	require.False(t, err == nil && result != nil && result.SignatureOK)
}

func TestSchnorrSignatureVerification(t *testing.T) {
	// Real test vector captured from a running enclave.
	// Body includes trailing newline.
	body := []byte("{\"status\":\"ready\"}\n")
	sigHex := "f2f2c20eff91556cd3614fcf230a6e14b4d0574d3f91f8bf33b9acc76d61da40a691821f451e364385cbfed6ba6338e650f1de6fbca58c4a0cc7144185fa6eff"
	pubkeyHex := "028d0bcf2b3384781e74e647351c01c0852775b59f063cde314d67328927d20dd0"

	err := verifySchnorrSignature(body, sigHex, pubkeyHex)
	require.NoError(t, err)
}

func TestSchnorrRejectsWrongBody(t *testing.T) {
	body := []byte("{\"status\":\"tampered\"}\n")
	sigHex := "f2f2c20eff91556cd3614fcf230a6e14b4d0574d3f91f8bf33b9acc76d61da40a691821f451e364385cbfed6ba6338e650f1de6fbca58c4a0cc7144185fa6eff"
	pubkeyHex := "028d0bcf2b3384781e74e647351c01c0852775b59f063cde314d67328927d20dd0"

	err := verifySchnorrSignature(body, sigHex, pubkeyHex)
	require.ErrorContains(t, err, "signature verification failed")
}

func TestSchnorrRejectsWrongPubkey(t *testing.T) {
	body := []byte("{\"status\":\"ready\"}\n")
	sigHex := "f2f2c20eff91556cd3614fcf230a6e14b4d0574d3f91f8bf33b9acc76d61da40a691821f451e364385cbfed6ba6338e650f1de6fbca58c4a0cc7144185fa6eff"
	// Completely different pubkey (different x-coordinate).
	pubkeyHex := "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	err := verifySchnorrSignature(body, sigHex, pubkeyHex)
	require.ErrorContains(t, err, "signature verification failed")
}

func TestKeyBindingSigningKey(t *testing.T) {
	doc := loadTestAttestation(t)

	result, _ := nitrite.Verify(doc, nitrite.VerifyOptions{
		CurrentTime: time.Now(),
	})
	require.NotNil(t, result)
	require.NotNil(t, result.Document)

	userData := result.Document.UserData
	require.GreaterOrEqual(t, len(userData), 68)

	// Check multihash prefix at offset 34.
	require.Equal(t, byte(0x12), userData[34])
	require.Equal(t, byte(0x20), userData[35])

	signingKeyHash := userData[36:68]

	// signingKeyHash should not be all zeros.
	allZero := true
	for _, b := range signingKeyHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	require.False(t, allZero, "signingKeyHash is all zeros")

	// Verify SHA256(attestation_pubkey) matches signingKeyHash.
	// The pubkey is from the enclave-info response.
	pubkeyHex := "028d0bcf2b3384781e74e647351c01c0852775b59f063cde314d67328927d20dd0"
	pubkeyBytes, err := hex.DecodeString(pubkeyHex)
	require.NoError(t, err)

	expectedHash := sha256.Sum256(pubkeyBytes)
	require.Equal(t, expectedHash[:], signingKeyHash)
}

func TestIsAllZeroHex(t *testing.T) {
	cases := map[string]bool{
		"":                                 true,
		"00":                               true,
		strings.Repeat("0", 64):            true,
		"abc123":                           false,
		"0000000000000000000000000000000a": false,
	}
	for in, want := range cases {
		require.Equal(t, want, isAllZeroHex(in), "input %q", in)
	}
}

func TestVerifyLeafCertPin(t *testing.T) {
	cert := []byte("a fake DER certificate")
	sum := sha256.Sum256(cert)
	good := hex.EncodeToString(sum[:])

	// Match (case-insensitive).
	require.NoError(t, verifyLeafCertPin([][]byte{cert}, strings.ToUpper(good)))
	// Mismatch.
	require.ErrorContains(
		t,
		verifyLeafCertPin([][]byte{cert}, strings.Repeat("ab", 32)),
		"TLS cert fingerprint mismatch",
	)
	// No peer cert.
	require.ErrorContains(t, verifyLeafCertPin(nil, good), "no peer certificate presented")
	// Empty / all-zero expected hash (uninitialized binding).
	require.ErrorContains(
		t,
		verifyLeafCertPin([][]byte{cert}, ""),
		"no attested TLS cert fingerprint",
	)
	require.ErrorContains(
		t,
		verifyLeafCertPin([][]byte{cert}, strings.Repeat("0", 64)),
		"no attested TLS cert fingerprint",
	)
}
