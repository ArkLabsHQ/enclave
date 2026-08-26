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

	// This historical signed fixture predates the current runtime wire format.
	// It remains useful for COSE verification but is not parsed as a TLS binding.
	require.NotEmpty(t, result.Document.UserData)

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

func TestExtractTLSKeyHashRequiresExactFormat(t *testing.T) {
	digest := sha256.Sum256([]byte("tls leaf"))
	valid := append([]byte(udHashPrefix), digest[:]...)
	short := append([]byte(nil), valid[:len(valid)-1]...)
	long := append(append([]byte(nil), valid...), 0)
	legacy := append(append([]byte(nil), valid...), ';')
	legacy = append(legacy, []byte(udHashPrefix)...)
	legacy = append(legacy, make([]byte, sha256.Size)...)
	badPrefix := append([]byte(nil), valid...)
	badPrefix[0] = 'x'
	zero := append([]byte(udHashPrefix), make([]byte, sha256.Size)...)
	require.Len(t, valid, 39)
	require.Len(t, short, 38)
	require.Len(t, long, 40)
	require.Len(t, legacy, 79)

	tests := []struct {
		name        string
		result      *nitrite.Result
		want        string
		errContains string
	}{
		{
			name:   "valid exact payload",
			result: &nitrite.Result{Document: &nitrite.Document{UserData: valid}},
			want:   hex.EncodeToString(digest[:]),
		},
		{
			name:        "short payload",
			result:      &nitrite.Result{Document: &nitrite.Document{UserData: short}},
			errContains: "exactly 39 bytes",
		},
		{
			name:        "long payload",
			result:      &nitrite.Result{Document: &nitrite.Document{UserData: long}},
			errContains: "exactly 39 bytes",
		},
		{
			name:        "legacy two-hash payload",
			result:      &nitrite.Result{Document: &nitrite.Document{UserData: legacy}},
			errContains: "exactly 39 bytes",
		},
		{
			name:        "bad prefix",
			result:      &nitrite.Result{Document: &nitrite.Document{UserData: badPrefix}},
			errContains: "missing \"sha256:\" prefix",
		},
		{
			name:        "all-zero digest",
			result:      &nitrite.Result{Document: &nitrite.Document{UserData: zero}},
			errContains: "all-zero",
		},
		{name: "nil attestation", errContains: "no attestation result"},
		{
			name:        "nil document",
			result:      &nitrite.Result{},
			errContains: "no attestation result",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractTLSKeyHash(tc.result)
			if tc.errContains != "" {
				require.ErrorContains(t, err, tc.errContains)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
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
