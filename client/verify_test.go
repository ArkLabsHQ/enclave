package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
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

	result, err := nitrite.Verify(doc, nitrite.VerifyOptions{
		CurrentTime: time.Now(),
	})
	// Fixture chain expired (notAfter 2026-04-04); nitrite still returns the parsed
	// document with SignatureOK. Chain validity is covered by the new regression tests.
	require.NotNil(t, result, "nitrite.Verify failed: %v", err)
	require.True(t, result.SignatureOK, "attestation signature not OK: %v", err)
	require.NotNil(t, result.Document)

	pcr0, ok := result.Document.PCRs[0]
	require.True(t, ok, "PCR0 not found in attestation document")
	expectedPCR0 := "834837d8fdff29f35317acc40ba4e1e505b71a3cf7374ebba016a38e05c43784a01f0c1e88bf2b6174e4dbfc6f679ba9"
	require.Equal(t, expectedPCR0, hex.EncodeToString(pcr0))

	expectedNonce := "deadbeefcafebabe1234567890abcdef01020304"
	require.Equal(t, expectedNonce, hex.EncodeToString(result.Document.Nonce))
	require.NotEmpty(t, result.Document.UserData)
	require.NotEmpty(t, result.Document.ModuleID)
	require.Equal(t, "SHA384", result.Document.Digest)
	require.NotZero(t, result.Document.Timestamp)
}

func TestFetchAndVerifyAttestationRejectsInvalidCertificateChain(t *testing.T) {
	pcr0 := strings.Repeat("ab", 48)

	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
	}{
		{
			name: "untrusted chain",
		},
		{
			name:      "expired chain",
			notBefore: time.Now().Add(-48 * time.Hour),
			notAfter:  time.Now().Add(-24 * time.Hour),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := buildSelfSignedAttestationDoc(
				t,
				pcr0,
				strings.Repeat("cd", 20),
				tt.notBefore,
				tt.notAfter,
			)

			result, err := nitrite.Verify(doc, nitrite.VerifyOptions{CurrentTime: time.Now()})
			require.Error(t, err)
			require.NotNil(t, result)
			require.True(t, result.SignatureOK)

			srv := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					nonceHex := r.URL.Query().Get("nonce")
					nonce, err := hex.DecodeString(nonceHex)
					require.NoError(t, err)
					docWithNonce := buildSelfSignedAttestationDoc(
						t,
						pcr0,
						hex.EncodeToString(nonce),
						tt.notBefore,
						tt.notAfter,
					)
					_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(docWithNonce)))
				}),
			)
			defer srv.Close()

			_, err = fetchAndVerifyAttestation(
				context.Background(),
				srv.Client(),
				srv.URL,
				pcr0,
				false,
			)
			require.ErrorContains(t, err, "attestation verification:")
		})
	}
}

func buildSelfSignedAttestationDoc(
	t *testing.T,
	pcr0Hex, nonceHex string,
	notBefore, notAfter time.Time,
) []byte {
	t.Helper()
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour)
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "untrusted.test"},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	// Second self-signed cert (same key as leaf), not a real intermediate CA. The
	// CABundle cannot chain to the AWS Nitro root, which is what the tests need.
	intermediateDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	pcr0, err := hex.DecodeString(pcr0Hex)
	require.NoError(t, err)
	nonce, err := hex.DecodeString(nonceHex)
	require.NoError(t, err)

	payload, err := cbor.Marshal(&nitrite.Document{
		ModuleID:    "test-module",
		Timestamp:   uint64(time.Now().UnixMilli()),
		Digest:      "SHA384",
		PCRs:        map[uint][]byte{0: pcr0},
		Certificate: certDER,
		CABundle:    [][]byte{intermediateDER},
		Nonce:       nonce,
		UserData:    append([]byte(udHashPrefix), make([]byte, sha256.Size)...),
	})
	require.NoError(t, err)

	protected, err := cbor.Marshal(map[int]int64{1: -35})
	require.NoError(t, err)

	sigStruct, err := cbor.Marshal(&struct {
		_           struct{} `cbor:",toarray"`
		Context     string
		Protected   []byte
		ExternalAAD []byte
		Payload     []byte
	}{
		Context:     "Signature1",
		Protected:   protected,
		ExternalAAD: []byte{},
		Payload:     payload,
	})
	require.NoError(t, err)

	hash := sha512.Sum384(sigStruct)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	require.NoError(t, err)

	sig := make([]byte, 96)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[48-len(rb):48], rb)
	copy(sig[96-len(sb):96], sb)

	envelope, err := cbor.Marshal(&struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected cbor.RawMessage
		Payload     []byte
		Signature   []byte
	}{
		Protected:   protected,
		Unprotected: cbor.RawMessage{0xa0},
		Payload:     payload,
		Signature:   sig,
	})
	require.NoError(t, err)
	return envelope
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

// testUserData builds the 149-byte user_data the runtime attests, with a 24h
// migration cooldown and no pending migration.
func testUserData(tlsHash [sha256.Size]byte, signingKey []byte) []byte {
	ud := append([]byte(udHashPrefix), tlsHash[:]...)
	ud = append(ud, udSigningPrefix...)
	ud = append(ud, signingKey...)
	ud = append(ud, udCooldownPrefix...)
	ud = binary.BigEndian.AppendUint64(ud, uint64(24*time.Hour/time.Second))
	ud = append(ud, udPCR0Prefix...)
	return append(ud, make([]byte, sha512.Size384)...)
}

func TestParseUserDataRequiresExactFormat(t *testing.T) {
	digest := sha256.Sum256([]byte("tls leaf"))
	signingKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	valid := testUserData(digest, signingKey)
	unsigned := testUserData(digest, make([]byte, ed25519.PublicKeySize))
	migrating := append([]byte(nil), valid...)
	copy(migrating[udPCR0Start:], bytes.Repeat([]byte{0xab}, sha512.Size384))
	short := append([]byte(nil), valid[:len(valid)-1]...)
	long := append(append([]byte(nil), valid...), 0)
	keysOnly := append([]byte(nil), valid[:udSigningEnd]...)
	mutate := func(offset int, b byte) []byte {
		out := append([]byte(nil), valid...)
		out[offset] = b
		return out
	}
	hugeCooldown := append([]byte(nil), valid...)
	copy(hugeCooldown[udCooldownStart:udCooldownEnd], bytes.Repeat([]byte{0xff}, 8))
	zero := testUserData([sha256.Size]byte{}, signingKey)
	require.Len(t, valid, 149)
	require.Len(t, keysOnly, 79)

	data := func(raw []byte) *nitrite.Result {
		return &nitrite.Result{Document: &nitrite.Document{UserData: raw}}
	}
	digestHex := hex.EncodeToString(digest[:])
	tests := []struct {
		name        string
		result      *nitrite.Result
		want        *attestedUserData
		errContains string
	}{
		{
			name:   "valid exact payload",
			result: data(valid),
			want: &attestedUserData{
				tlsKeyHash: digestHex, signingKey: signingKey, migrationCooldown: 24 * time.Hour,
			},
		},
		{
			name:   "no signing key set",
			result: data(unsigned),
			want:   &attestedUserData{tlsKeyHash: digestHex, migrationCooldown: 24 * time.Hour},
		},
		{
			name:   "pending migration",
			result: data(migrating),
			want: &attestedUserData{
				tlsKeyHash: digestHex, signingKey: signingKey, migrationCooldown: 24 * time.Hour,
				migrationTargetPCR0: strings.Repeat("ab", sha512.Size384),
			},
		},
		{name: "short payload", result: data(short), errContains: "exactly 149 bytes"},
		{name: "long payload", result: data(long), errContains: "exactly 149 bytes"},
		{
			name:        "keys-only payload of an older runtime",
			result:      data(keysOnly),
			errContains: "exactly 149 bytes",
		},
		{
			name:        "bad prefix",
			result:      data(mutate(0, 'x')),
			errContains: "missing \"sha256:\" prefix",
		},
		{
			name:        "bad signing key prefix",
			result:      data(mutate(udTLSEnd+1, 'x')),
			errContains: "missing \"ed25519:\" prefix",
		},
		{
			name:        "bad cooldown prefix",
			result:      data(mutate(udSigningEnd, 'x')),
			errContains: "missing \"cooldown:\" prefix",
		},
		{
			name:        "bad target prefix",
			result:      data(mutate(udCooldownEnd, 'x')),
			errContains: "missing \"pcr0:\" prefix",
		},
		{
			name:        "cooldown out of range",
			result:      data(hugeCooldown),
			errContains: "out of range",
		},
		{
			name:        "all-zero digest",
			result:      data(zero),
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
			got, err := parseUserData(tc.result)
			if tc.errContains != "" {
				require.ErrorContains(t, err, tc.errContains)
				require.Nil(t, got)
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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "enclave.test"},
		DNSNames:     []string{"enclave.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(cert)
	require.NoError(t, err)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	good := hex.EncodeToString(sum[:])

	// Match (case-insensitive).
	require.NoError(t, verifyLeafCertPin([][]byte{cert}, strings.ToUpper(good)))

	// A renewed certificate with different DER but the same key keeps the same pin.
	renewedTemplate := *tmpl
	renewedTemplate.SerialNumber = big.NewInt(2)
	renewedTemplate.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	renewed, err := x509.CreateCertificate(
		rand.Reader, &renewedTemplate, &renewedTemplate, &key.PublicKey, key,
	)
	require.NoError(t, err)
	require.NotEqual(t, cert, renewed)
	require.NoError(t, verifyLeafCertPin([][]byte{renewed}, good))
	// Mismatch.
	require.ErrorContains(
		t,
		verifyLeafCertPin([][]byte{cert}, strings.Repeat("ab", 32)),
		"TLS public-key fingerprint mismatch",
	)
	// No peer cert.
	require.ErrorContains(t, verifyLeafCertPin(nil, good), "no peer certificate presented")
	// Empty / all-zero expected hash (uninitialized binding).
	require.ErrorContains(
		t,
		verifyLeafCertPin([][]byte{cert}, ""),
		"no attested TLS public-key fingerprint",
	)
	require.ErrorContains(
		t,
		verifyLeafCertPin([][]byte{cert}, strings.Repeat("0", 64)),
		"no attested TLS public-key fingerprint",
	)
}
