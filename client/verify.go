package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
)

// fetchAndVerifyAttestation fetches the attestation document from the enclave,
// verifies it against the AWS Nitro root certificate chain, checks the nonce,
// and validates PCR0 against the expected value.
//
// When insecureSkipCOSEVerify is true, the COSE Sign1 signature + cert chain
// check is bypassed (the document is parsed manually). PCR0 and nonce checks
// still run. Used for local QEMU tests where the emulated NSM doesn't sign
// with AWS Nitro keys.
func fetchAndVerifyAttestation(
	ctx context.Context,
	httpClient *http.Client,
	baseURL, expectedPCR0 string,
	insecureSkipCOSEVerify bool,
) (*nitrite.Result, error) {
	// Generate a random nonce to prevent replay attacks.
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)

	url := strings.TrimRight(baseURL, "/") + "/enclave/attestation?nonce=" + nonceHex
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf(
			"attestation status %d: %s",
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// The attestation may be returned as raw base64 or as a JSON object
	// with a "document" field.
	docB64 := strings.TrimSpace(string(payload))
	if strings.HasPrefix(docB64, "{") {
		var parsed struct {
			Document string `json:"document"`
		}
		if err := json.Unmarshal(payload, &parsed); err == nil && parsed.Document != "" {
			docB64 = parsed.Document
		}
	}

	docBytes, err := base64.StdEncoding.DecodeString(docB64)
	if err != nil {
		return nil, fmt.Errorf("decode attestation document: %w", err)
	}

	return verifyAttestationDocument(docBytes, nonce, expectedPCR0, insecureSkipCOSEVerify)
}

// verifyAttestationDocument verifies an attestation document against the AWS
// Nitro root certificate chain, checks that it answers nonce, and validates
// PCR0 against the expected value. insecureSkipCOSEVerify is as for
// fetchAndVerifyAttestation.
func verifyAttestationDocument(
	docBytes, nonce []byte,
	expectedPCR0 string,
	insecureSkipCOSEVerify bool,
) (*nitrite.Result, error) {
	var (
		result *nitrite.Result
		err    error
	)
	if insecureSkipCOSEVerify {
		// Manual parse — extract Document from the COSE Sign1 payload without
		// validating the AWS Nitro chain. PCR0 + tlsKeyHash pinning below still
		// constrain trust to the expected enclave build.
		result, err = parseCOSEPayloadInsecure(docBytes)
		if err != nil {
			return nil, fmt.Errorf("insecure parse attestation: %w", err)
		}
	} else {
		result, err = nitrite.Verify(docBytes, nitrite.VerifyOptions{
			CurrentTime: time.Now(),
		})
		if err != nil {
			return nil, fmt.Errorf("attestation verification: %w", err)
		}
	}

	if result == nil || result.Document == nil {
		return nil, fmt.Errorf("attestation missing document")
	}

	// Verify the nonce to confirm freshness.
	if len(result.Document.Nonce) == 0 {
		return nil, fmt.Errorf("attestation missing nonce")
	}
	if !bytes.Equal(result.Document.Nonce, nonce) {
		return nil, fmt.Errorf("attestation nonce mismatch")
	}

	// Verify PCR0 matches the expected enclave build measurement.
	pcr0, ok := result.Document.PCRs[0]
	if !ok {
		return nil, fmt.Errorf("attestation missing PCR0")
	}
	if !strings.EqualFold(hex.EncodeToString(pcr0), expectedPCR0) {
		return nil, fmt.Errorf(
			"PCR0 mismatch: expected %s, got %s",
			expectedPCR0,
			hex.EncodeToString(pcr0),
		)
	}

	return result, nil
}

// verifyPCRs returns the document's non-empty PCRs in hex, after checking that
// PCR16 onwards match expected, the secrets' public key hashes in order.
func verifyPCRs(docPCRs map[uint][]byte, expected []string) (map[uint]string, error) {
	pcrs := make(map[uint]string)
	for idx, pcrBytes := range docPCRs {
		if len(pcrBytes) > 0 {
			pcrs[idx] = fmt.Sprintf("%x", pcrBytes)
		}
	}

	for i, expectedHash := range expected {
		pcrIndex := uint(16) + uint(i)
		actual, ok := pcrs[pcrIndex]
		if !ok {
			return nil, fmt.Errorf("PCR%d not found in attestation document", pcrIndex)
		}
		if !strings.EqualFold(actual, expectedHash) {
			return nil, fmt.Errorf(
				"PCR%d mismatch: expected %s, got %s",
				pcrIndex,
				expectedHash,
				actual,
			)
		}
	}
	return pcrs, nil
}

// UserData format embedded in NSM attestation documents:
//
//	"sha256:" ++ tlsKeyHash(32) ++ "ed25519:" ++ responseSigningKey(32) ++
//	"cooldown:" ++ migrationCooldownLeftSeconds(8) ++ "pcr0:" ++ migrationTargetPCR0(48)
//
// Total 149 bytes: the raw TLS PublicKey hash at bytes 7:39, the raw Ed25519
// response-signing public key at bytes 47:79, the seconds left of the pending
// migration's cooldown as a big-endian uint64 at bytes 88:96, and the pending
// migration's target PCR0 at bytes 101:149, all zero when none is pending.
const (
	udHashPrefix     = "sha256:"
	udTLSStart       = len(udHashPrefix)
	udTLSEnd         = udTLSStart + 32
	udSigningPrefix  = "ed25519:"
	udSigningStart   = udTLSEnd + len(udSigningPrefix)
	udSigningEnd     = udSigningStart + ed25519.PublicKeySize
	udCooldownPrefix = "cooldown:"
	udCooldownStart  = udSigningEnd + len(udCooldownPrefix)
	udCooldownEnd    = udCooldownStart + 8
	udPCR0Prefix     = "pcr0:"
	udPCR0Start      = udCooldownEnd + len(udPCR0Prefix)
	udLen            = udPCR0Start + 48
)

// attestedUserData is the parsed attestation user_data.
type attestedUserData struct {
	tlsKeyHash          string            // hex-encoded SHA-256 of the TLS PublicKey
	signingKey          ed25519.PublicKey // nil while unset
	migrationCooldown   time.Duration
	migrationTargetPCR0 string // hex; empty when no migration is pending
}

// parseUserData returns the hex-encoded SHA-256 fingerprint of the enclave's
// TLS PublicKey, its response-signing key, which is nil while unset, and what
// it discloses about migration.
func parseUserData(attestResult *nitrite.Result) (*attestedUserData, error) {
	if attestResult == nil || attestResult.Document == nil {
		return nil, fmt.Errorf("no attestation result")
	}
	userData := attestResult.Document.UserData
	if len(userData) != udLen {
		return nil, fmt.Errorf(
			"user_data must be exactly %d bytes (got %d)", udLen, len(userData),
		)
	}
	if string(userData[:udTLSStart]) != udHashPrefix {
		return nil, fmt.Errorf("user_data missing %q prefix at offset 0", udHashPrefix)
	}
	if string(userData[udTLSEnd:udSigningStart]) != udSigningPrefix {
		return nil, fmt.Errorf(
			"user_data missing %q prefix at offset %d", udSigningPrefix, udTLSEnd,
		)
	}
	if string(userData[udSigningEnd:udCooldownStart]) != udCooldownPrefix {
		return nil, fmt.Errorf(
			"user_data missing %q prefix at offset %d", udCooldownPrefix, udSigningEnd,
		)
	}
	if string(userData[udCooldownEnd:udPCR0Start]) != udPCR0Prefix {
		return nil, fmt.Errorf(
			"user_data missing %q prefix at offset %d", udPCR0Prefix, udCooldownEnd,
		)
	}
	h := hex.EncodeToString(userData[udTLSStart:udTLSEnd])
	if isAllZeroHex(h) {
		return nil, fmt.Errorf("attested tlsKeyHash is all-zero (runtime bound no TLS cert)")
	}
	var signingKey ed25519.PublicKey
	if key := userData[udSigningStart:udSigningEnd]; !bytes.Equal(key, make([]byte, len(key))) {
		signingKey = bytes.Clone(key)
	}
	cooldown := binary.BigEndian.Uint64(userData[udCooldownStart:udCooldownEnd])
	if cooldown > uint64(math.MaxInt64/int64(time.Second)) {
		return nil, fmt.Errorf("attested migration cooldown out of range: %ds", cooldown)
	}
	var targetPCR0 string
	if target := hex.EncodeToString(userData[udPCR0Start:]); !isAllZeroHex(target) {
		targetPCR0 = target
	}
	return &attestedUserData{
		tlsKeyHash:          h,
		signingKey:          signingKey,
		migrationCooldown:   time.Duration(cooldown) * time.Second,
		migrationTargetPCR0: targetPCR0,
	}, nil
}

// Signed responses; runtime/servers.go holds the signing half.
const (
	signNonceHeader = "X-Enclave-Sign-Nonce"
	signatureHeader = "X-Enclave-Signature"
	timestampHeader = "X-Enclave-Timestamp"
)

// verifyResponseSignature checks the X-Enclave-Signature header over the
// message for the X-Enclave-Timestamp header, the enclave's time in Unix
// milliseconds when it passed the request to the app. A missing header is
// named in the error.
func verifyResponseSignature(
	key ed25519.PublicKey, header http.Header, message func(timestamp time.Time) []byte,
) error {
	sig, err := base64.StdEncoding.DecodeString(header.Get(signatureHeader))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("missing or invalid %s", signatureHeader)
	}
	ms, err := strconv.ParseInt(header.Get(timestampHeader), 10, 64)
	if err != nil {
		return fmt.Errorf("missing or invalid %s", timestampHeader)
	}
	if !ed25519.Verify(key, message(time.UnixMilli(ms)), sig) {
		return fmt.Errorf("missing or invalid %s", signatureHeader)
	}
	return nil
}

// isAllZeroHex reports whether s is empty or all '0' — an uninitialized binding.
func isAllZeroHex(s string) bool {
	if s == "" {
		return true
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}

// verifyLeafKeyHash returns nil iff SHA-256 of the live leaf certificate's
// PublicKey equals expectedHashHex. The public key remains
// stable across routine certificate renewal. Shared by HTTP and gRPC.
func verifyLeafKeyHash(rawCerts [][]byte, expectedHashHex string) error {
	if isAllZeroHex(expectedHashHex) {
		return fmt.Errorf("no attested TLS public-key fingerprint to pin against")
	}
	if len(rawCerts) == 0 {
		return fmt.Errorf("no peer certificate presented")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse peer leaf certificate: %w", err)
	}
	got := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if !strings.EqualFold(hex.EncodeToString(got[:]), expectedHashHex) {
		return fmt.Errorf(
			"TLS public-key fingerprint mismatch: expected %s, got %x",
			expectedHashHex,
			got[:],
		)
	}
	return nil
}

// parseCOSEPayloadInsecure decodes a COSE Sign1 attestation envelope without
// verifying the signature or cert chain. Used only when the caller opts into
// InsecureSkipCOSEVerify (local-test mode). It still returns the parsed
// Document so PCR0 + tlsKeyHash pinning can run downstream.
func parseCOSEPayloadInsecure(data []byte) (*nitrite.Result, error) {
	var envelope struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected cbor.RawMessage
		Payload     []byte
		Signature   []byte
	}
	if err := cbor.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("decode COSE Sign1 envelope: %w", err)
	}
	if len(envelope.Payload) == 0 {
		return nil, fmt.Errorf("COSE Sign1 payload empty")
	}
	doc := &nitrite.Document{}
	if err := cbor.Unmarshal(envelope.Payload, doc); err != nil {
		return nil, fmt.Errorf("decode attestation document: %w", err)
	}
	return &nitrite.Result{
		Document:    doc,
		Protected:   envelope.Protected,
		Payload:     envelope.Payload,
		Signature:   envelope.Signature,
		SignatureOK: false,
	}, nil
}
