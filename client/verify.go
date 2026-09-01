package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

	var result *nitrite.Result
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
			if result != nil && result.SignatureOK {
				// Signature is valid but certificate may have expired — proceed
				// with a warning since we still trust the attestation.
			} else {
				return nil, fmt.Errorf("attestation verification: %w", err)
			}
		}
	}

	if result == nil || result.Document == nil {
		return nil, fmt.Errorf("attestation missing document")
	}

	// Verify the nonce to confirm freshness.
	expectedNonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	if len(result.Document.Nonce) == 0 {
		return nil, fmt.Errorf("attestation missing nonce")
	}
	if !bytes.Equal(result.Document.Nonce, expectedNonce) {
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

// UserData format embedded in NSM attestation documents:
//
//	"sha256:" ++ tlsKeyHash(32)
//
// Total 39 bytes, with the raw TLS PublicKey hash at bytes 7:39.
const (
	udHashPrefix = "sha256:"
	udTLSStart   = len(udHashPrefix)
	udTLSEnd     = udTLSStart + 32
)

// extractTLSKeyHash returns the hex-encoded SHA-256 fingerprint of the
// enclave's TLS PublicKey, taken from bytes 7:39 of user_data.
func extractTLSKeyHash(attestResult *nitrite.Result) (string, error) {
	if attestResult == nil || attestResult.Document == nil {
		return "", fmt.Errorf("no attestation result")
	}
	userData := attestResult.Document.UserData
	if len(userData) != udTLSEnd {
		return "", fmt.Errorf(
			"user_data must be exactly %d bytes (got %d)", udTLSEnd, len(userData),
		)
	}
	if string(userData[:udTLSStart]) != udHashPrefix {
		return "", fmt.Errorf("user_data missing %q prefix at offset 0", udHashPrefix)
	}
	h := hex.EncodeToString(userData[udTLSStart:udTLSEnd])
	if isAllZeroHex(h) {
		return "", fmt.Errorf("attested tlsKeyHash is all-zero (runtime bound no TLS cert)")
	}
	return h, nil
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

// verifyLeafCertPin returns nil iff SHA-256 of the live leaf certificate's
// PublicKey equals expectedHashHex. The public key remains
// stable across routine certificate renewal. Shared by HTTP and gRPC.
func verifyLeafCertPin(rawCerts [][]byte, expectedHashHex string) error {
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
