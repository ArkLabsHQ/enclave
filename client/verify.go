package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
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
			return nil, fmt.Errorf("attestation verification: %w", err)
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
//	"sha256:" ++ tlsKeyHash(32) ++ "ed25519:" ++ responseSigningKey(32)
//
// Total 79 bytes: the raw TLS PublicKey hash at bytes 7:39 and the raw Ed25519
// response-signing public key at bytes 47:79.
const (
	udHashPrefix    = "sha256:"
	udTLSStart      = len(udHashPrefix)
	udTLSEnd        = udTLSStart + 32
	udSigningPrefix = "ed25519:"
	udSigningStart  = udTLSEnd + len(udSigningPrefix)
	udLen           = udSigningStart + ed25519.PublicKeySize
)

// parseUserData returns the hex-encoded SHA-256 fingerprint of the enclave's
// TLS PublicKey and its response-signing key, which is nil while unset.
func parseUserData(attestResult *nitrite.Result) (string, ed25519.PublicKey, error) {
	if attestResult == nil || attestResult.Document == nil {
		return "", nil, fmt.Errorf("no attestation result")
	}
	userData := attestResult.Document.UserData
	if len(userData) != udLen {
		return "", nil, fmt.Errorf(
			"user_data must be exactly %d bytes (got %d)", udLen, len(userData),
		)
	}
	if string(userData[:udTLSStart]) != udHashPrefix {
		return "", nil, fmt.Errorf("user_data missing %q prefix at offset 0", udHashPrefix)
	}
	if string(userData[udTLSEnd:udSigningStart]) != udSigningPrefix {
		return "", nil, fmt.Errorf(
			"user_data missing %q prefix at offset %d", udSigningPrefix, udTLSEnd,
		)
	}
	h := hex.EncodeToString(userData[udTLSStart:udTLSEnd])
	if isAllZeroHex(h) {
		return "", nil, fmt.Errorf("attested tlsKeyHash is all-zero (runtime bound no TLS cert)")
	}
	var signingKey ed25519.PublicKey
	if key := userData[udSigningStart:]; !bytes.Equal(key, make([]byte, len(key))) {
		signingKey = bytes.Clone(key)
	}
	return h, signingKey, nil
}

// Signed responses; runtime/servers.go holds the signing half.
const (
	signNonceHeader = "X-Enclave-Sign-Nonce"
	signatureHeader = "X-Enclave-Signature"
)

// prepareResponseSigningContext asks for a signed response under a fresh nonce and
// captures the authority, headers, and body the response must authenticate.
func prepareResponseSigningContext(req *http.Request) (responseSigningContext, error) {
	var body []byte
	if req.Body != nil {
		var err error
		if body, err = io.ReadAll(req.Body); err != nil {
			return responseSigningContext{}, fmt.Errorf("read request body: %w", err)
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	// Normalize aliases before HTTP/2 can serialize map keys in a different
	// order. Preserve repeated values in the same order as HTTP/1 writes them.
	headers := make(http.Header, len(req.Header)+1)
	for _, name := range slices.Sorted(maps.Keys(req.Header)) {
		canonical := http.CanonicalHeaderKey(name)
		headers[canonical] = append(headers[canonical], req.Header[name]...)
	}
	req.Header = headers
	// Let the transport ask for gzip and decode it, so the body we hash is the
	// decoded one the runtime signed, even if a proxy compresses it.
	req.Header.Del("Accept-Encoding")
	// http.Client adds URL credentials after Do starts; bind them before that.
	if req.URL != nil && req.URL.User != nil && req.Header.Get("Authorization") == "" {
		password, _ := req.URL.User.Password()
		req.SetBasicAuth(req.URL.User.Username(), password)
	}
	req.Header.Set(signNonceHeader, rand.Text())
	return captureResponseSigningContext(req, body)
}

// verifyResponseSignature checks the X-Enclave-Signature header over msg.
func verifyResponseSignature(key ed25519.PublicKey, msg []byte, header http.Header) error {
	sig, err := base64.StdEncoding.DecodeString(header.Get(signatureHeader))
	if err != nil || !ed25519.Verify(key, msg, sig) {
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
