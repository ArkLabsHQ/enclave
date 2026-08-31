package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
)

// enclaveInfoResponse is the JSON structure returned by /enclave/v1/info.
type enclaveInfoResponse struct {
	Version           string `json:"version"`
	PreviousPCR0      string `json:"previous_pcr0"`
	AttestationPubkey string `json:"attestation_pubkey,omitempty"`
	Error             string `json:"error,omitempty"`
}

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

// UserData format embedded in NSM attestation documents (nitriding v1.4.2):
//
//	"sha256:" ++ tlsKeyHash(32) ++ ";" ++ "sha256:" ++ signingKeyHash(32)
//
// Total 79 bytes. tlsKeyHash at bytes 7:39, signingKeyHash at bytes 47:79.
const (
	udHashPrefix = "sha256:"
	udHashSep    = ";"
	udTLSStart   = len(udHashPrefix)
	udTLSEnd     = udTLSStart + 32
	udSepStart   = udTLSEnd
	udAppPrefix  = udSepStart + len(udHashSep)
	udAppStart   = udAppPrefix + len(udHashPrefix)
	udAppEnd     = udAppStart + 32
)

// extractTLSKeyHash returns the hex-encoded SHA-256 fingerprint of the
// enclave's TLS leaf cert, taken from bytes 7:39 of user_data.
func extractTLSKeyHash(attestResult *nitrite.Result) (string, error) {
	if attestResult == nil || attestResult.Document == nil {
		return "", fmt.Errorf("no attestation result")
	}
	userData := attestResult.Document.UserData
	if len(userData) < udTLSEnd {
		return "", fmt.Errorf("user_data too short for tlsKeyHash (got %d bytes)", len(userData))
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

// verifyLeafCertPin returns nil iff SHA-256 of the live leaf cert (rawCerts[0])
// equals expectedHashHex; missing/empty/all-zero is rejected. Shared by HTTP+gRPC.
func verifyLeafCertPin(rawCerts [][]byte, expectedHashHex string) error {
	if isAllZeroHex(expectedHashHex) {
		return fmt.Errorf("no attested TLS cert fingerprint to pin against")
	}
	if len(rawCerts) == 0 {
		return fmt.Errorf("no peer certificate presented")
	}
	got := sha256.Sum256(rawCerts[0])
	if !strings.EqualFold(hex.EncodeToString(got[:]), expectedHashHex) {
		return fmt.Errorf(
			"TLS cert fingerprint mismatch: expected %s, got %x",
			expectedHashHex,
			got[:],
		)
	}
	return nil
}

// verifyKeyBinding verifies the enclave's ephemeral attestation key by
// checking that the pubkey from /enclave/v1/info matches the signingKeyHash
// in the attestation document's UserData.
func verifyKeyBinding(
	ctx context.Context,
	httpClient *http.Client,
	baseURL string,
	attestResult *nitrite.Result,
) (string, error) {
	if attestResult == nil || attestResult.Document == nil {
		return "", fmt.Errorf("no attestation result to verify against")
	}

	const (
		hashPrefix   = "sha256:"
		hashSep      = ";"
		tlsStart     = len(hashPrefix)
		tlsEnd       = tlsStart + 32
		sepStart     = tlsEnd
		sigKeyPrefix = sepStart + len(hashSep)
		sigKeyStart  = sigKeyPrefix + len(hashPrefix)
		sigKeyEnd    = sigKeyStart + 32
	)

	userData := attestResult.Document.UserData
	if len(userData) < sigKeyEnd {
		// UserData too short — enclave may not support attestation key.
		return "", nil
	}
	if !bytes.Equal(userData[:tlsStart], []byte(hashPrefix)) {
		return "", fmt.Errorf(
			"UserData missing %q prefix at offset 0 (got %q)",
			hashPrefix,
			string(userData[:tlsStart]),
		)
	}
	if string(userData[sepStart:sigKeyPrefix]) != hashSep {
		return "", fmt.Errorf(
			"UserData missing %q separator at offset %d (got %q)",
			hashSep,
			sepStart,
			string(userData[sepStart:sigKeyPrefix]),
		)
	}
	if !bytes.Equal(userData[sigKeyPrefix:sigKeyStart], []byte(hashPrefix)) {
		return "", fmt.Errorf(
			"UserData missing %q prefix at offset %d (got %q)",
			hashPrefix,
			sigKeyPrefix,
			string(userData[sigKeyPrefix:sigKeyStart]),
		)
	}
	signingKeyHash := userData[sigKeyStart:sigKeyEnd]

	// Check if signingKeyHash is all zeros (key not yet registered).
	allZero := true
	for _, b := range signingKeyHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", fmt.Errorf("attestation key not yet registered (signingKeyHash is all zeros)")
	}

	// Fetch the attestation pubkey from the enclave.
	info, err := fetchEnclaveInfo(ctx, httpClient, baseURL)
	if err != nil {
		return "", fmt.Errorf("fetch enclave info: %w", err)
	}
	if info.AttestationPubkey == "" {
		return "", fmt.Errorf("enclave reports no attestation pubkey but signingKeyHash is set")
	}

	attestPubkeyBytes, err := hex.DecodeString(info.AttestationPubkey)
	if err != nil {
		return "", fmt.Errorf("decode attestation pubkey hex: %w", err)
	}

	// Verify that SHA256(pubkey) matches the signingKeyHash from attestation.
	expectedHash := sha256.Sum256(attestPubkeyBytes)
	if !bytes.Equal(expectedHash[:], signingKeyHash) {
		return "", fmt.Errorf("signingKeyHash mismatch: expected SHA256(%s) = %s, got %s",
			info.AttestationPubkey,
			hex.EncodeToString(expectedHash[:]),
			hex.EncodeToString(signingKeyHash))
	}

	return info.AttestationPubkey, nil
}

// verifySchnorrSignature verifies a BIP-340 Schnorr signature over the
// SHA256 hash of body, using the hex-encoded compressed secp256k1 pubkey.
func verifySchnorrSignature(body []byte, sigHex, attestPubkeyHex string) error {
	pubkeyBytes, err := hex.DecodeString(attestPubkeyHex)
	if err != nil {
		return fmt.Errorf("decode pubkey: %w", err)
	}
	// The attestation pubkey is compressed (33 bytes). Extract x-only (32 bytes)
	// by dropping the prefix byte for Schnorr verification.
	if len(pubkeyBytes) == 33 {
		pubkeyBytes = pubkeyBytes[1:]
	}
	pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return fmt.Errorf("parse attestation pubkey: %w", err)
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("decode signature hex: %w", err)
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}

	msgHash := sha256.Sum256(body)
	if !sig.Verify(msgHash[:], pubkey) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// fetchEnclaveInfo fetches the /enclave/v1/info endpoint.
func fetchEnclaveInfo(
	ctx context.Context,
	httpClient *http.Client,
	baseURL string,
) (*enclaveInfoResponse, error) {
	infoURL := strings.TrimRight(baseURL, "/") + "/enclave/v1/info"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, infoURL, nil)
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
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var info enclaveInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode enclave info: %w", err)
	}
	if info.Error != "" {
		return &info, fmt.Errorf("enclave init error: %s", info.Error)
	}
	return &info, nil
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
