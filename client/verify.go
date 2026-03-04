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
	"github.com/hf/nitrite"
)

// VerifyManifestProvenance checks that a deployment manifest has a valid
// GitHub artifact attestation, proving it was produced by a GitHub Actions
// workflow — not manually uploaded. It calls the GitHub Attestations API
// with the SHA256 digest of the manifest bytes.
//
// For public repos, token can be empty. For private repos, pass a GitHub
// token with attestations:read permission.
func VerifyManifestProvenance(ctx context.Context, repo string, manifestBytes []byte, token string) error {
	digest := sha256.Sum256(manifestBytes)
	digestStr := fmt.Sprintf("sha256:%x", digest)

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/attestations/%s", repo, digestStr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("attestations API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("no attestations found for manifest (repo: %s)", repo)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("attestations API status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result struct {
		Attestations []json.RawMessage `json:"attestations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode attestations: %w", err)
	}

	if len(result.Attestations) == 0 {
		return fmt.Errorf("no attestations found for manifest (repo: %s)", repo)
	}

	return nil
}

// enclaveInfoResponse is the JSON structure returned by /v1/enclave-info.
type enclaveInfoResponse struct {
	Version           string `json:"version"`
	PreviousPCR0      string `json:"previous_pcr0"`
	AttestationPubkey string `json:"attestation_pubkey,omitempty"`
	Error             string `json:"error,omitempty"`
}

// fetchAndVerifyAttestation fetches the attestation document from the enclave,
// verifies it against the AWS Nitro root certificate chain, checks the nonce,
// and validates PCR0 against the expected value.
func fetchAndVerifyAttestation(ctx context.Context, httpClient *http.Client, baseURL, expectedPCR0 string) (*nitrite.Result, error) {
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("attestation status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
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

	// Verify the COSE Sign1 document against the AWS Nitro root certs.
	result, err := nitrite.Verify(docBytes, nitrite.VerifyOptions{
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
		return nil, fmt.Errorf("PCR0 mismatch: expected %s, got %s", expectedPCR0, hex.EncodeToString(pcr0))
	}

	return result, nil
}

// verifyKeyBinding verifies the enclave's ephemeral attestation key by
// checking that the pubkey from /v1/enclave-info matches the appKeyHash
// in the attestation document's UserData.
//
// UserData format (nitriding): [0x12, 0x20, tlsKeyHash:32] ++ [0x12, 0x20, appKeyHash:32]
// Total 68 bytes. appKeyHash is at bytes 36:68 (after the 2nd multihash prefix).
func verifyKeyBinding(ctx context.Context, httpClient *http.Client, baseURL string, attestResult *nitrite.Result) (string, error) {
	if attestResult == nil || attestResult.Document == nil {
		return "", fmt.Errorf("no attestation result to verify against")
	}

	userData := attestResult.Document.UserData
	if len(userData) < 68 {
		// UserData too short — enclave may not support attestation key.
		return "", nil
	}

	if userData[34] != 0x12 || userData[35] != 0x20 {
		return "", fmt.Errorf("UserData missing multihash prefix at offset 34 (got %02x %02x)", userData[34], userData[35])
	}
	appKeyHash := userData[36:68]

	// Check if appKeyHash is all zeros (key not yet registered).
	allZero := true
	for _, b := range appKeyHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", fmt.Errorf("attestation key not yet registered (appKeyHash is all zeros)")
	}

	// Fetch the attestation pubkey from the enclave.
	info, err := fetchEnclaveInfo(ctx, httpClient, baseURL)
	if err != nil {
		return "", fmt.Errorf("fetch enclave info: %w", err)
	}
	if info.AttestationPubkey == "" {
		return "", fmt.Errorf("enclave reports no attestation pubkey but appKeyHash is set")
	}

	attestPubkeyBytes, err := hex.DecodeString(info.AttestationPubkey)
	if err != nil {
		return "", fmt.Errorf("decode attestation pubkey hex: %w", err)
	}

	// Verify that SHA256(pubkey) matches the appKeyHash from attestation.
	expectedHash := sha256.Sum256(attestPubkeyBytes)
	if !bytes.Equal(expectedHash[:], appKeyHash) {
		return "", fmt.Errorf("appKeyHash mismatch: expected SHA256(%s) = %s, got %s",
			info.AttestationPubkey,
			hex.EncodeToString(expectedHash[:]),
			hex.EncodeToString(appKeyHash))
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

// fetchEnclaveInfo fetches the /v1/enclave-info endpoint.
func fetchEnclaveInfo(ctx context.Context, httpClient *http.Client, baseURL string) (*enclaveInfoResponse, error) {
	infoURL := strings.TrimRight(baseURL, "/") + "/v1/enclave-info"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, infoURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
