package introspector_enclave

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/hf/nitrite"
	"github.com/spf13/cobra"
)

// errAppKeyNotReady is returned when the attestation document's appKeyHash is
// all zeros, meaning the app hasn't registered its key with nitriding yet.
var errAppKeyNotReady = errors.New("attestation key not yet registered (appKeyHash is all zeros)")

func verifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify enclave attestation",
		Long:  "Connects to the enclave, verifies PCR0 attestation, and checks response signatures.",
		RunE:  runVerify,
	}
	cmd.Flags().String("base-url", "", "Enclave base URL (overrides CDK outputs)")
	cmd.Flags().Bool("verify-build", false, "Rebuild EIF locally and compare PCR0")
	cmd.Flags().Bool("strict-tls", false, "Require CA-signed TLS certificate")
	cmd.Flags().String("expected-pcr0", "", "Expected PCR0 hex (overrides auto-detection)")
	cmd.Flags().Bool("verify-attestation-key", true, "Verify attestation key via UserData appKeyHash and test response signature")
	cmd.Flags().Int("wait", 0, "Wait up to N seconds for enclave to become reachable (0 = no retry)")
	return cmd
}

func runVerify(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	root, err := findRepoRoot()
	if err != nil {
		return err
	}

	baseURL, _ := cmd.Flags().GetString("base-url")
	if baseURL == "" {
		outputs, err := loadCDKOutputs(root)
		if err != nil {
			return err
		}

		stack := cfg.stackName()
		elasticIP := outputs.getOutput(stack, "ElasticIP", "Elastic IP")
		if elasticIP == "" {
			return fmt.Errorf("ElasticIP not found in cdk-outputs.json (use --base-url to override)")
		}

		baseURL = "https://" + elasticIP
	}
	fmt.Printf("[verify] Verifying %s\n", baseURL)

	pcr0, _ := cmd.Flags().GetString("expected-pcr0")

	if verifyBuild, _ := cmd.Flags().GetBool("verify-build"); verifyBuild && pcr0 == "" {
		derived, err := buildAndExtractPCR0(root, cfg.Version, cfg.Region, cfg.NixImage)
		if err != nil {
			return fmt.Errorf("build verification failed: %w", err)
		}
		fmt.Printf("[verify] Derived PCR0 from build: %s\n", derived)
		pcr0 = derived
	}

	strictTLS, _ := cmd.Flags().GetBool("strict-tls")
	client := verifyHTTPClient(!strictTLS)

	waitSec, _ := cmd.Flags().GetInt("wait")
	doVerifyKey, _ := cmd.Flags().GetBool("verify-attestation-key")

	// runAllChecks performs attestation verification and optionally key binding check.
	// Returns nil on full success, or an error (which may be retryable).
	runAllChecks := func() error {
		result, err := verifyAttestation(client, baseURL, pcr0)
		if err != nil {
			return err
		}
		if doVerifyKey {
			if err := verifyAttestationKeyBinding(client, baseURL, result); err != nil {
				return err
			}
		}
		if err := verifyPCR0Chain(client, baseURL); err != nil {
			return fmt.Errorf("PCR0 chain: %w", err)
		}
		return nil
	}

	if waitSec > 0 {
		deadline := time.Now().Add(time.Duration(waitSec) * time.Second)
		interval := 5 * time.Second
		attempt := 0
		for {
			attempt++
			err = runAllChecks()
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("verification failed after %ds: %w", waitSec, err)
			}
			remaining := time.Until(deadline).Truncate(time.Second)
			fmt.Printf("[verify] Attempt %d failed (%s), retrying... (%s remaining)\n", attempt, shortErr(err), remaining)
			time.Sleep(interval)
		}
	} else {
		if err := runAllChecks(); err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
	}

	fmt.Println("[verify] All checks passed.")
	return nil
}

// --- Attestation verification ---

func verifyAttestation(client *http.Client, baseURL, expectedPCR0 string) (*nitrite.Result, error) {
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)

	url := strings.TrimRight(baseURL, "/") + "/enclave/attestation?nonce=" + nonceHex
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
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

	result, err := nitrite.Verify(docBytes, nitrite.VerifyOptions{
		CurrentTime: time.Now(),
	})
	if err != nil {
		if result != nil && result.SignatureOK {
			fmt.Fprintf(os.Stderr, "[verify] warning: attestation signature OK but validation error: %v\n", err)
		} else {
			return nil, err
		}
	}

	if result == nil || result.Document == nil {
		return nil, fmt.Errorf("attestation missing document")
	}

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

	if expectedPCR0 != "" {
		pcr0, ok := result.Document.PCRs[0]
		if !ok {
			return nil, fmt.Errorf("attestation missing PCR0")
		}

		if !strings.EqualFold(hex.EncodeToString(pcr0), expectedPCR0) {
			return nil, fmt.Errorf("PCR0 mismatch: expected %s, got %s", expectedPCR0, hex.EncodeToString(pcr0))
		}
	}

	fmt.Println("[verify] Attestation document verified.")
	return result, nil
}

// --- Attestation key binding ---

// verifyAttestationKeyBinding verifies the enclave's ephemeral attestation key
// by checking that the pubkey from /v1/enclave-info matches the appKeyHash in
// the attestation document's UserData, then verifying a live response signature.
//
// UserData format (nitriding): [0x12, 0x20, tlsKeyHash:32] ++ [0x12, 0x20, appKeyHash:32]
// Total 68 bytes. appKeyHash is at bytes 36:68 (after the 2nd multihash prefix).
func verifyAttestationKeyBinding(client *http.Client, baseURL string, attestResult *nitrite.Result) error {
	if attestResult == nil || attestResult.Document == nil {
		return fmt.Errorf("no attestation result to verify against")
	}

	userData := attestResult.Document.UserData
	if len(userData) < 68 {
		fmt.Println("[verify] UserData too short for appKeyHash (enclave may not support attestation key)")
		return nil
	}

	if userData[34] != 0x12 || userData[35] != 0x20 {
		return fmt.Errorf("UserData missing multihash prefix at offset 34 (got %02x %02x)", userData[34], userData[35])
	}
	appKeyHash := userData[36:68]

	allZero := true
	for _, b := range appKeyHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return errAppKeyNotReady
	}

	info, err := fetchEnclaveInfo(client, baseURL)
	if err != nil {
		return fmt.Errorf("fetch enclave info: %w", err)
	}
	if info.AttestationPubkey == "" {
		return fmt.Errorf("enclave reports no attestation pubkey but appKeyHash is set")
	}

	attestPubkeyBytes, err := hex.DecodeString(info.AttestationPubkey)
	if err != nil {
		return fmt.Errorf("decode attestation pubkey hex: %w", err)
	}

	expectedHash := sha256.Sum256(attestPubkeyBytes)
	if !bytes.Equal(expectedHash[:], appKeyHash) {
		return fmt.Errorf("appKeyHash mismatch: expected SHA256(%s) = %s, got %s",
			info.AttestationPubkey,
			hex.EncodeToString(expectedHash[:]),
			hex.EncodeToString(appKeyHash))
	}

	fmt.Printf("[verify] Attestation key binding verified via appKeyHash: %s\n", info.AttestationPubkey)

	if err := verifyResponseSignature(client, baseURL, info.AttestationPubkey); err != nil {
		return fmt.Errorf("response signature verification: %w", err)
	}

	return nil
}

// verifyResponseSignature fetches /v1/enclave-info and verifies the
// X-Attestation-Signature header against the attestation pubkey.
func verifyResponseSignature(client *http.Client, baseURL, attestPubkeyHex string) error {
	infoURL := strings.TrimRight(baseURL, "/") + "/v1/enclave-info"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, infoURL, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	sigHex := resp.Header.Get("X-Attestation-Signature")
	if sigHex == "" {
		return fmt.Errorf("response missing X-Attestation-Signature header")
	}

	pubkeyBytes, err := hex.DecodeString(attestPubkeyHex)
	if err != nil {
		return fmt.Errorf("decode pubkey: %w", err)
	}
	// The attestation pubkey is compressed (33 bytes). Extract x-only (32 bytes)
	// by dropping the prefix byte.
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

	fmt.Println("[verify] Response signature verified (X-Attestation-Signature valid).")
	return nil
}

// --- PCR0 chain verification ---

// verifyPCR0Chain verifies the cryptographic PCR0 upgrade chain.
// If the enclave reports a previous PCR0 with an attestation document,
// it verifies the document against the AWS Nitro root certificate and
// confirms the PCR0 inside matches the reported previous_pcr0.
func verifyPCR0Chain(client *http.Client, baseURL string) error {
	info, err := fetchEnclaveInfo(client, baseURL)
	if err != nil {
		return fmt.Errorf("fetch enclave info: %w", err)
	}

	if info.PreviousPCR0 == "genesis" {
		fmt.Println("[verify] PCR0 chain: genesis (first deployment)")
		return nil
	}

	if info.PreviousPCR0Attestation == "" {
		fmt.Printf("[verify] PCR0 chain: previous_pcr0=%s (no attestation proof — unverified)\n", info.PreviousPCR0)
		return nil
	}

	attestBytes, err := base64.StdEncoding.DecodeString(info.PreviousPCR0Attestation)
	if err != nil {
		return fmt.Errorf("decode PCR0 attestation: %w", err)
	}

	// Verify attestation document against AWS Nitro root certificate.
	// Use zero time to skip expiration check — the attestation was generated
	// at upgrade time, which may have been weeks/months ago.
	result, err := nitrite.Verify(attestBytes, nitrite.VerifyOptions{})
	if err != nil {
		if result != nil && result.SignatureOK {
			fmt.Fprintf(os.Stderr, "[verify] PCR0 attestation signature OK but certificate warning: %v\n", err)
		} else {
			return fmt.Errorf("PCR0 attestation verification failed: %w", err)
		}
	}

	if result == nil || result.Document == nil {
		return fmt.Errorf("PCR0 attestation missing document payload")
	}

	pcr0, ok := result.Document.PCRs[0]
	if !ok {
		return fmt.Errorf("PCR0 not found in attestation document")
	}
	attestedPCR0 := hex.EncodeToString(pcr0)

	if !strings.EqualFold(attestedPCR0, info.PreviousPCR0) {
		return fmt.Errorf("PCR0 chain mismatch: reported previous_pcr0=%s, attested=%s",
			info.PreviousPCR0, attestedPCR0)
	}

	fmt.Printf("[verify] PCR0 chain verified: previous_pcr0=%s (cryptographic proof from NSM attestation)\n", info.PreviousPCR0)
	return nil
}

// --- Helpers ---

type enclaveInfoResponse struct {
	Version                 string `json:"version"`
	PreviousPCR0            string `json:"previous_pcr0"`
	PreviousPCR0Attestation string `json:"previous_pcr0_attestation,omitempty"`
	AttestationPubkey       string `json:"attestation_pubkey,omitempty"`
	Error                   string `json:"error,omitempty"`
}

func fetchEnclaveInfo(client *http.Client, baseURL string) (*enclaveInfoResponse, error) {
	infoURL := strings.TrimRight(baseURL, "/") + "/v1/enclave-info"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, infoURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
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

func verifyHTTPClient(insecure bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

// shortErr returns a concise error string for retry logging.
func shortErr(err error) string {
	s := err.Error()
	if strings.Contains(s, "TLS handshake timeout") {
		return "TLS handshake timeout"
	}
	if strings.Contains(s, "connection refused") {
		return "connection refused"
	}
	if strings.Contains(s, "i/o timeout") {
		return "i/o timeout"
	}
	if errors.Is(err, errAppKeyNotReady) {
		return "attestation key not yet registered"
	}
	if strings.Contains(s, "enclave init error:") {
		return s
	}
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}

func buildAndExtractPCR0(repoPath, version, region, nixImage string) (string, error) {
	absRepo, err := filepath.Abs(repoPath)
	if err != nil {
		return "", fmt.Errorf("resolve repo path: %w", err)
	}

	resultPath := filepath.Join(absRepo, "enclave", "artifacts")
	_ = os.RemoveAll(resultPath)
	_ = os.MkdirAll(resultPath, 0o755)

	fmt.Println("[verify] Building EIF via NixOS Docker (reproducible)...")
	if nixImage == "" {
		nixImage = "nixos/nix:2.24.9"
	}
	if version == "" {
		version = "0.0.1"
	}
	if region == "" {
		region = "us-east-1"
	}

	nixCmd := "git config --global --add safe.directory /src && " +
		"nix build --impure --extra-experimental-features 'nix-command flakes' " +
		"--option download-attempts 3 --out-link flake_result .#eif && " +
		"cp flake_result/image.eif /src/enclave/artifacts/image.eif && " +
		"cp flake_result/pcr.json /src/enclave/artifacts/pcr.json"

	env := []string{
		"VERSION=" + version,
		"AWS_REGION=" + region,
	}

	if err := runContainer(context.Background(), nixImage, nixCmd, absRepo, "/src", env); err != nil {
		return "", fmt.Errorf("docker nix build failed: %w", err)
	}

	pcrPath := filepath.Join(resultPath, "pcr.json")
	pcrData, err := os.ReadFile(pcrPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", pcrPath, err)
	}

	var buildOutput PCRValues
	if err := json.Unmarshal(pcrData, &buildOutput); err != nil {
		return "", fmt.Errorf("parse pcr.json: %w", err)
	}

	if len(buildOutput.PCR0) != 96 {
		return "", fmt.Errorf("unexpected PCR0 length %d (expected 96 hex chars): %q", len(buildOutput.PCR0), buildOutput.PCR0)
	}

	fmt.Printf("[verify] EIF built successfully\n")
	fmt.Printf("[verify] PCR0: %s\n", buildOutput.PCR0)

	return buildOutput.PCR0, nil
}
