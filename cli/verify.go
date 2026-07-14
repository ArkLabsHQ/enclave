package cli

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ArkLabsHQ/introspector-enclave/client"
	"github.com/hf/nitrite"
	"github.com/spf13/cobra"
)

func verifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify enclave attestation",
		Long:  "Connects to the enclave, verifies PCR0 attestation, and checks response signatures.",
		RunE:  runVerify,
	}
	cmd.Flags().String("base-url", "", "Enclave base URL (required)")
	cmd.Flags().String("expected-pcr0", "", "Expected PCR0 hex (required)")
	cmd.Flags().Bool("strict-tls", false, "Require CA-signed TLS certificate")
	cmd.Flags().Bool("verify-attestation-key", true, "Verify attestation key via UserData signingKeyHash and test response signature")
	cmd.Flags().Int("wait", 0, "Wait up to N seconds for enclave to become reachable (0 = no retry)")
	_ = cmd.MarkFlagRequired("base-url")
	_ = cmd.MarkFlagRequired("expected-pcr0")
	return cmd
}

func runVerify(cmd *cobra.Command, args []string) error {
	baseURL, _ := cmd.Flags().GetString("base-url")
	pcr0, _ := cmd.Flags().GetString("expected-pcr0")
	strictTLS, _ := cmd.Flags().GetBool("strict-tls")
	doVerifyKey, _ := cmd.Flags().GetBool("verify-attestation-key")
	waitSec, _ := cmd.Flags().GetInt("wait")

	fmt.Printf("[verify] Verifying %s\n", baseURL)

	// Delegate attestation verification, TLS pinning, and key binding to the
	// client package (the same path `enclave curl` uses). The only verify-specific
	// check is the PCR0 upgrade chain.
	c, err := client.New(baseURL, client.Options{
		ExpectedPCR0:   pcr0,
		StrictTLS:      strictTLS,
		SkipKeyBinding: !doVerifyKey,
	})
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	runAllChecks := func() error {
		res, err := c.VerifyAttestation(ctx)
		if err != nil {
			return err
		}
		fmt.Println("[verify] Attestation verified: PCR0 + TLS cert pinned to attested fingerprint.")
		if doVerifyKey && res.AttestationKey != "" {
			fmt.Printf("[verify] Attestation key binding + response signature verified: %s\n", res.AttestationKey)
		}
		return verifyPCR0Chain(ctx, c)
	}

	if waitSec > 0 {
		const interval = 5 * time.Second
		start := time.Now()
		deadline := start.Add(time.Duration(waitSec) * time.Second)
		for attempt := 1; ; attempt++ {
			err := runAllChecks()
			if err == nil {
				break
			}
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return fmt.Errorf("verification failed after %s: %w", time.Since(start).Truncate(time.Second), err)
			}
			// Never sleep past the deadline, so the actual wait matches waitSec.
			sleep := interval
			if sleep > remaining {
				sleep = remaining
			}
			fmt.Printf("[verify] Attempt %d failed (%s), retrying... (%s remaining)\n",
				attempt, shortErr(err), remaining.Truncate(time.Second))
			time.Sleep(sleep)
		}
	} else if err := runAllChecks(); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	fmt.Println("[verify] All checks passed.")
	return nil
}

// --- PCR0 chain verification ---

// verifyPCR0Chain verifies the cryptographic PCR0 upgrade chain. If the enclave
// reports a previous PCR0 with an attestation document, it verifies that document
// against the AWS Nitro root and confirms the PCR0 inside matches previous_pcr0.
func verifyPCR0Chain(ctx context.Context, c *client.Client) error {
	resp, err := c.Get(ctx, "/v1/enclave-info")
	if err != nil {
		return fmt.Errorf("fetch enclave info: %w", err)
	}
	var info enclaveInfoResponse
	if err := json.Unmarshal(resp.Body, &info); err != nil {
		return fmt.Errorf("decode enclave info: %w", err)
	}
	if info.Error != "" {
		return fmt.Errorf("enclave init error: %s", info.Error)
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

	// Zero time skips the expiration check — the attestation was generated at
	// upgrade time, which may have been weeks/months ago.
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
	switch {
	case strings.Contains(s, "TLS handshake timeout"):
		return "TLS handshake timeout"
	case strings.Contains(s, "connection refused"):
		return "connection refused"
	case strings.Contains(s, "i/o timeout"):
		return "i/o timeout"
	case strings.Contains(s, "not yet registered"):
		return "attestation key not yet registered"
	case strings.Contains(s, "enclave init error:"):
		return s
	}
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}
