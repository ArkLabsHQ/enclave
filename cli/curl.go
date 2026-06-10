package cli

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/ArkLabsHQ/introspector-enclave/client"
	"github.com/spf13/cobra"
)

func curlCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "curl <path>",
		Short: "Call an endpoint on the deployed enclave (attestation-verified by default)",
		Long: `Makes an HTTP request to the deployed enclave, auto-discovering the
endpoint from tofu outputs (Elastic IP).

By default the request is verified: the enclave's attestation is checked
against --expected-pcr0 and the live TLS certificate is pinned to the
fingerprint signed into that attestation, so the connection is proven to
terminate inside the enclave. The request is only sent once the pin holds.

Use --insecure for raw, unverified diagnostics (warns on stderr).

Examples:
  enclave curl --expected-pcr0 <hex> /v1/enclave-info
  enclave curl --insecure /health
  enclave curl --expected-pcr0 <hex> -X POST -d '{"k":"v"}' /my-endpoint`,
		Args: cobra.ExactArgs(1),
		RunE: runCurl,
	}
	cmd.Flags().StringP("method", "X", "GET", "HTTP method")
	cmd.Flags().StringP("data", "d", "", "Request body")
	cmd.Flags().StringArrayP("header", "H", nil, "Custom header (repeatable, format: 'Key: Value')")
	cmd.Flags().String("base-url", "", "Override enclave endpoint URL")
	cmd.Flags().BoolP("verbose", "v", false, "Print request details and response headers")
	cmd.Flags().String("expected-pcr0", "", "Expected PCR0 hex (required unless --insecure)")
	cmd.Flags().Bool("insecure", false, "Skip attestation + TLS pinning (raw, unverified)")
	cmd.Flags().Bool("strict-tls", false, "Add public CA/hostname validation on top of attestation pinning")
	return cmd
}

func runCurl(cmd *cobra.Command, args []string) error {
	path := args[0]
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	method, _ := cmd.Flags().GetString("method")
	data, _ := cmd.Flags().GetString("data")
	headers, _ := cmd.Flags().GetStringArray("header")
	baseURL, _ := cmd.Flags().GetString("base-url")
	verbose, _ := cmd.Flags().GetBool("verbose")
	expectedPCR0, _ := cmd.Flags().GetString("expected-pcr0")
	insecure, _ := cmd.Flags().GetBool("insecure")
	strictTLS, _ := cmd.Flags().GetBool("strict-tls")

	if insecure && strictTLS {
		return fmt.Errorf("--insecure and --strict-tls are mutually exclusive")
	}
	if !insecure && expectedPCR0 == "" {
		return fmt.Errorf("--expected-pcr0 is required (or pass --insecure to skip verification)")
	}

	// Discover endpoint from tofu outputs if not overridden.
	if baseURL == "" {
		root, err := findRepoRoot()
		if err != nil {
			return err
		}
		outputs, err := loadTofuOutputs(root)
		if err != nil {
			return err
		}
		elasticIP := outputs.getOutput("elastic_ip")
		if elasticIP == "" {
			return fmt.Errorf("elastic_ip not found in tofu outputs (run 'tofu apply' first, or use --base-url to specify the endpoint)")
		}
		baseURL = "https://" + elasticIP
	}
	baseURL = strings.TrimRight(baseURL, "/")

	// Build request.
	var body io.Reader
	if data != "" {
		body = strings.NewReader(data)
	}
	req, err := http.NewRequestWithContext(cmd.Context(), method, baseURL+path, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if data != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid header format %q (expected 'Key: Value')", h)
		}
		req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "> %s %s\n", method, baseURL+path)
		for k, vs := range req.Header {
			for _, v := range vs {
				fmt.Fprintf(os.Stderr, "> %s: %s\n", k, v)
			}
		}
		fmt.Fprintln(os.Stderr)
	}

	if insecure {
		fmt.Fprintln(os.Stderr, "WARNING: --insecure skips attestation and TLS pinning; this connection is NOT proven to terminate inside the enclave.")
		return rawCurl(req, verbose)
	}

	// Verified: pin the live cert to the attested fingerprint, then send the
	// user's request on the pinned connection (#129: curl checks PCR0 only).
	c, err := client.New(baseURL, client.Options{ExpectedPCR0: expectedPCR0, StrictTLS: strictTLS, SkipKeyBinding: true})
	if err != nil {
		return err
	}
	resp, err := c.Do(cmd.Context(), req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "< %d (attestation verified: PCR0 + TLS cert pinned)\n", resp.StatusCode)
		for k, vs := range resp.Header {
			for _, v := range vs {
				fmt.Fprintf(os.Stderr, "< %s: %s\n", k, v)
			}
		}
		fmt.Fprintln(os.Stderr)
	}
	_, _ = os.Stdout.Write(resp.Body)
	fmt.Println()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// rawCurl executes an unverified request (the --insecure path).
func rawCurl(req *http.Request, verbose bool) error {
	resp, err := verifyHTTPClient(true).Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if verbose {
		fmt.Fprintf(os.Stderr, "< %s\n", resp.Status)
		for k, vs := range resp.Header {
			for _, v := range vs {
				fmt.Fprintf(os.Stderr, "< %s: %s\n", k, v)
			}
		}
		fmt.Fprintln(os.Stderr)
	}
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	fmt.Println()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
