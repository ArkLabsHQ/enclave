package introspector_enclave

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func curlCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "curl <path>",
		Short: "Call an endpoint on the deployed enclave",
		Long: `Makes an HTTP request to the deployed enclave, auto-discovering the
endpoint from CDK outputs (Elastic IP). TLS verification is skipped
by default since nitriding uses self-signed certificates.

Examples:
  enclave curl /health
  enclave curl /v1/enclave-info
  enclave curl -X POST -d '{"pcr":16}' /v1/extend-pcr
  enclave curl -H "Content-Type: application/json" /my-endpoint
  enclave curl --base-url https://my-domain.com /api/data`,
		Args: cobra.ExactArgs(1),
		RunE: runCurl,
	}
	cmd.Flags().StringP("method", "X", "GET", "HTTP method")
	cmd.Flags().StringP("data", "d", "", "Request body")
	cmd.Flags().StringArrayP("header", "H", nil, "Custom header (repeatable, format: 'Key: Value')")
	cmd.Flags().String("base-url", "", "Override enclave endpoint URL")
	cmd.Flags().BoolP("verbose", "v", false, "Print request details and response headers")
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

	// Discover endpoint from CDK outputs if not overridden.
	if baseURL == "" {
		root, err := findRepoRoot()
		if err != nil {
			return err
		}
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		outputs, err := loadCDKOutputs(root)
		if err != nil {
			return err
		}
		stack := cfg.stackName()
		elasticIP := outputs.getOutput(stack, "ElasticIP", "Elastic IP")
		if elasticIP == "" {
			return fmt.Errorf("ElasticIP not found in cdk-outputs.json\nRun 'enclave deploy' first, or use --base-url to specify the endpoint.")
		}
		baseURL = "https://" + elasticIP
	}

	url := baseURL + path

	// Build request.
	var body io.Reader
	if data != "" {
		body = strings.NewReader(data)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Set default Content-Type for POST/PUT with body.
	if data != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		req.Header.Set("Content-Type", "application/json")
	}

	// Apply custom headers.
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid header format %q (expected 'Key: Value')", h)
		}
		req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "> %s %s\n", method, url)
		for k, vs := range req.Header {
			for _, v := range vs {
				fmt.Fprintf(os.Stderr, "> %s: %s\n", k, v)
			}
		}
		fmt.Fprintln(os.Stderr)
	}

	// Execute request (skip TLS verification for self-signed nitriding certs).
	client := verifyHTTPClient(true)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if verbose {
		fmt.Fprintf(os.Stderr, "< %s\n", resp.Status)
		for k, vs := range resp.Header {
			for _, v := range vs {
				fmt.Fprintf(os.Stderr, "< %s: %s\n", k, v)
			}
		}
		fmt.Fprintln(os.Stderr)
	}

	// Write response body to stdout.
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Print trailing newline if output doesn't end with one.
	fmt.Println()

	// Return error for non-2xx status codes.
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return nil
}
