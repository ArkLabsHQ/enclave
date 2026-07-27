package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/ArkLabsHQ/enclave/client"
	"github.com/spf13/cobra"
)

func newCurlCommand() *cobra.Command {
	var (
		baseURL     string
		expectedPCR string
		method      string
		data        string
		headers     []string
		strictTLS   bool
		verbose     bool
	)

	cmd := &cobra.Command{
		Use:   "curl <path>",
		Short: "Make an attestation-verified request",
		Long: `Verifies the enclave's Nitro attestation and PCR0, binds the live TLS
certificate to the attestation document, then makes the requested call. The
response must carry a valid enclave response signature.

Use /v1/enclave-info for runtime, status, and migration information.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCurl(cmd, curlOptions{
				baseURL:     baseURL,
				expectedPCR: expectedPCR,
				method:      method,
				data:        data,
				headers:     headers,
				strictTLS:   strictTLS,
				verbose:     verbose,
				path:        args[0],
			})
		},
	}
	cmd.Flags().StringVar(&baseURL, "base-url", "", "enclave HTTPS base URL (required)")
	cmd.Flags().StringVar(&expectedPCR, "expected-pcr0", "", "expected PCR0 hex value (required)")
	cmd.Flags().StringVarP(&method, "method", "X", http.MethodGet, "HTTP method")
	cmd.Flags().StringVarP(&data, "data", "d", "", "request body")
	cmd.Flags().
		StringArrayVarP(&headers, "header", "H", nil, "request header, in 'Name: value' form (repeatable)")
	cmd.Flags().
		BoolVar(&strictTLS, "strict-tls", false, "also require public CA and hostname validation")
	cmd.Flags().
		BoolVarP(&verbose, "verbose", "v", false, "write request and verification details to stderr")
	_ = cmd.MarkFlagRequired("base-url")
	_ = cmd.MarkFlagRequired("expected-pcr0")
	return cmd
}

type curlOptions struct {
	baseURL     string
	expectedPCR string
	method      string
	data        string
	headers     []string
	strictTLS   bool
	verbose     bool
	path        string
}

func runCurl(cmd *cobra.Command, opts curlOptions) error {
	baseURL := strings.TrimRight(opts.baseURL, "/")
	path := opts.path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	var body io.Reader
	if opts.data != "" {
		body = strings.NewReader(opts.data)
	}
	req, err := http.NewRequestWithContext(cmd.Context(), opts.method, baseURL+path, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if opts.data != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, header := range opts.headers {
		name, value, ok := strings.Cut(header, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return fmt.Errorf("invalid header %q (want 'Name: value')", header)
		}
		req.Header.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}

	if opts.verbose {
		fmt.Fprintf(os.Stderr, "> %s %s\n", req.Method, req.URL)
	}

	c, err := client.New(baseURL, client.Options{
		ExpectedPCR0: opts.expectedPCR,
		StrictTLS:    opts.strictTLS,
	})
	if err != nil {
		return err
	}
	resp, err := c.Do(cmd.Context(), req)
	if err != nil {
		return fmt.Errorf("verified request: %w", err)
	}
	if !resp.SignatureVerified {
		return fmt.Errorf("enclave response signature was missing or invalid")
	}

	if opts.verbose {
		fmt.Fprintf(
			os.Stderr,
			"< %d (PCR0, attestation key, TLS pin, and response signature verified)\n",
			resp.StatusCode,
		)
	}
	if _, err := os.Stdout.Write(resp.Body); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	if len(resp.Body) == 0 || resp.Body[len(resp.Body)-1] != '\n' {
		_, _ = fmt.Fprintln(os.Stdout)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
