package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

func newCurlCommand() *cobra.Command {
	var opts curlOptions

	cmd := &cobra.Command{
		Use:   "curl <path>",
		Short: "Make an attestation-verified request",
		Long: `Verifies the enclave's Nitro attestation and PCR0, checks
--expected-tls-key-hash when supplied, then makes the requested call over a
TLS connection pinned to the attested public-key fingerprint.

Use 'enclave attest' to obtain the fingerprint for subsequent calls.
Use /enclave/v1/info for runtime, status, and migration information.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.path = args[0]
			return runCurl(cmd, opts)
		},
	}
	opts.addFlags(cmd)
	cmd.Flags().StringVarP(&opts.method, "method", "X", http.MethodGet, "HTTP method")
	cmd.Flags().StringVarP(&opts.data, "data", "d", "", "request body")
	cmd.Flags().
		StringArrayVarP(&opts.headers, "header", "H", nil, "request header, in 'Name: value' form (repeatable)")
	cmd.Flags().
		BoolVarP(&opts.verbose, "verbose", "v", false, "write request and verification details to stderr")
	return cmd
}

type curlOptions struct {
	verificationOptions
	method  string
	data    string
	headers []string
	verbose bool
	path    string
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
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "> %s %s\n", req.Method, req.URL)
	}

	c, err := opts.newClient(cmd)
	if err != nil {
		return err
	}
	resp, err := c.Do(cmd.Context(), req)
	if err != nil {
		return fmt.Errorf("verified request: %w", err)
	}

	if opts.verbose {
		_, _ = fmt.Fprintf(
			cmd.ErrOrStderr(),
			"< %d (PCR0 and attested TLS pin verified)\n",
			resp.StatusCode,
		)
	}
	if _, err := cmd.OutOrStdout().Write(resp.Body); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	if len(resp.Body) == 0 || resp.Body[len(resp.Body)-1] != '\n' {
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
