package main

import (
	"fmt"

	"github.com/ArkLabsHQ/enclave/client"
	"github.com/spf13/cobra"
)

type verificationOptions struct {
	baseURL string
	client  client.Options
}

func (opts *verificationOptions) addFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&opts.baseURL, "base-url", "", "enclave HTTPS base URL (required)")
	cmd.Flags().StringVar(&opts.client.ExpectedPCR0, "expected-pcr0", "",
		"expected PCR0 hex value (required)")
	cmd.Flags().StringVar(&opts.client.ExpectedTLSKeyHash, "expected-tls-key-hash", "",
		"expected TLS public-key SHA-256 (64 hex characters; empty trusts first verified attestation)")
	cmd.Flags().BoolVar(&opts.client.StrictTLS, "strict-tls", false,
		"also require public CA and hostname validation")
	cmd.Flags().BoolVar(&opts.client.InsecureSkipCOSEVerify, "insecure-skip-cose-verify", false,
		"skip COSE Sign1 + AWS Nitro root chain verification (QEMU/local test only)")
	_ = cmd.MarkFlagRequired("base-url")
	_ = cmd.MarkFlagRequired("expected-pcr0")
}

func (opts verificationOptions) newClient(cmd *cobra.Command) (*client.Client, error) {
	if opts.client.InsecureSkipCOSEVerify {
		_, _ = fmt.Fprintln(
			cmd.ErrOrStderr(),
			"WARNING: skipping attestation COSE signature and AWS Nitro root chain verification — QEMU/local test only",
		)
	}
	return client.New(opts.baseURL, opts.client)
}
