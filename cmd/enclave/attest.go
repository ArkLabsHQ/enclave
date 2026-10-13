package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newAttestCommand() *cobra.Command {
	var opts verificationOptions
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Verify attestation and print the TLS public-key fingerprint",
		Long: `Verifies the enclave's Nitro attestation, nonce, and expected PCR0, then
prints the attested TLS public-key SHA-256 as 64 hex characters and a newline.
If --expected-tls-key-hash is supplied, the attested fingerprint must match it.

Save this value once and pass it to subsequent calls with --expected-tls-key-hash,
including when accepting a successor image's PCR0. No application request is made.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := opts.newClient(cmd)
			if err != nil {
				return err
			}
			result, err := c.VerifyAttestation(cmd.Context())
			if err != nil {
				return fmt.Errorf("verify attestation: %w", err)
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), result.TLSKeyHash); err != nil {
				return fmt.Errorf("write fingerprint: %w", err)
			}
			return nil
		},
	}
	opts.addFlags(cmd)
	return cmd
}
