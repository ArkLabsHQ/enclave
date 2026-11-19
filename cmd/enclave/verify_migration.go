package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ArkLabsHQ/enclave/client"
	"github.com/spf13/cobra"
)

func newVerifyMigrationCommand() *cobra.Command {
	var (
		baseURL     string
		expectedPCR string
		genesisPCR0 string
		skipCOSE    bool
		minCooldown time.Duration
	)

	cmd := &cobra.Command{
		Use:   "verify-migration",
		Short: "Verify an enclave's attested migration history",
		Long: `Walks every handoff from --genesis-pcr0: fetches the genesis migration intent
log from GET /enclave/v1/migration, then the log of every generation it handed
off to, and so on, all as signed responses. Verifies each record's attestation
by the generation that wrote it, resolves each log by the runtime's rules,
checks that every finalised handoff waited --min-cooldown after its request,
and requires the enclave at --expected-pcr0 to be reached. Reports every
migration handed off and any migration still pending.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVerifyMigration(cmd, verifyMigrationOptions{
				baseURL:     baseURL,
				expectedPCR: expectedPCR,
				genesisPCR0: genesisPCR0,
				skipCOSE:    skipCOSE,
				minCooldown: minCooldown,
			})
		},
	}
	cmd.Flags().StringVar(&baseURL, "base-url", "", "enclave HTTPS base URL (required)")
	cmd.Flags().StringVar(&expectedPCR, "expected-pcr0", "", "expected PCR0 hex value (required)")
	cmd.Flags().
		StringVar(&genesisPCR0, "genesis-pcr0", "", "PCR0 of the deployment's genesis (required)")
	cmd.Flags().
		BoolVar(&skipCOSE, "insecure-skip-cose-verify", false,
			"skip COSE Sign1 + AWS Nitro root chain verification (QEMU/local test only)")
	cmd.Flags().
		DurationVar(&minCooldown, "min-cooldown", 24*time.Hour,
			"least attested time between a request and its finalised handoff")
	_ = cmd.MarkFlagRequired("base-url")
	_ = cmd.MarkFlagRequired("expected-pcr0")
	_ = cmd.MarkFlagRequired("genesis-pcr0")
	return cmd
}

type verifyMigrationOptions struct {
	baseURL     string
	expectedPCR string
	genesisPCR0 string
	skipCOSE    bool
	minCooldown time.Duration
}

func runVerifyMigration(cmd *cobra.Command, opts verifyMigrationOptions) error {
	if opts.skipCOSE {
		fmt.Fprintln(
			os.Stderr,
			"WARNING: skipping attestation COSE signature and AWS Nitro root chain verification — QEMU/local test only",
		)
	}

	c, err := client.New(opts.baseURL, client.Options{
		ExpectedPCR0:           opts.expectedPCR,
		InsecureSkipCOSEVerify: opts.skipCOSE,
		SignedResponses:        true,
	})
	if err != nil {
		return err
	}
	// Every record's attestation names the intent bucket.
	var info struct {
		MigrationIntentBucket string `json:"migration_intent_bucket"`
	}
	if err := getVerifiedJSON(cmd.Context(), c, "/enclave/v1/info", &info); err != nil {
		return err
	}
	fetch := func(ctx context.Context, pcr0 string) (client.MigrationGeneration, error) {
		var generation client.MigrationGeneration
		err := getVerifiedJSON(ctx, c, "/enclave/v1/migration?pcr0="+pcr0, &generation)
		return generation, err
	}

	walk := client.WalkHandoffs(
		cmd.Context(), fetch, info.MigrationIntentBucket, opts.genesisPCR0, opts.expectedPCR,
		client.MigrationVerifyOptions{
			MinCooldown:            opts.minCooldown,
			InsecureSkipCOSEVerify: opts.skipCOSE,
		},
	)
	var records, handoffs, pending, ignored int
	for _, generation := range walk.Generations {
		for _, err := range generation.Ignored {
			fmt.Printf("%s: ignored a record that does not verify: %v\n", generation.PCR0, err)
		}
		for _, record := range generation.Records {
			fmt.Printf("%s: record %d %s %s, attested %s\n", generation.PCR0, record.Sequence,
				record.Action, record.TargetPCR0, record.AttestedAt.Format(time.RFC3339))
		}
		for _, handoff := range generation.Handoffs {
			fmt.Printf(
				"%s: handed off to %s, requested %s (sequence %d), finalised %s (sequence %d)\n",
				generation.PCR0, handoff.Finalised.TargetPCR0,
				handoff.Request.AttestedAt.Format(time.RFC3339), handoff.Request.Sequence,
				handoff.Finalised.AttestedAt.Format(time.RFC3339), handoff.Finalised.Sequence,
			)
		}
		if request := generation.Pending; request != nil {
			fmt.Printf(
				"%s: pending migration to %s, requested %s (sequence %d), "+
					"neither finalised nor aborted\n",
				generation.PCR0, request.TargetPCR0,
				request.AttestedAt.Format(time.RFC3339), request.Sequence,
			)
			pending++
		}
		for _, record := range generation.Ambiguous {
			fmt.Printf("%s: tied %s for %s at sequence %d blocks any handoff until an abort\n",
				generation.PCR0, record.Action, record.TargetPCR0, record.Sequence)
		}
		records += len(generation.Records)
		handoffs += len(generation.Handoffs)
		ignored += len(generation.Ignored)
	}
	for _, failure := range walk.Failures {
		fmt.Printf("failed: %v\n", failure)
	}
	fmt.Printf(
		"verified %d records across %d generations: "+
			"%d handed off, %d pending, %d ignored, %d failed\n",
		records, len(walk.Generations), handoffs, pending, ignored, len(walk.Failures),
	)
	if len(walk.Failures) > 0 {
		return fmt.Errorf("%d migration checks failed", len(walk.Failures))
	}
	return nil
}

// getVerifiedJSON fetches path as a verified, signed response and decodes its body.
func getVerifiedJSON(ctx context.Context, c *client.Client, path string, out any) error {
	resp, err := c.Get(ctx, path)
	if err != nil {
		return fmt.Errorf("verified request %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d: %s", path, resp.StatusCode, resp.Body)
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
