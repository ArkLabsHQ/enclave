package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ArkLabsHQ/enclave/internal/migration"
	"github.com/hf/nitrite"
)

// MigrationGeneration is the body of GET /enclave/v1/migration: the intent log
// written by the enclave measured as PCR0, each record exactly as stored with
// the time S3 published it.
type MigrationGeneration = migration.Generation

// VerifiedMigrationRecord is a record whose attestation verified.
type VerifiedMigrationRecord struct {
	migration.ObjectV1
	SourcePCR0 string
	// PublishedAt is when S3 published the record. The runtime orders a log and
	// starts a cooldown by it.
	PublishedAt time.Time
	// AttestedAt is when the source enclave attested the record.
	AttestedAt time.Time
}

// MigrationHandoff is a finalised handoff and the request it stood on.
type MigrationHandoff struct {
	Request   VerifiedMigrationRecord
	Finalised VerifiedMigrationRecord
}

// VerifiedGeneration is one generation's verified intent log and what it
// resolves to under the runtime's rules.
type VerifiedGeneration struct {
	PCR0    string
	Records []VerifiedMigrationRecord
	// Handoffs are the generation's finalised handoffs, oldest first. Tied ones,
	// each released under its own key, are all listed, the one in force first.
	Handoffs []MigrationHandoff
	// Pending is the request in force that is neither finalised nor aborted.
	Pending *VerifiedMigrationRecord
	// Ambiguous holds tied records that block any handoff until an abort.
	Ambiguous []VerifiedMigrationRecord
	// Ignored says why each record that does not verify was ignored; the
	// runtime ignores the same records.
	Ignored []error
}

// FetchMigrationGeneration returns the intent log written by the enclave
// measured as pcr0, as GET /enclave/v1/migration?pcr0= serves it.
type FetchMigrationGeneration func(ctx context.Context, pcr0 string) (MigrationGeneration, error)

// MigrationVerifyOptions relaxes or tightens WalkHandoffs.
type MigrationVerifyOptions struct {
	// MinCooldown is the least time between a request's publication and the
	// attestation of the handoff it led to: the runtime finalises only once its
	// clock passes the request's publication plus its cooldown.
	MinCooldown time.Duration
	// InsecureSkipCOSEVerify skips COSE signature and certificate chain
	// verification. For local testing against emulated NSM only.
	InsecureSkipCOSEVerify bool
}

// HandoffWalk is what WalkHandoffs found.
type HandoffWalk struct {
	// Generations are the generations reached, genesis first.
	Generations []VerifiedGeneration
	// Failures are the checks that failed. The walk carries on past each, so
	// every one is reported.
	Failures []error
}

// WalkHandoffs starts at the enclave measured as genesisPCR0 and follows every
// handoff in every log it reaches, so it visits every generation that received
// the state, off the current enclave's path too. A record counts only if the
// generation that wrote it attested it for bucket; any other is ignored, as the
// runtime ignores it. Each log is resolved by the runtime's own rules. A
// handoff that did not wait MinCooldown, a log that cannot be fetched or is
// served for another PCR0, and a currentPCR0 that is not reached are recorded
// as failures.
func WalkHandoffs(
	ctx context.Context,
	fetch FetchMigrationGeneration,
	bucket, genesisPCR0, currentPCR0 string,
	opts MigrationVerifyOptions,
) HandoffWalk {
	genesis := strings.ToLower(genesisPCR0)
	reached := map[string]bool{genesis: true}
	toVisit := []string{genesis}
	var walk HandoffWalk
	for len(toVisit) > 0 {
		pcr0 := toVisit[0]
		toVisit = toVisit[1:]
		generation, err := fetch(ctx, pcr0)
		if err != nil {
			walk.Failures = append(walk.Failures, fmt.Errorf("generation %s: %w", pcr0, err))
			continue
		}
		if generation.PCR0 != pcr0 {
			walk.Failures = append(walk.Failures,
				fmt.Errorf("asked for generation %s, got %s", pcr0, generation.PCR0))
			continue
		}

		resolved := verifyGeneration(bucket, generation, opts.InsecureSkipCOSEVerify)
		for _, handoff := range resolved.Handoffs {
			// A handoff before its cooldown still released the state, so it is
			// recorded and followed.
			gap := handoff.Finalised.AttestedAt.Sub(handoff.Request.PublishedAt)
			if gap < opts.MinCooldown {
				walk.Failures = append(walk.Failures, fmt.Errorf(
					"generation %s finalised %s %s after its request, before the %s cooldown",
					pcr0, handoff.Finalised.TargetPCR0, gap, opts.MinCooldown,
				))
			}
			// A generation reached again was already read whole.
			if reached[handoff.Finalised.TargetPCR0] {
				continue
			}
			reached[handoff.Finalised.TargetPCR0] = true
			toVisit = append(toVisit, handoff.Finalised.TargetPCR0)
		}
		walk.Generations = append(walk.Generations, resolved)
	}

	if !reached[strings.ToLower(currentPCR0)] {
		walk.Failures = append(walk.Failures,
			fmt.Errorf("no handoff from genesis %s reaches %s", genesis, currentPCR0))
	}
	return walk
}

// verifyGeneration verifies every record of one log with the runtime's own
// check, ignores those that fail, and resolves the rest as the runtime does.
func verifyGeneration(
	bucket string,
	generation MigrationGeneration,
	insecureSkipCOSEVerify bool,
) VerifiedGeneration {
	resolved := VerifiedGeneration{PCR0: generation.PCR0}
	verify := storedAttestationVerifier(insecureSkipCOSEVerify)
	var intents []migration.Intent
	for _, record := range generation.Records {
		var object migration.ObjectV1
		if err := json.Unmarshal(record.Object, &object); err != nil {
			resolved.Ignored = append(resolved.Ignored, fmt.Errorf("decode record: %w", err))
			continue
		}
		intent, attestedAt, err := migration.VerifyIntentObject(
			object, generation.PCR0, bucket, record.PublishedAt, verify,
		)
		if err != nil {
			resolved.Ignored = append(resolved.Ignored,
				fmt.Errorf("sequence %d: %w", object.Sequence, err))
			continue
		}
		resolved.Records = append(resolved.Records, VerifiedMigrationRecord{
			ObjectV1:    object,
			SourcePCR0:  generation.PCR0,
			PublishedAt: record.PublishedAt,
			AttestedAt:  attestedAt,
		})
		intents = append(intents, intent)
	}

	state := migration.ResolveGeneration(intents)
	for _, handoff := range state.Handoffs {
		resolved.Handoffs = append(resolved.Handoffs, MigrationHandoff{
			Request:   resolved.Records[handoff.Request],
			Finalised: resolved.Records[handoff.Finalised],
		})
	}
	if state.Current >= 0 && resolved.Records[state.Current].Action == migration.Requested {
		resolved.Pending = &resolved.Records[state.Current]
	}
	for _, i := range state.Ambiguous {
		resolved.Ambiguous = append(resolved.Ambiguous, resolved.Records[i])
	}
	return resolved
}

// storedAttestationVerifier verifies stored records' attestations for the
// shared migration check.
func storedAttestationVerifier(insecureSkipCOSEVerify bool) migration.VerifyAttestationFunc {
	return func(b64 string) (migration.Attestation, error) {
		result, err := verifyStoredAttestation(b64, insecureSkipCOSEVerify)
		if err != nil {
			return migration.Attestation{}, err
		}
		return migration.Attestation{
			PCRs:      result.Document.PCRs,
			UserData:  result.Document.UserData,
			Timestamp: time.UnixMilli(int64(result.Document.Timestamp)).UTC(),
		}, nil
	}
}

// verifyStoredAttestation verifies an attestation at the time it was made: a
// stored record outlives the short-lived certificates that signed it.
func verifyStoredAttestation(b64 string, insecureSkipCOSEVerify bool) (*nitrite.Result, error) {
	doc, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode attestation: %w", err)
	}
	result, err := parseCOSEPayloadInsecure(doc)
	if err != nil {
		return nil, fmt.Errorf("parse attestation: %w", err)
	}
	if !insecureSkipCOSEVerify {
		result, err = nitrite.Verify(doc, nitrite.VerifyOptions{
			CurrentTime: time.UnixMilli(int64(result.Document.Timestamp)),
		})
		if err != nil {
			return nil, fmt.Errorf("attestation verification: %w", err)
		}
	}
	if result.Document == nil {
		return nil, fmt.Errorf("attestation missing document")
	}
	return result, nil
}
