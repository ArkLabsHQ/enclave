package runtime

// The ancestor-key audit. Migration is strictly additive: every generation's
// KMSKeyID, ciphertexts and receipts survive under its own PCR0 forever, so a
// retired generation keeps a key that can still decrypt state until an operator
// removes it. Walking MigrationPreviousPCR0 backwards and probing each
// generation's key turns that removal into something an auditor can observe.

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	// ancestryRefreshInterval is how long a snapshot is served before a refresh is
	// kicked. Fixed rather than configurable: the only thing that moves is an
	// operator-initiated key deletion, which has a multi-day window.
	ancestryRefreshInterval = 24 * time.Hour

	ancestryNotYetProbed = "ancestor key audit has not completed yet"
)

// AncestorGeneration reports one ancestor enclave generation and the fate of the
// KMS key it used.
type AncestorGeneration struct {
	PCR0         string     `json:"pcr0"`
	KeyID        string     `json:"key_id,omitempty"`
	State        string     `json:"state"`
	CheckedVia   string     `json:"checked_via"`
	DeletionDate *time.Time `json:"deletion_date,omitempty"`
}

type GenesisOrigin struct {
	PCR0        string     `json:"pcr0"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	Attestation string     `json:"attestation,omitempty"`
}

// AncestryInfo is the ancestor-key audit block of GET /enclave/v1/info.
// Generations runs newest first: index 0 is the immediate predecessor and the
// last entry is the oldest generation reached. Complete reports only what the
// walk observed — that it ran out of predecessors rather than stopping on a
// cycle, a malformed record or an SSM failure, which Reason explains. Whether
// that oldest generation is the deployment's origin is the client's call, made
// against the Genesis record's own attestation. CheckedAt is null until the first refresh
// lands, so a caller can always tell "not yet audited" from "audited and clean".
type AncestryInfo struct {
	Generations []AncestorGeneration `json:"generations"`
	Genesis     *GenesisOrigin       `json:"genesis,omitempty"`
	Complete    bool                 `json:"complete"`
	Reason      string               `json:"reason,omitempty"`
	CheckedAt   *time.Time           `json:"checked_at"`
}

// Ancestry serves the ancestor-key audit.
//
// Snapshot neither blocks nor fails by construction, so the info endpoint can
// never be made slow or unavailable by SSM or KMS.
type Ancestry interface {
	Start(ctx context.Context)
	Snapshot() *AncestryInfo
}

// NewAncestry builds the audit; a nil genesis serves no origin record.
func NewAncestry(nsm NSM, ssm SSM, keys KeyAuditor, genesis *genesisLog) Ancestry {
	return &ancestry{
		nsm:     nsm,
		ssm:     ssm,
		keys:    keys,
		genesis: genesis,
		snap: &AncestryInfo{
			Generations: []AncestorGeneration{},
			Reason:      ancestryNotYetProbed,
		},
	}
}

type ancestry struct {
	nsm     NSM
	ssm     SSM
	keys    KeyAuditor
	genesis *genesisLog

	mu         sync.Mutex
	ctx        context.Context
	snap       *AncestryInfo
	refreshing bool
}

// Start binds the process context and kicks an eager first refresh, so the first
// caller usually finds a populated snapshot. It does not delay boot.
func (a *ancestry) Start(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.mu.Unlock()
	a.kickRefresh()
}

// Snapshot returns the current audit immediately and kicks a background refresh
// when it has aged out. The returned value is never mutated after publication,
// so sharing the pointer across callers is safe without a copy.
func (a *ancestry) Snapshot() *AncestryInfo {
	a.mu.Lock()
	snap := a.snap
	a.mu.Unlock()

	if snap.CheckedAt == nil || time.Since(*snap.CheckedAt) > ancestryRefreshInterval {
		a.kickRefresh()
	}
	return snap
}

// kickRefresh starts at most one refresh at a time, so a polled endpoint cannot
// multiply into concurrent KMS traffic.
func (a *ancestry) kickRefresh() {
	a.mu.Lock()
	ctx := a.ctx
	if a.refreshing || ctx == nil {
		a.mu.Unlock()
		return
	}
	a.refreshing = true
	a.mu.Unlock()

	go func() {
		defer func() {
			a.mu.Lock()
			a.refreshing = false
			a.mu.Unlock()
		}()
		a.refresh(ctx)
	}()
}

// refresh rebuilds the snapshot and publishes it in one assignment. No deadline:
// each key probe carries its own, and a walk-wide one would drop the oldest
// generations first.
func (a *ancestry) refresh(ctx context.Context) {
	var origin *GenesisOrigin
	generations := []AncestorGeneration{}
	complete, reason := false, ""

	own, err := a.nsm.PCR0()
	if err != nil {
		reason = fmt.Sprintf("could not read own PCR0: %v", err)
	} else {
		generations, complete, reason = a.walkAncestors(ctx, hex.EncodeToString(own))
		origin = a.genesisOrigin(ctx)
	}

	checkedAt := time.Now().UTC()
	a.mu.Lock()
	a.snap = &AncestryInfo{
		Generations: generations,
		Genesis:     origin,
		Complete:    complete,
		Reason:      reason,
		CheckedAt:   &checkedAt,
	}
	a.mu.Unlock()
}

// genesisOrigin serves the origin record without judging it: whether the chain
// reaches it is the client's call, against an attestation it verifies itself.
func (a *ancestry) genesisOrigin(ctx context.Context) *GenesisOrigin {
	if a.genesis == nil {
		return nil
	}
	artifact, err := a.genesis.Genesis(ctx)
	if err != nil {
		slog.Warn("could not read the deployment genesis record", "error", err)
		return nil
	}
	if artifact == nil {
		return nil
	}
	publishedAt := artifact.PublishedAt.UTC()
	return &GenesisOrigin{
		PCR0:        artifact.PCR0,
		PublishedAt: &publishedAt,
		Attestation: artifact.Attestation,
	}
}

// walkAncestors follows MigrationPreviousPCR0 back from ownPCR0, auditing each
// generation's key as it goes. ownPCR0 itself is excluded: its key is trivially
// live. Ordered newest first.
//
// Every stop short of genesis is reported as a reason with complete=false, and
// the generations found before it are still returned: a partial audit is worth
// more than none, provided it says it is partial.
func (a *ancestry) walkAncestors(
	ctx context.Context,
	ownPCR0 string,
) ([]AncestorGeneration, bool, string) {
	generations := make([]AncestorGeneration, 0, 8)
	visited := map[string]bool{normalizedOrRaw(ownPCR0): true}
	current := ownPCR0

	for {
		prev, err := a.ssm.MayGet(ctx, migrationPreviousPCR0Param(current))
		if err != nil {
			return generations, false, fmt.Sprintf("ancestor chain walk failed: %v", err)
		}
		// MayGet maps a missing parameter to empty, which is how genesis ends.
		if prev == "" {
			return generations, true, ""
		}

		normalized, _, err := normalizePCR0(prev)
		if err != nil {
			return generations, false, fmt.Sprintf(
				"malformed predecessor PCR0 recorded for generation %s: %v",
				prefix16(current), err,
			)
		}
		if visited[normalized] {
			return generations, false, fmt.Sprintf(
				"ancestor chain cycle detected at generation %s", prefix16(normalized),
			)
		}
		visited[normalized] = true

		// A missing KMSKeyID is an operator having pruned a retired generation, not
		// corruption. The chain is independent of it, so the walk carries on and the
		// generation reports unknown rather than vanishing from the audit.
		keyID, err := a.ssm.MayGet(ctx, kmsKeyIDParam(normalized))
		if err != nil {
			return generations, false, fmt.Sprintf("ancestor chain walk failed: %v", err)
		}
		status := a.keys.KeyStatus(ctx, keyID)
		if status.State == keyStateUnknown {
			slog.Warn("ancestor key state could not be read",
				"pcr0", prefix16(normalized), "key_id", keyID, "reason", status.Reason)
		}
		generations = append(generations, AncestorGeneration{
			PCR0:         normalized,
			KeyID:        keyID,
			State:        status.State,
			CheckedVia:   status.CheckedVia,
			DeletionDate: status.DeletionDate,
		})
		current = normalized
	}
}

// normalizedOrRaw lowercases a well-formed PCR0 for cycle comparison and passes
// anything else through, so a malformed own PCR0 still seeds the visited set.
func normalizedOrRaw(pcr0 string) string {
	if normalized, _, err := normalizePCR0(pcr0); err == nil {
		return normalized
	}
	return pcr0
}
