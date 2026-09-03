package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	ancestryRefreshInterval = 24 * time.Hour
	ancestryNotYetProbed    = "ancestor key audit has not completed yet"
)

type AncestorGeneration struct {
	PCR0         string     `json:"pcr0"`
	KeyID        string     `json:"key_id"`
	State        string     `json:"state"`
	DeletionDate *time.Time `json:"deletion_date,omitempty"`
}

type AncestryInfo struct {
	Generations []AncestorGeneration `json:"generations"`
	Complete    bool                 `json:"complete"`
	Reason      string               `json:"reason,omitempty"`
	CheckedAt   *time.Time           `json:"checked_at"`
}

type Ancestry interface {
	Start(ctx context.Context)
	Snapshot() *AncestryInfo
}

// NewAncestry starts from the lineage already authenticated during boot.
func NewAncestry(
	cfg *Config, nsm NSM, ssm SSM, keys KeyAuditor, current stateLineage,
) Ancestry {
	return &ancestry{
		cfg: cfg, nsm: nsm, ssm: ssm, keys: keys, current: current,
		snap: &AncestryInfo{
			Generations: []AncestorGeneration{},
			Reason:      ancestryNotYetProbed,
		},
	}
}

type ancestry struct {
	cfg     *Config
	nsm     NSM
	ssm     SSM
	keys    KeyAuditor
	current stateLineage

	mu         sync.Mutex
	ctx        context.Context
	snap       *AncestryInfo
	refreshing bool
}

func (a *ancestry) Start(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.mu.Unlock()
	a.kickRefresh()
}

func (a *ancestry) Snapshot() *AncestryInfo {
	a.mu.Lock()
	snap := a.snap
	a.mu.Unlock()
	if snap.CheckedAt == nil || time.Since(*snap.CheckedAt) > ancestryRefreshInterval {
		a.kickRefresh()
	}
	return snap
}

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

func (a *ancestry) refresh(ctx context.Context) {
	generations, complete, reason := a.walkAncestors(ctx)
	checkedAt := time.Now().UTC()
	a.mu.Lock()
	a.snap = &AncestryInfo{
		Generations: generations, Complete: complete,
		Reason: reason, CheckedAt: &checkedAt,
	}
	a.mu.Unlock()
}

// walkAncestors follows predecessor identities in verified state receipts.
func (a *ancestry) walkAncestors(ctx context.Context) ([]AncestorGeneration, bool, string) {
	generations := make([]AncestorGeneration, 0, 8)
	current := a.current
	visited := map[string]bool{current.ownerPCR0 + "\x00" + current.kmsKeyID: true}

	for current.predecessorPCR0 != "" || current.predecessorKMSKeyID != "" {
		if current.predecessorPCR0 == "" || current.predecessorKMSKeyID == "" {
			return generations, false, "predecessor identity is incomplete"
		}
		identity := current.predecessorPCR0 + "\x00" + current.predecessorKMSKeyID
		if visited[identity] {
			return generations, false, "ancestor chain contains a cycle"
		}
		visited[identity] = true

		status := a.keys.KeyStatus(ctx, current.predecessorKMSKeyID)
		if status.State == keyStateUnknown {
			slog.Warn("ancestor key state could not be read",
				"pcr0", prefix16(current.predecessorPCR0),
				"key_id", current.predecessorKMSKeyID, "reason", status.Reason)
		}
		generations = append(generations, AncestorGeneration{
			PCR0: current.predecessorPCR0, KeyID: current.predecessorKMSKeyID,
			State: status.State, DeletionDate: status.DeletionDate,
		})

		previousPCR0, previousKeyID, err := a.loadVerifiedLineage(
			ctx, current.predecessorPCR0, current.predecessorKMSKeyID,
		)
		if err != nil {
			slog.Warn("could not verify ancestor state", "error", err)
			return generations, false, "ancestor state receipt is missing or invalid"
		}
		current = stateLineage{
			ownerPCR0: current.predecessorPCR0, kmsKeyID: current.predecessorKMSKeyID,
			predecessorPCR0: previousPCR0, predecessorKMSKeyID: previousKeyID,
		}
	}
	return generations, true, ""
}

func (a *ancestry) loadVerifiedLineage(
	ctx context.Context, pcr0, keyID string,
) (string, string, error) {
	receipt, err := a.ssm.MustGet(ctx, a.cfg.stateOriginReceiptParam(keyID, pcr0))
	if err != nil {
		return "", "", err
	}
	userData, err := a.nsm.VerifyAttestation(
		receipt, map[uint]string{0: pcr0},
	)
	if err != nil {
		return "", "", err
	}
	var payload stateOriginPayloadV1
	if err := cbor.Unmarshal(userData, &payload); err != nil {
		return "", "", fmt.Errorf("decode state-origin receipt: %w", err)
	}
	if payload.Purpose != purposeStateOrigin || len(payload.StateRoot) == 0 {
		return "", "", fmt.Errorf("invalid state-origin receipt payload")
	}
	if payload.KMSKeyID != keyID {
		return "", "", fmt.Errorf("state-origin receipt has unexpected KMS key ID")
	}
	if (payload.PredecessorPCR0 == "") != (payload.PredecessorKMSKeyID == "") {
		return "", "", fmt.Errorf("incomplete predecessor identity")
	}
	return payload.PredecessorPCR0, payload.PredecessorKMSKeyID, nil
}
