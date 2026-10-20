package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	ancestryRefreshInterval = 24 * time.Hour
	ancestryNotYetProbed    = "ancestor key audit has not completed yet"
)

type AncestorGeneration struct {
	PCR0  string `json:"pcr0"`
	KeyID string `json:"key_id"`
	State string `json:"state"`
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

// NewAncestry starts from the snapshot already authenticated during boot.
func NewAncestry(
	cfg *Config, s3api S3API, nsm NSM, bucket string, keys KeyAuditor, current Snapshot,
) Ancestry {
	return &ancestry{
		cfg: cfg, s3: s3api, nsm: nsm, bucket: bucket, keys: keys, current: current,
		snap: &AncestryInfo{
			Generations: []AncestorGeneration{},
			Reason:      ancestryNotYetProbed,
		},
	}
}

type ancestry struct {
	cfg     *Config
	s3      S3API
	nsm     NSM
	bucket  string
	keys    KeyAuditor
	current Snapshot

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

// walkAncestors follows predecessor identities through verified snapshots.
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

		state := a.keys.KeyState(ctx, current.predecessorKMSKeyID)
		if state == keyStateUnknown {
			slog.Warn("ancestor key state could not be read",
				"pcr0", prefix16(current.predecessorPCR0),
				"key_id", current.predecessorKMSKeyID)
		}
		generations = append(generations, AncestorGeneration{
			PCR0: current.predecessorPCR0, KeyID: current.predecessorKMSKeyID,
			State: state,
		})

		predecessor, err := a.loadPredecessor(ctx, current)
		if err != nil {
			slog.Warn("could not verify ancestor snapshot", "error", err)
			return generations, false, "ancestor snapshot is missing or invalid"
		}
		current = predecessor
	}
	return generations, true, ""
}

// Verify the predecessor's snapshot and its key ID against the child's lineage.
func (a *ancestry) loadPredecessor(ctx context.Context, current Snapshot) (Snapshot, error) {
	predecessor, err := readSnapshot(ctx, a.cfg, a.s3, a.nsm, a.bucket, current.predecessorPCR0)
	if err != nil {
		return Snapshot{}, err
	}
	if predecessor == nil {
		return Snapshot{}, fmt.Errorf("no snapshot for %s", prefix16(current.predecessorPCR0))
	}
	if predecessor.kmsKeyID != current.predecessorKMSKeyID {
		return Snapshot{}, fmt.Errorf("snapshot has unexpected KMS key ID")
	}
	return *predecessor, nil
}
