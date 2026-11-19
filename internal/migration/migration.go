// Package migration is the migration intent format and the rules that resolve
// an intent log. The runtime writes and reads the log with it, and the client
// verifies the log with it, so the two always agree.
package migration

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	IntentSchemaV1 = "enclave.migration_intent.v1"

	Requested = "requested"
	Aborted   = "aborted"
	Finalised = "finalised"

	// SnapshotRootDomainV1 separates snapshot roots from other SHA-256 uses.
	SnapshotRootDomainV1 = "enclave.snapshot_root.v1\x00"

	// TargetPCRIndex holds the target a source commits to before it attests a
	// finalised handoff.
	TargetPCRIndex = 31
)

// UserDataV1 is what an intent's attestation commits to.
type UserDataV1 struct {
	Schema                string `cbor:"schema"`
	BucketName            string `cbor:"bucket_name"`
	Sequence              uint64 `cbor:"sequence"`
	Action                string `cbor:"action"`
	TargetPCR0            string `cbor:"target_pcr0"`
	FinalisedSnapshotRoot []byte `cbor:"finalised_snapshot_root,omitempty"`
}

// ObjectV1 is an intent as stored in the intent bucket.
type ObjectV1 struct {
	Schema            string `json:"schema"`
	Sequence          uint64 `json:"sequence"`
	Action            string `json:"action"`
	TargetPCR0        string `json:"target_pcr0"`
	Attestation       string `json:"attestation"`
	FinalisedSnapshot []byte `json:"finalised_snapshot,omitempty"`
}

// Record is one stored version of an intent log: the object exactly as stored,
// and when S3 published it.
type Record struct {
	PublishedAt time.Time       `json:"published_at"`
	Object      json.RawMessage `json:"object"`
}

// Generation is the intent log written by the enclave measured as PCR0.
type Generation struct {
	PCR0    string   `json:"pcr0"`
	Records []Record `json:"records"`
}

// Attestation is what an accepted attestation document says.
type Attestation struct {
	PCRs      map[uint][]byte
	UserData  []byte
	Timestamp time.Time
}

// VerifyAttestationFunc checks a base64 attestation document's signature and
// certificate chain at the document's own time, and returns what it says.
type VerifyAttestationFunc func(attestationB64 string) (Attestation, error)

// snapshotLineage is the part of a handed-off snapshot that names its generations.
type snapshotLineage struct {
	OwnerPCR0       string `cbor:"owner_pcr0"`
	PredecessorPCR0 string `cbor:"predecessor_pcr0"`
}

// Intent is what resolution reads from one valid version of an intent log.
type Intent struct {
	Sequence    uint64
	Action      string
	TargetPCR0  string
	PublishedAt time.Time
	// For a finalised intent: the root of the snapshot it hands off, which
	// tells handoffs apart and chooses among tied ones.
	SnapshotRoot []byte
}

// Handoff is a finalised intent and the request it stood on, as indexes into
// the resolved intents.
type Handoff struct {
	Request   int
	Finalised int
}

// GenerationState is what a generation's intent log resolves to. Indexes refer
// to the resolved intents.
type GenerationState struct {
	// Current is the intent in force, or -1 when there is none or a conflict.
	Current int
	// Ambiguous holds the tied intents of a conflict.
	Ambiguous []int
	// Handoffs are the finalised handoffs, oldest first. Tied ones, each
	// released under its own key, are all listed, the one in force first.
	Handoffs []Handoff
	// HighestSequence is the highest sequence recorded, so ignored requests cannot
	// occupy the next slot.
	HighestSequence uint64
}

// earliestIntents holds, per sequence, the intents published first: requests
// and aborts, which compete for a sequence, apart from finalised intents.
type earliestIntents struct {
	intents           []Intent
	requestsAndAborts map[uint64][]int // sequence -> indexes of earliest requests and aborts
	finalised         map[uint64][]int // sequence -> indexes of earliest finalised intents
}

// insertIfEarliest inserts intent i if it is among those published first at
// its sequence.
func (e *earliestIntents) insertIfEarliest(i int) {
	intent := e.intents[i]
	earliestBySequence := e.requestsAndAborts
	if intent.Action == Finalised {
		earliestBySequence = e.finalised
	}
	earliest := earliestBySequence[intent.Sequence]
	if len(earliest) == 0 {
		earliestBySequence[intent.Sequence] = []int{i}
		return
	}
	first := e.intents[earliest[0]].PublishedAt
	if intent.PublishedAt.Before(first) {
		earliestBySequence[intent.Sequence] = []int{i}
		return
	}
	if !intent.PublishedAt.Equal(first) {
		return
	}
	// equivalent compares the logical intent, regardless of its version or
	// attestation bytes.
	equivalent := func(a, b Intent) bool {
		if a.Sequence != b.Sequence {
			return false
		}
		if a.Action != b.Action {
			return false
		}
		if a.TargetPCR0 != b.TargetPCR0 {
			return false
		}
		return bytes.Equal(a.SnapshotRoot, b.SnapshotRoot)
	}
	for _, kept := range earliest {
		if equivalent(e.intents[kept], intent) {
			return
		}
	}
	earliestBySequence[intent.Sequence] = append(earliest, i)
}

// finalisedFor returns the finalised intents recorded first at a sequence for
// targetPCR0, smallest snapshot root first. Tied ones each release the same
// state to the same target under their own key, so each is a handoff, and every
// reader takes the first as the one in force, regardless of listing order.
func (e *earliestIntents) finalisedFor(sequence uint64, targetPCR0 string) []int {
	var finalised []int
	for _, i := range e.finalised[sequence] {
		if e.intents[i].TargetPCR0 == targetPCR0 {
			finalised = append(finalised, i)
		}
	}
	slices.SortFunc(finalised, func(a, b int) int {
		return bytes.Compare(e.intents[a].SnapshotRoot, e.intents[b].SnapshotRoot)
	})
	return finalised
}

// earliestAt returns the requests and aborts published first at a sequence.
// Tied aborts all cancel the same round and resolve to one representative.
func (e *earliestIntents) earliestAt(sequence uint64) []int {
	earliest := e.requestsAndAborts[sequence]
	if len(earliest) < 2 {
		return earliest
	}
	chosen := earliest[0]
	for _, i := range earliest {
		// A tie involving a request stays as it is.
		if e.intents[i].Action != Aborted {
			return earliest
		}
		// Choose consistently, regardless of listing order.
		if e.intents[i].TargetPCR0 < e.intents[chosen].TargetPCR0 {
			chosen = i
		}
	}
	return []int{chosen}
}

// addHandoffs lists each finalised intent as a handoff on request.
func (s *GenerationState) addHandoffs(request int, finalised []int) {
	for _, i := range finalised {
		s.Handoffs = append(s.Handoffs, Handoff{Request: request, Finalised: i})
	}
}

// IsAction reports whether action is one an intent can record.
func IsAction(action string) bool {
	switch action {
	case Requested, Aborted, Finalised:
		return true
	}
	return false
}

// EncodeUserData is the canonical CBOR an intent's attestation carries.
func EncodeUserData(userData UserDataV1) ([]byte, error) {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return enc.Marshal(userData)
}

// SnapshotRoot is the root a finalised intent attests for its canonical snapshot.
func SnapshotRoot(snapshot []byte) []byte {
	h := sha256.New()
	h.Write([]byte(SnapshotRootDomainV1))
	h.Write(snapshot)
	return h.Sum(nil)
}

// TargetCommitment is the TargetPCRIndex value once the target is committed:
// the PCR extended once, from zero, with the target's raw PCR0.
func TargetCommitment(targetPCR0 []byte) []byte {
	h := sha512.Sum384(append(make([]byte, sha512.Size384), targetPCR0...))
	return h[:]
}

// VerifyIntentObject checks that object is an intent the enclave measured as
// sourcePCR0 attested for bucket. It returns what resolution reads from the
// intent and when it was attested.
func VerifyIntentObject(
	object ObjectV1,
	sourcePCR0, bucket string,
	publishedAt time.Time,
	verify VerifyAttestationFunc,
) (Intent, time.Time, error) {
	finalised := object.Action == Finalised
	if object.Schema != IntentSchemaV1 {
		return Intent{}, time.Time{}, fmt.Errorf("unexpected schema %q", object.Schema)
	}
	if !IsAction(object.Action) {
		return Intent{}, time.Time{}, fmt.Errorf("unexpected action %q", object.Action)
	}
	if finalised != (len(object.FinalisedSnapshot) > 0) {
		return Intent{}, time.Time{}, fmt.Errorf("only a finalised intent carries a snapshot")
	}
	target, err := hex.DecodeString(object.TargetPCR0)
	if err != nil {
		return Intent{}, time.Time{}, fmt.Errorf("target PCR0 is not hex: %w", err)
	}
	if len(target) != sha512.Size384 {
		return Intent{}, time.Time{}, fmt.Errorf("target PCR0 is %d bytes, not %d",
			len(target), sha512.Size384)
	}
	if hex.EncodeToString(target) != object.TargetPCR0 {
		return Intent{}, time.Time{}, fmt.Errorf("target PCR0 is not lowercase hex")
	}

	attestation, err := verify(object.Attestation)
	if err != nil {
		return Intent{}, time.Time{}, err
	}
	if hex.EncodeToString(attestation.PCRs[0]) != sourcePCR0 {
		return Intent{}, time.Time{}, fmt.Errorf("attested by PCR0 %x, not %s",
			attestation.PCRs[0], sourcePCR0)
	}

	intent := Intent{
		Sequence:    object.Sequence,
		Action:      object.Action,
		TargetPCR0:  object.TargetPCR0,
		PublishedAt: publishedAt,
	}
	userData := UserDataV1{
		Schema:     object.Schema,
		BucketName: bucket,
		Sequence:   object.Sequence,
		Action:     object.Action,
		TargetPCR0: object.TargetPCR0,
	}
	if finalised {
		var snapshot snapshotLineage
		if err := cbor.Unmarshal(object.FinalisedSnapshot, &snapshot); err != nil {
			return Intent{}, time.Time{}, fmt.Errorf("decode snapshot: %w", err)
		}
		if snapshot.OwnerPCR0 != object.TargetPCR0 {
			return Intent{}, time.Time{}, fmt.Errorf("snapshot is owned by %s, not the target",
				snapshot.OwnerPCR0)
		}
		if snapshot.PredecessorPCR0 != sourcePCR0 {
			return Intent{}, time.Time{}, fmt.Errorf("snapshot names predecessor %s",
				snapshot.PredecessorPCR0)
		}
		// The source commits the target before it attests the handoff.
		if !bytes.Equal(attestation.PCRs[TargetPCRIndex], TargetCommitment(target)) {
			return Intent{}, time.Time{}, fmt.Errorf("PCR%d does not commit to the target",
				TargetPCRIndex)
		}
		intent.SnapshotRoot = SnapshotRoot(object.FinalisedSnapshot)
		userData.FinalisedSnapshotRoot = intent.SnapshotRoot
	}
	payload, err := EncodeUserData(userData)
	if err != nil {
		return Intent{}, time.Time{}, fmt.Errorf("encode user_data: %w", err)
	}
	if !bytes.Equal(attestation.UserData, payload) {
		return Intent{}, time.Time{}, fmt.Errorf("attested user_data does not match the intent")
	}
	return intent, attestation.Timestamp, nil
}

// ResolveGeneration applies a log's intents in sequence order, in any input order.
// Per sequence only the intents published first count; requests and aborts
// compete for a sequence, and finalised intents are kept apart. An abort ends
// the pending request, its handoff or a conflict. A tie involving a request is
// a conflict. A finalised intent stands only on the pending request for its
// target. A request is accepted only when nothing is pending.
func ResolveGeneration(intents []Intent) GenerationState {
	bySequence := earliestIntents{
		intents:           intents,
		requestsAndAborts: map[uint64][]int{},
		finalised:         map[uint64][]int{},
	}
	for i := range intents {
		bySequence.insertIfEarliest(i)
	}
	sequences := slices.Concat(
		slices.Collect(maps.Keys(bySequence.requestsAndAborts)),
		slices.Collect(maps.Keys(bySequence.finalised)),
	)
	slices.Sort(sequences)

	state := GenerationState{Current: -1}
	for _, sequence := range slices.Compact(sequences) {
		state.HighestSequence = sequence
		earliest := bySequence.earliestAt(sequence)
		conflict := len(state.Ambiguous) > 0

		// A finalised intent stands only on the pending request for its target.
		// Tied ones are all handoffs; the first is in force.
		var handoffs []int
		if !conflict && state.Current >= 0 && intents[state.Current].Action == Requested {
			handoffs = bySequence.finalisedFor(sequence, intents[state.Current].TargetPCR0)
		}

		// An abort ends the pending request, its handoff or a conflict. A handoff
		// at the abort's own sequence never comes into force, but it released its
		// state, so it is still listed.
		if len(earliest) == 1 && intents[earliest[0]].Action == Aborted {
			state.addHandoffs(state.Current, handoffs)
			state.Current, state.Ambiguous = earliest[0], nil
			continue
		}

		// A tie involving a request is a conflict, whatever was pending.
		if len(earliest) > 1 {
			state.Current, state.Ambiguous = -1, earliest
			continue
		}

		if len(handoffs) > 0 {
			state.addHandoffs(state.Current, handoffs)
			state.Current = handoffs[0]
			continue
		}

		// A single request is accepted only when nothing is pending.
		if len(earliest) == 1 && nothingPending(intents, state.Current, conflict) {
			state.Current = earliest[0]
		}
	}
	return state
}

// nothingPending reports whether a new request takes effect: nothing is in
// force, or the last intent in force was an abort, and there is no conflict.
func nothingPending(intents []Intent, current int, conflict bool) bool {
	if conflict {
		return false
	}
	if current < 0 {
		return true
	}
	return intents[current].Action == Aborted
}
