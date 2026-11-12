package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/fxamacker/cbor/v2"
)

const (
	migrationIntentPrefix   = "migration-intent/"
	migrationIntentSchemaV1 = "enclave.migration_intent.v1"

	migrationIntentRequested = "requested"
	migrationIntentAborted   = "aborted"
	migrationIntentFinalised = "finalised"
)

var (
	errMigrationIntentAmbiguous        = errors.New("migration intent: ambiguous head")
	errMigrationIntentAbsent           = errors.New("migration intent: absent")
	errMigrationIntentAborted          = errors.New("migration intent: aborted")
	errMigrationIntentAlreadyRequested = errors.New(
		"migration intent: already requested, abort first",
	)
	errMigrationIntentAbortTargetMismatch = errors.New(
		"migration intent: abort target is not active",
	)
	errMigrationCooldownActive         = errors.New("migration cooldown: active")
	errMigrationIntentStoreUnavailable = errors.New("migration intent store: unavailable")
	errMigrationIntentSelfTarget       = errors.New(
		"migration intent: target PCR0 is this enclave",
	)
	errMigrationAlreadyFinalised = errors.New("migration: already finalised for this target")
)

type migrationIntentUserDataV1 struct {
	Schema                string `cbor:"schema"`
	BucketName            string `cbor:"bucket_name"`
	Sequence              uint64 `cbor:"sequence"`
	Action                string `cbor:"action"`
	TargetPCR0            string `cbor:"target_pcr0"`
	FinalisedSnapshotRoot []byte `cbor:"finalised_snapshot_root,omitempty"`
}

type migrationIntentObjectV1 struct {
	Schema            string `json:"schema"`
	Sequence          uint64 `json:"sequence"`
	Action            string `json:"action"`
	TargetPCR0        string `json:"target_pcr0"`
	Attestation       string `json:"attestation"`
	FinalisedSnapshot []byte `json:"finalised_snapshot,omitempty"`
}

type migrationIntent struct {
	SourcePCR0        string
	TargetPCR0        string
	Action            string
	Sequence          uint64
	PublishedAt       time.Time
	VersionID         string
	FinalisedSnapshot *Snapshot
}

// intentState is what a log's intents resolve to: one intent in force, or
// several tied intents in conflict.
type intentState struct {
	current   *migrationIntent   // nil when there is none, or a conflict
	ambiguous []*migrationIntent // the tied intents of a conflict
}

// intentHead derives a log's active intents from its versions.
type intentHead struct {
	// Per sequence, the distinct intents published first. Requests and aborts
	// compete for a sequence; finalised intents are kept apart.
	requestsAndAborts map[uint64][]*migrationIntent
	finalised         map[uint64][]*migrationIntent
}

type migrationIntentLog struct {
	cfg       *Config
	s3        S3API
	nsm       NSM
	bucket    string
	enc       cbor.EncMode
	retention time.Duration
}

func migrationIntentBucketName(cfg *Config, accountID string) string {
	identity := cfg.Namespace + "\x00" + cfg.AppName
	digest := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("enclave-%s-%x-migration-intents", accountID, digest[:8])
}

func newMigrationIntentLog(
	cfg *Config, s3Client S3API, nsm NSM, bucket string,
) (*migrationIntentLog, error) {
	if strings.TrimSpace(bucket) == "" {
		return nil, fmt.Errorf("migration intent bucket is required")
	}
	retention := cfg.IntentRetention
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("build migration intent CBOR encoder: %w", err)
	}
	return &migrationIntentLog{
		cfg: cfg,
		s3:  s3Client, nsm: nsm, bucket: bucket, enc: enc, retention: retention,
	}, nil
}

func (l *migrationIntentLog) Head(
	ctx context.Context,
	sourcePCR0 string,
) (*migrationIntent, error) {
	state, _, err := l.scanIntents(ctx, sourcePCR0)
	if err != nil {
		return nil, err
	}
	if len(state.ambiguous) > 0 {
		return nil, errMigrationIntentAmbiguous
	}

	return state.current, nil
}

// Request records a request. Its returned version confirms persistence; Head
// determines whether the request is the active authorization.
func (l *migrationIntentLog) Request(
	ctx context.Context,
	sourcePCR0, targetPCR0 string,
) (*migrationIntent, error) {
	targetPCR0, _, err := normalizePCR0(targetPCR0)
	if err != nil {
		return nil, fmt.Errorf("target PCR0: %w", err)
	}
	// A self-targeted handoff would satisfy the PCR31 check trivially.
	if strings.EqualFold(targetPCR0, sourcePCR0) {
		return nil, errMigrationIntentSelfTarget
	}
	state, highest, err := l.scanIntents(ctx, sourcePCR0)
	if err != nil {
		return nil, err
	}
	if len(state.ambiguous) > 0 ||
		(state.current != nil && state.current.Action != migrationIntentAborted) {
		return nil, errMigrationIntentAlreadyRequested
	}
	return l.append(ctx, sourcePCR0, highest, migrationIntentRequested, targetPCR0, Snapshot{})
}

// Finalise records snapshot for the target of the request at sequence. The
// record is the handoff, and its attestation is the transition receipt.
func (l *migrationIntentLog) Finalise(
	ctx context.Context,
	sourcePCR0, targetPCR0 string,
	sequence uint64,
	snapshot Snapshot,
) (*migrationIntent, error) {
	state, highest, err := l.scanIntents(ctx, sourcePCR0)
	if err != nil {
		return nil, err
	}
	if len(state.ambiguous) > 0 {
		return nil, errMigrationIntentAmbiguous
	}
	if state.current == nil {
		return nil, errMigrationIntentAbsent
	}
	head := state.current
	switch {
	case head.Action == migrationIntentFinalised && head.TargetPCR0 == targetPCR0:
		return nil, errMigrationAlreadyFinalised
	case head.Action != migrationIntentRequested || head.Sequence != sequence ||
		head.TargetPCR0 != targetPCR0:
		return nil, fmt.Errorf(
			"%w: request %d is no longer the active intent", errMigrationIntentAborted, sequence,
		)
	}
	return l.append(ctx, sourcePCR0, highest, migrationIntentFinalised, targetPCR0, snapshot)
}

// Abort records a cancellation naming the operator's selected active target.
// A concurrent request at the same sequence and timestamp can leave Head ambiguous.
func (l *migrationIntentLog) Abort(
	ctx context.Context,
	sourcePCR0, targetPCR0 string,
) (*migrationIntent, error) {
	targetPCR0, _, err := normalizePCR0(targetPCR0)
	if err != nil {
		return nil, fmt.Errorf("target PCR0: %w", err)
	}
	state, highest, err := l.scanIntents(ctx, sourcePCR0)
	if err != nil {
		return nil, err
	}
	// The abort names the intent in force, or one of the tied requests.
	active := state.ambiguous
	if state.current != nil {
		active = []*migrationIntent{state.current}
	}
	if len(active) == 0 {
		return nil, errMigrationIntentAbsent
	}
	if state.current != nil && state.current.Action == migrationIntentAborted {
		return nil, errMigrationIntentAborted
	}
	if !slices.ContainsFunc(active, func(intent *migrationIntent) bool {
		return intent.TargetPCR0 == targetPCR0
	}) {
		return nil, errMigrationIntentAbortTargetMismatch
	}

	return l.append(ctx, sourcePCR0, highest, migrationIntentAborted, targetPCR0, Snapshot{})
}

// append records one intent. Only a finalised intent carries a snapshot.
func (l *migrationIntentLog) append(
	ctx context.Context,
	sourcePCR0 string,
	baseSequence uint64,
	action, targetPCR0 string,
	snapshot Snapshot,
) (*migrationIntent, error) {
	if baseSequence == math.MaxUint64 {
		return nil, fmt.Errorf("migration intent sequence overflow")
	}
	sequence := baseSequence + 1
	entry := migrationIntentObjectV1{
		Schema:     migrationIntentSchemaV1,
		Sequence:   sequence,
		Action:     action,
		TargetPCR0: targetPCR0,
	}
	expected := &migrationIntent{
		SourcePCR0: sourcePCR0, TargetPCR0: targetPCR0, Action: action, Sequence: sequence,
	}
	userData := migrationIntentUserDataV1{
		Schema:     migrationIntentSchemaV1,
		BucketName: l.bucket,
		Sequence:   sequence,
		Action:     action,
		TargetPCR0: targetPCR0,
	}
	if action == migrationIntentFinalised {
		var err error
		if entry.FinalisedSnapshot, err = snapshot.encode(l.cfg); err != nil {
			return nil, fmt.Errorf("encode finalised snapshot: %w", err)
		}
		if userData.FinalisedSnapshotRoot, err = snapshot.root(l.cfg); err != nil {
			return nil, fmt.Errorf("compute finalised snapshot root: %w", err)
		}
		expected.FinalisedSnapshot = &snapshot
	}
	payload, err := l.enc.Marshal(userData)
	if err != nil {
		return nil, fmt.Errorf("encode migration intent: %w", err)
	}
	doc, _, err := l.nsm.BuildAttestationDocument(WithUserData(payload))
	if err != nil {
		return nil, fmt.Errorf("attest migration intent: %w", err)
	}
	entry.Attestation = base64.StdEncoding.EncodeToString(doc)
	body, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("encode migration intent object: %w", err)
	}
	writeCtx, cancel := context.WithTimeout(ctx, l.writeTimeout())
	defer cancel()

	key := migrationIntentObjectKey(sourcePCR0, sequence)
	out, err := l.s3.PutObject(writeCtx, &s3.PutObjectInput{
		Bucket:                    aws.String(l.bucket),
		Key:                       aws.String(key),
		Body:                      bytes.NewReader(body),
		ContentType:               aws.String("application/json"),
		ObjectLockMode:            s3types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: aws.Time(time.Now().Add(l.retention)),
	})
	if err != nil {
		return nil, fmt.Errorf(
			"%w: put migration intent sequence %d: %w",
			errMigrationIntentStoreUnavailable,
			sequence,
			err,
		)
	}
	if out == nil || aws.ToString(out.VersionId) == "" {
		return nil, fmt.Errorf(
			"%w: put migration intent sequence %d: S3 returned no version ID",
			errMigrationIntentStoreUnavailable,
			sequence,
		)
	}

	return l.verifyIntentExistence(ctx, aws.ToString(out.VersionId), expected)
}

// verifyIntentExistence verifies the written version independently of the active
// authorization. A concurrent record can leave Head ambiguous despite this write.
func (l *migrationIntentLog) verifyIntentExistence(
	ctx context.Context,
	versionID string,
	expected *migrationIntent,
) (*migrationIntent, error) {
	key := migrationIntentObjectKey(expected.SourcePCR0, expected.Sequence)
	var recorded *migrationIntent
	err := forEachObjectVersion(ctx, l.s3, l.bucket, key,
		errMigrationIntentStoreUnavailable, "verify appended migration intent",
		func(listedKey, listedVersion string, publishedAt *time.Time) (bool, error) {
			if listedKey != key || listedVersion != versionID || publishedAt == nil {
				return false, nil
			}
			intent, valid, err := l.fetchIntent(
				ctx, key, versionID, expected.SourcePCR0, expected.Sequence, publishedAt.UTC(),
			)
			if valid && intent.equivalent(expected) {
				recorded = intent
			}
			return true, err
		})
	if err != nil {
		return nil, err
	}
	if recorded == nil {
		return nil, fmt.Errorf(
			"%w: migration intent sequence %d version %q missing or invalid after write",
			errMigrationIntentStoreUnavailable,
			expected.Sequence,
			versionID,
		)
	}

	return recorded, nil
}

// equivalent compares the complete logical record, including an abort's target
// and a finalised snapshot, regardless of its S3 version or attestation bytes.
func (i *migrationIntent) equivalent(other *migrationIntent) bool {
	sameIntent := i.SourcePCR0 == other.SourcePCR0 && i.Sequence == other.Sequence &&
		i.Action == other.Action && i.TargetPCR0 == other.TargetPCR0
	if i.Action != migrationIntentFinalised {
		return sameIntent
	}
	return sameIntent && i.FinalisedSnapshot.sameState(*other.FinalisedSnapshot)
}

func newIntentHead() *intentHead {
	return &intentHead{
		requestsAndAborts: make(map[uint64][]*migrationIntent),
		finalised:         make(map[uint64][]*migrationIntent),
	}
}

// scanIntents returns the active authorization separately from the highest
// valid sequence, so ignored requests cannot occupy the next abort slot. More
// than one active intent means a tie involving a request. Tied aborts all cancel
// the same round and resolve to one representative.
func (l *migrationIntentLog) scanIntents(
	ctx context.Context,
	sourcePCR0 string,
) (intentState, uint64, error) {
	head := newIntentHead()
	err := forEachObjectVersion(ctx, l.s3, l.bucket, migrationIntentPrefix+sourcePCR0+"/",
		errMigrationIntentStoreUnavailable, "list migration intents",
		func(key, versionID string, lastModified *time.Time) (bool, error) {
			if versionID == "" || lastModified == nil {
				return false, nil
			}

			keySourcePCR0, sequence, ok := parseMigrationIntentObjectKey(key)
			if !ok || keySourcePCR0 != sourcePCR0 {
				return false, nil
			}

			nextHead, valid, err := l.fetchIntent(
				ctx, key, versionID, keySourcePCR0, sequence, lastModified.UTC(),
			)
			if err != nil || !valid {
				return false, err
			}
			head.record(nextHead)
			return false, nil
		})
	if err != nil {
		return intentState{}, 0, err
	}
	state, highest := head.resolve()
	return state, highest, nil
}

// writeTimeout bounds upload delay and the corresponding read-side tolerance.
func (l *migrationIntentLog) writeTimeout() time.Duration {
	return l.cfg.IntentWriteTimeout
}

// readIntent returns one version if it is a well-formed, non-multipart record at
// the expected sequence, retained under the Object Lock the runtime writes.
// It does not verify the attestation.
func (l *migrationIntentLog) readIntent(
	ctx context.Context,
	key, versionID string,
	sequence uint64,
	publishedAt time.Time,
) (migrationIntentObjectV1, bool, error) {
	var entry migrationIntentObjectV1
	body, ok, err := readLockedVersion(
		ctx, l.s3, l.bucket, key, versionID, publishedAt,
		l.retention, l.writeTimeout(), errMigrationIntentStoreUnavailable, "migration intent",
	)
	if err != nil || !ok {
		return entry, false, err
	}
	entry, err = decodeMigrationIntentObject(body)
	if err != nil || entry.Schema != migrationIntentSchemaV1 || entry.Sequence != sequence ||
		!isMigrationIntentAction(entry.Action) ||
		entry.Attestation == "" || !isCanonicalPCR0(entry.TargetPCR0) {
		return entry, false, nil
	}
	return entry, true, nil
}

func (l *migrationIntentLog) fetchIntent(
	ctx context.Context,
	key, versionID, sourcePCR0 string,
	sequence uint64,
	publishedAt time.Time,
) (*migrationIntent, bool, error) {
	entry, valid, err := l.readIntent(ctx, key, versionID, sequence, publishedAt)
	if err != nil || !valid {
		return nil, false, err
	}
	intent := &migrationIntent{
		SourcePCR0:  sourcePCR0,
		TargetPCR0:  entry.TargetPCR0,
		Action:      entry.Action,
		Sequence:    entry.Sequence,
		PublishedAt: publishedAt,
		VersionID:   versionID,
	}
	userData := migrationIntentUserDataV1{
		Schema:     entry.Schema,
		BucketName: l.bucket,
		Sequence:   entry.Sequence,
		Action:     entry.Action,
		TargetPCR0: entry.TargetPCR0,
	}
	if entry.Action == migrationIntentFinalised {
		// The attested root binds the carried snapshot to this record.
		snapshot, err := decodeSnapshot(l.cfg, entry.FinalisedSnapshot)
		if err != nil {
			return nil, false, nil
		}
		if userData.FinalisedSnapshotRoot, err = snapshot.root(l.cfg); err != nil {
			return nil, false, nil
		}
		snapshot.transitionReceipt = entry.Attestation
		intent.FinalisedSnapshot = &snapshot
	}
	payload, err := l.enc.Marshal(userData)
	if err != nil {
		return nil, false, fmt.Errorf(
			"encode migration intent %q version %q: %w",
			key,
			versionID,
			err,
		)
	}
	if err := verifyAttestationUserData(
		l.nsm,
		entry.Attestation,
		map[uint]string{0: sourcePCR0},
		payload,
	); err != nil {
		return nil, false, nil
	}
	return intent, true, nil
}

// record takes one valid version. The scan calls it once per version, in any order.
func (h *intentHead) record(intent *migrationIntent) {
	earliestBySequence := h.requestsAndAborts
	if isFinalisedIntent(intent) {
		earliestBySequence = h.finalised
	}
	earliest := earliestBySequence[intent.Sequence]
	if len(earliest) == 0 || intent.PublishedAt.Before(earliest[0].PublishedAt) {
		earliestBySequence[intent.Sequence] = []*migrationIntent{intent}
		return
	}
	if intent.PublishedAt.Equal(earliest[0].PublishedAt) &&
		!slices.ContainsFunc(earliest, intent.equivalent) {
		earliestBySequence[intent.Sequence] = append(earliest, intent)
	}
}

// resolve applies the sequences in order and returns what they resolve to and
// the highest sequence.
func (h *intentHead) resolve() (intentState, uint64) {
	var state intentState
	var highestSequence uint64
	for _, sequence := range h.sequences() {
		highestSequence = sequence
		earliest := h.earliestAt(sequence)
		conflict := len(state.ambiguous) > 0
		pendingRequest := !conflict && state.current != nil &&
			state.current.Action == migrationIntentRequested
		nothingPending := !conflict &&
			(state.current == nil || state.current.Action == migrationIntentAborted)

		// An abort ends the pending request, its handoff or a conflict.
		if len(earliest) == 1 && earliest[0].Action == migrationIntentAborted {
			state = intentState{current: earliest[0]}
			continue
		}

		// A tie involving a request is a conflict, whatever was pending.
		if len(earliest) > 1 {
			state = intentState{ambiguous: earliest}
			continue
		}

		// A finalised intent stands only on the pending request for its target.
		if pendingRequest {
			finalised := h.finalisedFor(sequence, state.current.TargetPCR0)
			if finalised != nil {
				state = intentState{current: finalised}
				continue
			}
		}

		// A single request is accepted only when nothing is pending.
		if len(earliest) == 1 && nothingPending {
			state = intentState{current: earliest[0]}
		}
	}
	return state, highestSequence
}

// sequences returns every sequence with a recorded intent, in order.
func (h *intentHead) sequences() []uint64 {
	sequences := slices.Concat(
		slices.Collect(maps.Keys(h.requestsAndAborts)),
		slices.Collect(maps.Keys(h.finalised)),
	)
	slices.Sort(sequences)
	return slices.Compact(sequences)
}

// earliestAt returns the requests and aborts published first at sequence.
// Tied aborts all cancel the same round and resolve to one representative.
func (h *intentHead) earliestAt(sequence uint64) []*migrationIntent {
	earliest := h.requestsAndAborts[sequence]
	if len(earliest) < 2 {
		return earliest
	}

	chosen := earliest[0]
	for _, intent := range earliest {
		// A tie involving a request stays as it is.
		if intent.Action != migrationIntentAborted {
			return earliest
		}

		// Choose consistently, regardless of S3 listing order.
		if intent.TargetPCR0 < chosen.TargetPCR0 {
			chosen = intent
		}
	}

	return []*migrationIntent{chosen}
}

// finalisedFor returns the finalised intent recorded at sequence for
// targetPCR0, or nil. Tied ones each release the same state to the same target
// under their own key and resolve to one representative.
func (h *intentHead) finalisedFor(sequence uint64, targetPCR0 string) *migrationIntent {
	var chosen *migrationIntent
	for _, intent := range h.finalised[sequence] {
		if intent.TargetPCR0 != targetPCR0 {
			continue
		}

		// Choose consistently, regardless of S3 listing order.
		if chosen == nil ||
			intent.FinalisedSnapshot.kmsKeyID < chosen.FinalisedSnapshot.kmsKeyID {
			chosen = intent
		}
	}

	return chosen
}

func migrationIntentObjectKey(sourcePCR0 string, sequence uint64) string {
	return fmt.Sprintf("%s%s/%020d", migrationIntentPrefix, sourcePCR0, sequence)
}

func parseMigrationIntentObjectKey(key string) (string, uint64, bool) {
	rest, ok := strings.CutPrefix(key, migrationIntentPrefix)
	if !ok {
		return "", 0, false
	}
	sourcePCR0, sequenceString, ok := strings.Cut(rest, "/")
	if !ok || strings.ContainsRune(sequenceString, '/') || !isCanonicalPCR0(sourcePCR0) ||
		len(sequenceString) != 20 {
		return "", 0, false
	}
	sequence, err := strconv.ParseUint(sequenceString, 10, 64)
	if err != nil || sequence == 0 || sequenceString != fmt.Sprintf("%020d", sequence) {
		return "", 0, false
	}
	return sourcePCR0, sequence, true
}

func normalizePCR0(value string) (string, []byte, error) {
	if len(value) != 96 {
		return "", nil, fmt.Errorf("must be 96 hex characters")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return "", nil, fmt.Errorf("must be valid hex")
	}
	return hex.EncodeToString(decoded), decoded, nil
}

func isMigrationIntentAction(action string) bool {
	switch action {
	case migrationIntentRequested, migrationIntentAborted, migrationIntentFinalised:
		return true
	}
	return false
}

func isCanonicalPCR0(value string) bool {
	normalized, _, err := normalizePCR0(value)
	return err == nil && normalized == value
}

func decodeMigrationIntentObject(body []byte) (migrationIntentObjectV1, error) {
	var entry migrationIntentObjectV1
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return entry, fmt.Errorf("migration intent must be a JSON object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return entry, err
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return entry, fmt.Errorf("invalid or duplicate migration intent field")
		}
		seen[name] = true
		switch name {
		case "schema":
			err = decoder.Decode(&entry.Schema)
		case "sequence":
			err = decoder.Decode(&entry.Sequence)
		case "action":
			err = decoder.Decode(&entry.Action)
		case "target_pcr0":
			err = decoder.Decode(&entry.TargetPCR0)
		case "attestation":
			err = decoder.Decode(&entry.Attestation)
		case "finalised_snapshot":
			err = decoder.Decode(&entry.FinalisedSnapshot)
		default:
			return entry, fmt.Errorf("unknown migration intent field %q", name)
		}
		if err != nil {
			return entry, err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return entry, err
	}
	// Only a finalised intent carries a snapshot.
	fields := 5
	if entry.Action == migrationIntentFinalised {
		fields = 6
	} else if seen["finalised_snapshot"] {
		return entry, fmt.Errorf("migration intent %q carries a snapshot", entry.Action)
	}
	if len(seen) != fields {
		return entry, fmt.Errorf("migration intent fields are missing")
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return entry, err
		}
		return entry, fmt.Errorf("unexpected trailing JSON token %v", token)
	}
	return entry, nil
}

func isFinalisedIntent(intent *migrationIntent) bool {
	return intent.Action == migrationIntentFinalised
}
