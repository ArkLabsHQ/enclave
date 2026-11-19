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
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArkLabsHQ/enclave/internal/migration"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/fxamacker/cbor/v2"
)

const (
	migrationIntentPrefix   = "migration-intent/"
	migrationIntentSchemaV1 = migration.IntentSchemaV1

	migrationIntentRequested = migration.Requested
	migrationIntentAborted   = migration.Aborted
	migrationIntentFinalised = migration.Finalised
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

type migrationIntentUserDataV1 = migration.UserDataV1

type migrationIntentObjectV1 = migration.ObjectV1

type migrationIntent struct {
	SourcePCR0        string
	TargetPCR0        string
	Action            string
	Sequence          uint64
	PublishedAt       time.Time
	VersionID         string
	FinalisedSnapshot *Snapshot
	// SnapshotRoot is the attested root of a finalised intent's snapshot.
	SnapshotRoot []byte
}

// intentState is what a log's intents resolve to: one intent in force, or
// several tied intents in conflict.
type intentState struct {
	current   *migrationIntent   // nil when there is none, or a conflict
	ambiguous []*migrationIntent // the tied intents of a conflict
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
	payload, err := migration.EncodeUserData(userData)
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
			intent, valid, err := l.fetchAttestedIntent(
				ctx, key, versionID, expected.SourcePCR0, expected.Sequence, publishedAt.UTC(),
			)
			if valid {
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
	if !recorded.equivalent(expected) {
		return nil, fmt.Errorf(
			"migration intent sequence %d version %q: "+
				"stored record does not match the submitted intent",
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

// scanIntents returns the active authorization separately from the highest
// valid sequence, so ignored requests cannot occupy the next abort slot. More
// than one active intent means a tie involving a request. Tied aborts all cancel
// the same round and resolve to one representative.
func (l *migrationIntentLog) scanIntents(
	ctx context.Context,
	sourcePCR0 string,
) (intentState, uint64, error) {
	intents, err := l.listIntents(ctx, sourcePCR0)
	if err != nil {
		return intentState{}, 0, err
	}

	modifiedIntents := make([]migration.Intent, len(intents))
	for i, intent := range intents {
		modifiedIntents[i] = migration.Intent{
			Sequence:    intent.Sequence,
			Action:      intent.Action,
			TargetPCR0:  intent.TargetPCR0,
			PublishedAt: intent.PublishedAt,
		}
		if intent.FinalisedSnapshot != nil {
			modifiedIntents[i].SnapshotRoot = intent.SnapshotRoot
		}
	}
	resolved := migration.ResolveGeneration(modifiedIntents)
	var state intentState
	if resolved.Current >= 0 {
		state.current = intents[resolved.Current]
	}
	for _, i := range resolved.Ambiguous {
		state.ambiguous = append(state.ambiguous, intents[i])
	}
	return state, resolved.HighestSequence, nil
}

// listIntents returns every valid version of the log in S3 listing order.
func (l *migrationIntentLog) listIntents(
	ctx context.Context,
	sourcePCR0 string,
) ([]*migrationIntent, error) {
	var intents []*migrationIntent
	err := l.forEachIntentVersion(ctx, sourcePCR0,
		func(key, versionID string, sequence uint64, publishedAt time.Time) error {
			intent, valid, err := l.fetchAttestedIntent(
				ctx, key, versionID, sourcePCR0, sequence, publishedAt,
			)
			if err != nil || !valid {
				return err
			}
			intents = append(intents, intent)
			return nil
		})
	if err != nil {
		return nil, err
	}
	return intents, nil
}

// listRecords returns the locked, well-formed versions of a log as stored,
// without verifying their attestations; verifiers do that.
func (l *migrationIntentLog) listRecords(
	ctx context.Context,
	sourcePCR0 string,
) ([]migration.Record, error) {
	records := []migration.Record{}
	err := l.forEachIntentVersion(ctx, sourcePCR0,
		func(key, versionID string, sequence uint64, publishedAt time.Time) error {
			_, body, valid, err := l.readIntent(ctx, key, versionID, sequence, publishedAt)
			if err != nil || !valid {
				return err
			}
			records = append(records, migration.Record{PublishedAt: publishedAt, Object: body})
			return nil
		})
	if err != nil {
		return nil, err
	}
	return records, nil
}

// forEachIntentVersion calls readVersion for every version filed under
// sourcePCR0's log.
func (l *migrationIntentLog) forEachIntentVersion(
	ctx context.Context,
	sourcePCR0 string,
	readVersion func(key, versionID string, sequence uint64, publishedAt time.Time) error,
) error {
	return forEachObjectVersion(ctx, l.s3, l.bucket, migrationIntentPrefix+sourcePCR0+"/",
		errMigrationIntentStoreUnavailable, "list migration intents",
		func(key, versionID string, lastModified *time.Time) (bool, error) {
			if versionID == "" || lastModified == nil {
				return false, nil
			}

			keySourcePCR0, sequence, ok := parseMigrationIntentObjectKey(key)
			if !ok || keySourcePCR0 != sourcePCR0 {
				return false, nil
			}

			return false, readVersion(key, versionID, sequence, lastModified.UTC())
		})
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
) (migrationIntentObjectV1, []byte, bool, error) {
	var entry migrationIntentObjectV1
	body, ok, err := readLockedVersion(
		ctx, l.s3, l.bucket, key, versionID, publishedAt,
		l.retention, l.writeTimeout(), errMigrationIntentStoreUnavailable, "migration intent",
	)
	if err != nil || !ok {
		return entry, nil, false, err
	}
	entry, err = decodeMigrationIntentObject(body)
	if err != nil || entry.Schema != migrationIntentSchemaV1 || entry.Sequence != sequence ||
		!migration.IsAction(entry.Action) ||
		entry.Attestation == "" || !isCanonicalPCR0(entry.TargetPCR0) {
		return entry, nil, false, nil
	}
	return entry, body, true, nil
}

func (l *migrationIntentLog) fetchAttestedIntent(
	ctx context.Context,
	key, versionID, sourcePCR0 string,
	sequence uint64,
	publishedAt time.Time,
) (*migrationIntent, bool, error) {
	entry, _, valid, err := l.readIntent(ctx, key, versionID, sequence, publishedAt)
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
	if entry.Action == migrationIntentFinalised {
		// Only a snapshot of this deployment can be adopted.
		snapshot, err := decodeSnapshot(l.cfg, entry.FinalisedSnapshot)
		if err != nil {
			return nil, false, nil
		}
		snapshot.transitionReceipt = entry.Attestation
		intent.FinalisedSnapshot = &snapshot
	}
	view, _, err := migration.VerifyIntentObject(
		entry, sourcePCR0, l.bucket, publishedAt, l.verifyAttestation,
	)
	if err != nil {
		return nil, false, nil
	}
	intent.SnapshotRoot = view.SnapshotRoot
	return intent, true, nil
}

// verifyAttestation checks an attestation with the enclave's NSM verifier, which
// verifies at the document's own time.
func (l *migrationIntentLog) verifyAttestation(b64 string) (migration.Attestation, error) {
	result, err := l.nsm.VerifyAttestationDocument(b64, nil)
	if err != nil {
		return migration.Attestation{}, err
	}
	return migration.Attestation{
		PCRs:      result.Document.PCRs,
		UserData:  result.Document.UserData,
		Timestamp: time.UnixMilli(int64(result.Document.Timestamp)).UTC(),
	}, nil
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
