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
	"log/slog"
	"math"
	"sort"
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
)

var (
	errMigrationIntentAmbiguous        = errors.New("migration intent: ambiguous head")
	errMigrationIntentAbsent           = errors.New("migration intent: absent")
	errMigrationIntentAborted          = errors.New("migration intent: aborted")
	errMigrationIntentAlreadyRequested = errors.New(
		"migration intent: already requested, abort first",
	)
	errMigrationCooldownActive         = errors.New("migration cooldown: active")
	errMigrationIntentStoreUnavailable = errors.New("migration intent store: unavailable")
	errMigrationIntentSelfTarget       = errors.New(
		"migration intent: target PCR0 is this enclave",
	)
	errMigrationAlreadyFinalised = errors.New("migration: already finalised for this target")
)

type migrationIntentV1 struct {
	Schema     string `cbor:"schema"`
	BucketName string `cbor:"bucket_name"`
	Sequence   uint64 `cbor:"sequence"`
	Action     string `cbor:"action"`
	TargetPCR0 string `cbor:"target_pcr0"`
}

type migrationIntentObjectV1 struct {
	Schema      string `json:"schema"`
	Sequence    uint64 `json:"sequence"`
	Action      string `json:"action"`
	TargetPCR0  string `json:"target_pcr0"`
	Attestation string `json:"attestation"`
}

type migrationIntent struct {
	SourcePCR0  string
	TargetPCR0  string
	Action      string
	Sequence    uint64
	PublishedAt time.Time
	VersionID   string
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
	identity := cfg.Deployment + "\x00" + cfg.AppName
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
	head, tie, err := l.deriveHead(ctx, sourcePCR0)
	if err != nil {
		return nil, err
	}
	if tie {
		return nil, errMigrationIntentAmbiguous
	}

	return head, nil
}

func (l *migrationIntentLog) Request(
	ctx context.Context,
	sourcePCR0, targetPCR0 string,
) (*migrationIntent, error) {
	targetPCR0, _, err := normalizePCR0(targetPCR0)
	if err != nil {
		return nil, fmt.Errorf("target PCR0: %w", err)
	}
	// A self-targeted handoff would overwrite this enclave's own commit pointer
	// and would satisfy the PCR31 check trivially.
	if strings.EqualFold(targetPCR0, sourcePCR0) {
		return nil, errMigrationIntentSelfTarget
	}
	head, tie, highest, err := l.scanIntents(ctx, sourcePCR0)
	if err != nil {
		return nil, err
	}
	if head != nil && (tie || head.Action == migrationIntentRequested) {
		return nil, errMigrationIntentAlreadyRequested
	}
	return l.append(ctx, sourcePCR0, highest, migrationIntentRequested, targetPCR0)
}

func (l *migrationIntentLog) Abort(
	ctx context.Context,
	sourcePCR0 string,
) (*migrationIntent, error) {
	head, tie, highest, err := l.scanIntents(ctx, sourcePCR0)
	if err != nil {
		return nil, err
	}
	if head == nil {
		return nil, errMigrationIntentAbsent
	}
	if !tie && head.Action == migrationIntentAborted {
		return nil, errMigrationIntentAborted
	}

	return l.append(ctx, sourcePCR0, highest, migrationIntentAborted, head.TargetPCR0)
}

func (l *migrationIntentLog) append(
	ctx context.Context,
	sourcePCR0 string,
	baseSequence uint64,
	action, targetPCR0 string,
) (*migrationIntent, error) {
	if baseSequence == math.MaxUint64 {
		return nil, fmt.Errorf("migration intent sequence overflow")
	}
	sequence := baseSequence + 1
	payload, err := l.enc.Marshal(migrationIntentV1{
		Schema:     migrationIntentSchemaV1,
		BucketName: l.bucket,
		Sequence:   sequence,
		Action:     action,
		TargetPCR0: targetPCR0,
	})
	if err != nil {
		return nil, fmt.Errorf("encode migration intent: %w", err)
	}
	doc, _, err := l.nsm.BuildAttestationDocument(WithUserData(payload))
	if err != nil {
		return nil, fmt.Errorf("attest migration intent: %w", err)
	}
	body, err := json.Marshal(migrationIntentObjectV1{
		Schema:      migrationIntentSchemaV1,
		Sequence:    sequence,
		Action:      action,
		TargetPCR0:  targetPCR0,
		Attestation: base64.StdEncoding.EncodeToString(doc),
	})
	if err != nil {
		return nil, fmt.Errorf("encode migration intent object: %w", err)
	}
	writeCtx, cancel := context.WithTimeout(ctx, l.writeTimeout())
	defer cancel()

	out, err := l.s3.PutObject(writeCtx, &s3.PutObjectInput{
		Bucket:                    aws.String(l.bucket),
		Key:                       aws.String(migrationIntentObjectKey(sourcePCR0, sequence)),
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

	head, tie, err := l.deriveHead(ctx, sourcePCR0)
	if err != nil {
		return nil, err
	}
	if tie {
		return nil, errMigrationIntentAmbiguous
	}
	if head == nil || head.Sequence < sequence {
		return nil, fmt.Errorf(
			"%w: migration intent sequence %d missing after write",
			errMigrationIntentStoreUnavailable,
			sequence,
		)
	}

	return head, nil
}

func (l *migrationIntentLog) deriveHead(
	ctx context.Context, sourcePCR0 string,
) (*migrationIntent, bool, error) {
	head, tie, _, err := l.scanIntents(ctx, sourcePCR0)
	return head, tie, err
}

// scanIntents returns the active authorization separately from the highest
// valid sequence, so ignored requests cannot occupy the next abort slot.
func (l *migrationIntentLog) scanIntents(
	ctx context.Context,
	sourcePCR0 string,
) (*migrationIntent, bool, uint64, error) {
	heads := make(map[uint64]*migrationIntent)
	ties := make(map[uint64]bool)
	err := forEachObjectVersion(ctx, l.s3, l.bucket, migrationIntentPrefix+sourcePCR0+"/",
		errMigrationIntentStoreUnavailable, "list migration intents",
		func(key, versionID string, lastModified *time.Time) (bool, error) {
			keySourcePCR0, sequence, ok := parseMigrationIntentObjectKey(key)
			if !ok || keySourcePCR0 != sourcePCR0 || versionID == "" || lastModified == nil {
				return false, nil
			}
			nextHead, valid, err := l.fetchIntent(
				ctx, key, versionID, keySourcePCR0, sequence, lastModified.UTC(),
			)
			if err != nil || !valid {
				return false, err
			}
			head := heads[sequence]
			switch {
			case head == nil || nextHead.PublishedAt.Before(head.PublishedAt):
				heads[sequence] = nextHead
				ties[sequence] = false
			case nextHead.PublishedAt.Equal(head.PublishedAt):
				ties[sequence] = true
			}
			return false, nil
		})
	if err != nil {
		return nil, false, 0, err
	}
	sequences := make([]uint64, 0, len(heads))
	for sequence := range heads {
		sequences = append(sequences, sequence)
	}
	sort.Slice(sequences, func(i, j int) bool { return sequences[i] < sequences[j] })
	var head *migrationIntent
	var tie bool
	var highest uint64
	for _, sequence := range sequences {
		highest = sequence
		next := heads[sequence]
		if ties[sequence] {
			head, tie = next, true
			continue
		}
		// An abort ends the pending request. Otherwise retain the earliest
		// request, including expired requests, until an abort follows it.
		aborts := next.Action == migrationIntentAborted
		unauthorized := head == nil || head.Action == migrationIntentAborted
		if aborts || (!tie && unauthorized) {
			head, tie = next, false
		}
	}
	return head, tie, highest, nil
}

// writeTimeout bounds upload delay and the corresponding read-side tolerance.
func (l *migrationIntentLog) writeTimeout() time.Duration {
	return l.cfg.IntentWriteTimeout
}

func (l *migrationIntentLog) compliesWithObjectLock(
	key, versionID string, publishedAt time.Time, out *s3.GetObjectOutput,
) bool {
	if out.ObjectLockMode != s3types.ObjectLockModeCompliance {
		slog.Warn("ignoring migration intent that is not retained under compliance mode",
			"key", key, "version", versionID, "mode", string(out.ObjectLockMode))
		return false
	}

	retainUntil := aws.ToTime(out.ObjectLockRetainUntilDate)
	minimum := l.retention - l.writeTimeout()
	minimumDeadline := publishedAt.Add(minimum)
	if retainUntil.IsZero() || retainUntil.Before(minimumDeadline) {
		slog.Warn("ignoring migration intent retained for less than the configured period",
			"key", key, "version", versionID,
			"retained_for", retainUntil.Sub(publishedAt), "minimum", minimum)
		return false
	}
	return true
}

// readIntent returns one version if it is a well-formed record at the expected
// sequence, retained under the Object Lock the runtime writes. It does not
// verify the attestation.
func (l *migrationIntentLog) readIntent(
	ctx context.Context,
	key, versionID string,
	sequence uint64,
	publishedAt time.Time,
) (migrationIntentObjectV1, bool, error) {
	var entry migrationIntentObjectV1
	out, err := l.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket:    aws.String(l.bucket),
		Key:       aws.String(key),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		return entry, false, fmt.Errorf(
			"%w: get migration intent %q version %q: %w",
			errMigrationIntentStoreUnavailable,
			key,
			versionID,
			err,
		)
	}
	defer func() { _ = out.Body.Close() }()
	if !l.compliesWithObjectLock(key, versionID, publishedAt, out) {
		return entry, false, nil
	}
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return entry, false, fmt.Errorf(
			"%w: read migration intent %q version %q: %w",
			errMigrationIntentStoreUnavailable,
			key,
			versionID,
			err,
		)
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
	payload, err := l.enc.Marshal(migrationIntentV1{
		Schema:     entry.Schema,
		BucketName: l.bucket,
		Sequence:   entry.Sequence,
		Action:     entry.Action,
		TargetPCR0: entry.TargetPCR0,
	})
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
	return &migrationIntent{
		SourcePCR0:  sourcePCR0,
		TargetPCR0:  entry.TargetPCR0,
		Action:      entry.Action,
		Sequence:    entry.Sequence,
		PublishedAt: publishedAt,
		VersionID:   versionID,
	}, true, nil
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
	case migrationIntentRequested, migrationIntentAborted:
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
	if len(seen) != 5 {
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
