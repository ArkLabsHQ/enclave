package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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
	errMigrationIntentTargetMismatch   = errors.New("migration intent: target mismatch")
	errMigrationCooldownActive         = errors.New("migration cooldown: active")
	errMigrationIntentStoreUnavailable = errors.New("migration intent store: unavailable")
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

type migrationIntentHead struct {
	SourcePCR0  string
	TargetPCR0  string
	Action      string
	Sequence    uint64
	PublishedAt time.Time
	VersionID   string
}

type migrationIntentScan struct {
	maxSequence uint64
	head        *migrationIntentHead
	ambiguous   bool
}

type migrationIntentLog struct {
	s3        S3API
	nsm       NSM
	bucket    string
	enc       cbor.EncMode
	retention time.Duration
}

func migrationIntentBucketParam() string {
	return fmt.Sprintf("/%s/%s/MigrationIntentBucketName", getDeployment(), getAppName())
}

func newMigrationIntentLog(s3Client S3API, nsm NSM, bucket string) (*migrationIntentLog, error) {
	if strings.TrimSpace(bucket) == "" {
		return nil, fmt.Errorf("migration intent bucket is required")
	}
	retention, err := migrationIntentRetention()
	if err != nil {
		return nil, err
	}
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("build migration intent CBOR encoder: %w", err)
	}
	return &migrationIntentLog{
		s3: s3Client, nsm: nsm, bucket: bucket, enc: enc, retention: retention,
	}, nil
}

func (l *migrationIntentLog) Head(ctx context.Context) (*migrationIntentHead, error) {
	sourcePCR0, err := l.sourcePCR0()
	if err != nil {
		return nil, err
	}
	scan, err := l.scan(ctx, sourcePCR0)
	if err != nil {
		return nil, err
	}
	return scan.resolvedHead()
}

func (l *migrationIntentLog) Request(
	ctx context.Context,
	targetPCR0 string,
) (*migrationIntentHead, error) {
	targetPCR0, err := normalizePCR0(targetPCR0)
	if err != nil {
		return nil, fmt.Errorf("target PCR0: %w", err)
	}
	sourcePCR0, err := l.sourcePCR0()
	if err != nil {
		return nil, err
	}
	scan, err := l.scan(ctx, sourcePCR0)
	if err != nil {
		return nil, err
	}
	return l.append(ctx, sourcePCR0, scan.maxSequence, migrationIntentRequested, targetPCR0)
}

func (l *migrationIntentLog) Abort(ctx context.Context) (*migrationIntentHead, error) {
	sourcePCR0, err := l.sourcePCR0()
	if err != nil {
		return nil, err
	}
	scan, err := l.scan(ctx, sourcePCR0)
	if err != nil {
		return nil, err
	}
	head, err := scan.resolvedHead()
	if err != nil {
		return nil, err
	}
	if head == nil {
		return nil, errMigrationIntentAbsent
	}
	if head.Action == migrationIntentAborted {
		return nil, errMigrationIntentAborted
	}
	return l.append(ctx, sourcePCR0, scan.maxSequence, migrationIntentAborted, head.TargetPCR0)
}

func (l *migrationIntentLog) append(
	ctx context.Context,
	sourcePCR0 string,
	maxSequence uint64,
	action, targetPCR0 string,
) (*migrationIntentHead, error) {
	if maxSequence == math.MaxUint64 {
		return nil, fmt.Errorf("migration intent sequence overflow")
	}
	sequence := maxSequence + 1
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
	out, err := l.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:                    aws.String(l.bucket),
		Key:                       aws.String(migrationIntentObjectKey(sourcePCR0, sequence)),
		Body:                      bytes.NewReader(body),
		ContentType:               aws.String("application/json"),
		ObjectLockMode:            s3types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: aws.Time(time.Now().Add(l.retention)),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: put migration intent sequence %d: %w", errMigrationIntentStoreUnavailable, sequence, err)
	}
	if out == nil || aws.ToString(out.VersionId) == "" {
		return nil, fmt.Errorf("%w: put migration intent sequence %d: S3 returned no version ID", errMigrationIntentStoreUnavailable, sequence)
	}

	scan, err := l.scan(ctx, sourcePCR0)
	if err != nil {
		return nil, err
	}
	if scan.maxSequence < sequence {
		return nil, fmt.Errorf("%w: migration intent sequence %d missing after write", errMigrationIntentStoreUnavailable, sequence)
	}
	return scan.resolvedHead()
}

func (l *migrationIntentLog) sourcePCR0() (string, error) {
	pcr0, err := l.nsm.PCR0()
	if err != nil {
		return "", fmt.Errorf("read source PCR0: %w", err)
	}
	if len(pcr0) != 48 {
		return "", fmt.Errorf("source PCR0 must be 48 bytes, got %d", len(pcr0))
	}
	return hex.EncodeToString(pcr0), nil
}

func (l *migrationIntentLog) scan(
	ctx context.Context,
	sourcePCR0 string,
) (migrationIntentScan, error) {
	var scan migrationIntentScan
	var keyMarker, versionMarker *string
	for {
		out, err := l.s3.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket:          aws.String(l.bucket),
			Prefix:          aws.String(migrationIntentPrefix + sourcePCR0 + "/"),
			KeyMarker:       keyMarker,
			VersionIdMarker: versionMarker,
		})
		if err != nil {
			return scan, fmt.Errorf("%w: list migration intents: %w", errMigrationIntentStoreUnavailable, err)
		}
		for _, version := range out.Versions {
			key := aws.ToString(version.Key)
			keySourcePCR0, sequence, ok := parseMigrationIntentObjectKey(key)
			versionID := aws.ToString(version.VersionId)
			if !ok || keySourcePCR0 != sourcePCR0 || versionID == "" || version.LastModified == nil {
				continue
			}
			head, valid, err := l.readVersion(
				ctx, key, versionID, keySourcePCR0, sequence, version.LastModified.UTC(),
			)
			if err != nil {
				return scan, err
			}
			if valid {
				scan.add(head)
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			return scan, nil
		}
		if out.NextKeyMarker == nil && out.NextVersionIdMarker == nil {
			return scan, fmt.Errorf("%w: list migration intents: truncated response missing markers", errMigrationIntentStoreUnavailable)
		}
		keyMarker, versionMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
}

func (l *migrationIntentLog) readVersion(
	ctx context.Context,
	key, versionID, sourcePCR0 string,
	sequence uint64,
	publishedAt time.Time,
) (*migrationIntentHead, bool, error) {
	out, err := l.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket:    aws.String(l.bucket),
		Key:       aws.String(key),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		return nil, false, fmt.Errorf("%w: get migration intent %q version %q: %w", errMigrationIntentStoreUnavailable, key, versionID, err)
	}
	defer func() { _ = out.Body.Close() }()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, false, fmt.Errorf("%w: read migration intent %q version %q: %w", errMigrationIntentStoreUnavailable, key, versionID, err)
	}
	entry, err := decodeMigrationIntentObject(body)
	if err != nil || entry.Schema != migrationIntentSchemaV1 || entry.Sequence != sequence ||
		(entry.Action != migrationIntentRequested && entry.Action != migrationIntentAborted) ||
		entry.Attestation == "" || !isCanonicalPCR0(entry.TargetPCR0) {
		return nil, false, nil
	}
	payload, err := l.enc.Marshal(migrationIntentV1{
		Schema:     entry.Schema,
		BucketName: l.bucket,
		Sequence:   entry.Sequence,
		Action:     entry.Action,
		TargetPCR0: entry.TargetPCR0,
	})
	if err != nil {
		return nil, false, fmt.Errorf("encode migration intent %q version %q: %w", key, versionID, err)
	}
	if err := l.nsm.VerifyAttestation(
		entry.Attestation,
		map[uint]string{0: sourcePCR0},
		payload,
	); err != nil {
		return nil, false, nil
	}
	return &migrationIntentHead{
		SourcePCR0:  sourcePCR0,
		TargetPCR0:  entry.TargetPCR0,
		Action:      entry.Action,
		Sequence:    entry.Sequence,
		PublishedAt: publishedAt,
		VersionID:   versionID,
	}, true, nil
}

func (s *migrationIntentScan) add(head *migrationIntentHead) {
	switch {
	case s.head == nil || head.Sequence > s.maxSequence:
		s.maxSequence = head.Sequence
		s.head = head
		s.ambiguous = false
	case head.Sequence < s.maxSequence:
		return
	case head.PublishedAt.Before(s.head.PublishedAt):
		s.head = head
		s.ambiguous = false
	case head.PublishedAt.Equal(s.head.PublishedAt):
		s.ambiguous = true
	}
}

func (s migrationIntentScan) resolvedHead() (*migrationIntentHead, error) {
	if s.ambiguous {
		return nil, errMigrationIntentAmbiguous
	}
	return s.head, nil
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

func normalizePCR0(value string) (string, error) {
	if len(value) != 96 {
		return "", fmt.Errorf("must be 96 hex characters")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("must be valid hex")
	}
	return hex.EncodeToString(decoded), nil
}

func isCanonicalPCR0(value string) bool {
	normalized, err := normalizePCR0(value)
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
