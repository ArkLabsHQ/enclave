package runtime

// Per-write rollback prevention via DEK-sealed Object Lock anchors.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/fxamacker/cbor/v2"
)

const (
	anchorPrefix   = "anchor/"
	anchorSchemaV1 = "enclave.freshness_anchor.v1"
)

var ErrRollbackDetected = errors.New("freshness anchor: rollback detected")

type anchorEntryV1 struct {
	Schema    string `cbor:"schema"`
	Key       string `cbor:"key"`
	Version   uint64 `cbor:"version"`
	Timestamp int64  `cbor:"ts"`
}

// FreshnessAnchor records and verifies per-write anchors.
type FreshnessAnchor interface {
	// Establish loads watermark and fails if live is behind.
	Establish(ctx context.Context, live map[string]uint64) error
	Record(ctx context.Context, key string, version uint64) error
	CheckFresh(key string, version uint64) error
}

type freshnessAnchor struct {
	rt     RuntimeState
	s3     S3API
	dek    DEK
	bucket string
	window time.Duration
	enc    cbor.EncMode

	mu           sync.RWMutex
	versionFloor map[string]uint64
}

func NewFreshnessAnchor(
	ctx context.Context,
	rt RuntimeState,
	s3 S3API,
	dek DEK,
	ssm SSM,
) (FreshnessAnchor, error) {
	bucket, err := ssm.MustGet(ctx, anchorBucketParam())
	if err != nil {
		return nil, fmt.Errorf("read anchor bucket name: %w", err)
	}

	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("failed to build canonical CBOR encoder: %v", err)
	}

	return &freshnessAnchor{
		rt:     rt,
		s3:     s3,
		dek:    dek,
		bucket: bucket,
		window: anchorWindow(),
		enc:    enc,
	}, nil
}

func (a *freshnessAnchor) Establish(ctx context.Context, live map[string]uint64) error {
	keys, err := a.anchoredKeys(ctx)
	if err != nil {
		return err
	}
	versionFloor := make(map[string]uint64, len(keys))
	for _, key := range keys {
		anchored, err := a.anchoredVersion(ctx, key)
		if err != nil {
			return err
		}
		if live[key] < anchored {
			a.rt.NotifyHalt()
			return fmt.Errorf(
				"%w: key %q live=%d anchored=%d",
				ErrRollbackDetected,
				key,
				live[key],
				anchored,
			)
		}
		versionFloor[key] = anchored
	}
	a.mu.Lock()
	a.versionFloor = versionFloor
	a.mu.Unlock()
	return nil
}

// Record writes the locked anchor for a committed version.
func (a *freshnessAnchor) Record(ctx context.Context, key string, version uint64) error {
	body, err := a.enc.Marshal(anchorEntryV1{
		Schema:    anchorSchemaV1,
		Key:       key,
		Version:   version,
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return err
	}
	sealed, err := a.dek.Seal(body, anchorAAD(key, version))
	if err != nil {
		return err
	}
	if _, err := a.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:                    aws.String(a.bucket),
		Key:                       aws.String(anchorObjectKey(key, version)),
		Body:                      bytes.NewReader(sealed),
		ObjectLockMode:            s3types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: aws.Time(time.Now().Add(a.window)),
	}); err != nil {
		return fmt.Errorf("anchor put %q v%d: %w", key, version, err)
	}
	a.setVersionFloor(key, version)
	return nil
}

// CheckFresh fails if liveVersion is below the watermark.
func (a *freshnessAnchor) CheckFresh(key string, liveVersion uint64) error {
	a.mu.RLock()
	want, ok := a.versionFloor[key]
	a.mu.RUnlock()
	if ok && liveVersion < want {
		a.rt.NotifyHalt()
		return fmt.Errorf(
			"%w: key %q live=%d anchored=%d",
			ErrRollbackDetected,
			key,
			liveVersion,
			want,
		)
	}
	return nil
}

func (a *freshnessAnchor) setVersionFloor(key string, version uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.versionFloor == nil {
		a.versionFloor = map[string]uint64{}
	}
	if version > a.versionFloor[key] {
		a.versionFloor[key] = version
	}
}

// anchoredVersion returns the highest valid sealed version, or 0.
func (a *freshnessAnchor) anchoredVersion(ctx context.Context, key string) (uint64, error) {
	byVersion, err := a.listObjectVersions(ctx, anchorPrefix+key+"/", key)
	if err != nil {
		return 0, err
	}
	versions := make([]uint64, 0, len(byVersion))
	for v := range byVersion {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] > versions[j] })
	for _, v := range versions {
		for _, versionID := range byVersion[v] {
			if a.opens(ctx, key, v, versionID) {
				return v, nil
			}
		}
	}
	return 0, nil
}

// anchoredKeys lists keys via versions so a delete marker can't hide one.
func (a *freshnessAnchor) anchoredKeys(ctx context.Context) ([]string, error) {
	seen := map[string]struct{}{}
	var keyMarker, versionMarker *string
	for {
		out, err := a.s3.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket:          aws.String(a.bucket),
			Prefix:          aws.String(anchorPrefix),
			KeyMarker:       keyMarker,
			VersionIdMarker: versionMarker,
		})
		if err != nil {
			return nil, fmt.Errorf("anchor list keys: %w", err)
		}
		for _, v := range out.Versions {
			if k, _, ok := parseAnchorKey(aws.ToString(v.Key)); ok {
				seen[k] = struct{}{}
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		keyMarker, versionMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	return keys, nil
}

func (a *freshnessAnchor) listObjectVersions(
	ctx context.Context,
	prefix, key string,
) (map[uint64][]string, error) {
	byVersion := map[uint64][]string{}
	var keyMarker, versionMarker *string
	for {
		out, err := a.s3.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket:          aws.String(a.bucket),
			Prefix:          aws.String(prefix),
			KeyMarker:       keyMarker,
			VersionIdMarker: versionMarker,
		})
		if err != nil {
			return nil, fmt.Errorf("anchor list %q: %w", key, err)
		}
		for _, v := range out.Versions {
			k, ver, ok := parseAnchorKey(aws.ToString(v.Key))
			if !ok || k != key {
				continue
			}
			byVersion[ver] = append(byVersion[ver], aws.ToString(v.VersionId))
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		keyMarker, versionMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
	return byVersion, nil
}

func (a *freshnessAnchor) opens(
	ctx context.Context,
	key string,
	version uint64,
	versionID string,
) bool {
	out, err := a.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket:    aws.String(a.bucket),
		Key:       aws.String(anchorObjectKey(key, version)),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		return false
	}
	defer func() { _ = out.Body.Close() }()
	sealed, err := io.ReadAll(out.Body)
	if err != nil {
		return false
	}
	plain, err := a.dek.Open(sealed, anchorAAD(key, version))
	if err != nil {
		return false
	}
	var entry anchorEntryV1
	if err := cbor.Unmarshal(plain, &entry); err != nil {
		return false
	}
	return entry.Schema == anchorSchemaV1 && entry.Key == key && entry.Version == version
}

func anchorObjectKey(key string, version uint64) string {
	return fmt.Sprintf("%s%s/%020d", anchorPrefix, key, version)
}

// parseAnchorKey splits anchor/<key>/<version>; version is the final segment since key may contain "/".
func parseAnchorKey(objKey string) (string, uint64, bool) {
	rest, ok := strings.CutPrefix(objKey, anchorPrefix)
	if !ok {
		return "", 0, false
	}
	i := strings.LastIndex(rest, "/")
	if i < 0 {
		return "", 0, false
	}
	v, err := strconv.ParseUint(rest[i+1:], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return rest[:i], v, true
}

func anchorAAD(key string, version uint64) []byte {
	return fmt.Appendf(nil, "%s/%s/anchor/%s/%d", getDeployment(), getAppName(), key, version)
}

func anchorBucketParam() string {
	return fmt.Sprintf("/%s/%s/AnchorBucketName", getDeployment(), getAppName())
}
