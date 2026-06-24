package runtime

// Per-write rollback prevention via DEK-sealed, Object-Lock-immutable anchors; version bound into object name and seal AAD.

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
	"sync/atomic"
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

// FreshnessAnchor records and verifies per-write anchors; nil receiver or empty bucket disables it.
type FreshnessAnchor struct {
	kv     *KVStore
	s3     S3API
	bucket string
	window time.Duration

	mu           sync.RWMutex
	versionFloor map[string]uint64
	halt         *atomic.Bool
}

// Init resolves the anchor bucket from SSM; empty/unset leaves it disabled.
func (a *FreshnessAnchor) Init(ctx context.Context) error {
	if a == nil {
		return nil
	}
	bucket, err := readSSMParamOptional(ctx, a.kv.kms.aws.SSM, anchorBucketParam())
	if err != nil {
		return fmt.Errorf("read anchor bucket name: %w", err)
	}
	a.bucket = bucket
	return nil
}

func (a *FreshnessAnchor) enabled() bool { return a != nil && a.bucket != "" }

// record writes the locked anchor for a committed version.
func (a *FreshnessAnchor) record(ctx context.Context, key string, version uint64) error {
	if !a.enabled() {
		return nil
	}
	body, err := canonicalCBOR.Marshal(anchorEntryV1{
		Schema:    anchorSchemaV1,
		Key:       key,
		Version:   version,
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return err
	}
	sealed, err := sealStorage(a.kv.dek, body, anchorAAD(key, version))
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

func (a *FreshnessAnchor) setVersionFloor(key string, version uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.versionFloor == nil {
		a.versionFloor = map[string]uint64{}
	}
	if version > a.versionFloor[key] {
		a.versionFloor[key] = version
	}
}

// checkFresh fails closed if a live head's version is below the watermark; missing heads are left to the boot gate.
func (a *FreshnessAnchor) checkFresh(key string, liveVersion uint64) error {
	if !a.enabled() {
		return nil
	}
	a.mu.RLock()
	want, ok := a.versionFloor[key]
	a.mu.RUnlock()
	if ok && liveVersion < want {
		if a.halt != nil {
			a.halt.Store(true)
		}
		return fmt.Errorf("%w: key %q live=%d anchored=%d", ErrRollbackDetected, key, liveVersion, want)
	}
	return nil
}

// Establish is the boot gate: loads the watermark and fails closed on any live version already below it.
func (a *FreshnessAnchor) Establish(ctx context.Context) error {
	if !a.enabled() {
		return nil
	}
	live, err := a.kv.VersionVector(ctx)
	if err != nil {
		return fmt.Errorf("anchor establish: read live versions: %w", err)
	}
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
			return fmt.Errorf("%w: key %q live=%d anchored=%d", ErrRollbackDetected, key, live[key], anchored)
		}
		versionFloor[key] = anchored
	}
	a.mu.Lock()
	a.versionFloor = versionFloor
	a.mu.Unlock()
	return nil
}

// anchoredVersion returns the highest version with a validly-sealed object (tampered ones fail seal/AAD and are skipped), 0 if never anchored.
func (a *FreshnessAnchor) anchoredVersion(ctx context.Context, key string) (uint64, error) {
	if !a.enabled() {
		return 0, nil
	}
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

// anchoredKeys lists every distinct anchored key via ListObjectVersions so a delete marker can't hide one.
func (a *FreshnessAnchor) anchoredKeys(ctx context.Context) ([]string, error) {
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

func (a *FreshnessAnchor) listObjectVersions(ctx context.Context, prefix, key string) (map[uint64][]string, error) {
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

func (a *FreshnessAnchor) opens(ctx context.Context, key string, version uint64, versionID string) bool {
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
	plain, err := openStorage(a.kv.dek, sealed, anchorAAD(key, version))
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
