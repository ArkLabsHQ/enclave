package runtime

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// fakeS3 — in-memory, versioned object store. Each PutObject appends a new
// version; nothing is overwritten or removed (modelling Object Lock). Only the
// subset the anchor uses is implemented.
// =============================================================================

type s3Version struct {
	id   string
	body []byte
}

type fakeS3 struct {
	mu      sync.Mutex
	seq     int
	objects map[string][]s3Version // object key → versions, append order
}

func newFakeS3() *fakeS3 { return &fakeS3{objects: map[string][]s3Version{}} }

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(in.Body)
	f.seq++
	id := strconv.Itoa(f.seq)
	key := aws.ToString(in.Key)
	f.objects[key] = append(f.objects[key], s3Version{id: id, body: body})
	return &s3.PutObjectOutput{VersionId: aws.String(id)}, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	versions := f.objects[aws.ToString(in.Key)]
	for i := len(versions) - 1; i >= 0; i-- {
		if in.VersionId == nil || versions[i].id == aws.ToString(in.VersionId) {
			return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(versions[i].body))}, nil
		}
	}
	return nil, &s3types.NoSuchKey{}
}

func (f *fakeS3) ListObjectVersions(_ context.Context, in *s3.ListObjectVersionsInput, _ ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := aws.ToString(in.Prefix)
	var out []s3types.ObjectVersion
	for key, versions := range f.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		for _, v := range versions {
			out = append(out, s3types.ObjectVersion{Key: aws.String(key), VersionId: aws.String(v.id)})
		}
	}
	return &s3.ListObjectVersionsOutput{Versions: out, IsTruncated: aws.Bool(false)}, nil
}

func (f *fakeS3) ListObjectsV2(_ context.Context, _ *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	return &s3.ListObjectsV2Output{}, nil
}

func (f *fakeS3) DeleteObject(_ context.Context, _ *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	return &s3.DeleteObjectOutput{}, nil // compliance lock: deletes are no-ops here
}

// appendVersion injects a raw object version, simulating an operator writing to
// the bucket (it can append but, lacking the DEK, cannot produce a valid seal).
func (f *fakeS3) appendVersion(key string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	f.objects[key] = append(f.objects[key], s3Version{id: strconv.Itoa(f.seq), body: body})
}

func (f *fakeS3) latestBody(key string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.objects[key]
	if len(v) == 0 {
		return nil
	}
	return v[len(v)-1].body
}

// setHeadVersion rewrites a key's live head version in DynamoDB, simulating an
// operator rolling the store back to an earlier point.
func (f *fakeDDB) setHeadVersion(t *testing.T, key string, ver uint64) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	ck := getPartitionKey(key) + "\x00" + kvHeadSK
	it := f.items[ck]
	if it == nil {
		t.Fatalf("no head item for %q", key)
	}
	it["ver"] = &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(ver, 10)}
}

// =============================================================================
// Anchor tests — real KVStore + fakeDDB + fakeS3
// =============================================================================

func newAnchoredKV(t *testing.T) (*KVStore, *fakeDDB, *fakeS3) {
	t.Helper()
	ddb := newFakeDDB()
	s3f := newFakeS3()
	kv := newEngineKV(ddb)
	kv.anchor = &FreshnessAnchor{kv: kv, s3: s3f, bucket: "anchor-bucket", window: time.Hour}
	return kv, ddb, s3f
}

func TestAnchor_VerifyPassesAfterWrites(t *testing.T) {
	kv, _, _ := newAnchoredKV(t)
	ctx := context.Background()
	mustSet(t, kv, "a", "1")
	mustSet(t, kv, "a", "2")
	mustSet(t, kv, "b", "x")

	av, err := kv.anchor.anchoredVersion(ctx, "a")
	require.NoError(t, err)
	require.Equal(t, uint64(2), av)
	require.NoError(t, kv.anchor.Establish(ctx))
}

func TestAnchor_GenesisPasses(t *testing.T) {
	kv, _, _ := newAnchoredKV(t)
	require.NoError(t, kv.anchor.Establish(context.Background()))
}

// Boot gate: an offline rollback (live version below the anchored watermark)
// fails Establish closed, so the enclave never starts serving.
func TestAnchor_BootGateDetectsRollback(t *testing.T) {
	kv, ddb, _ := newAnchoredKV(t)
	ctx := context.Background()
	mustSet(t, kv, "a", "1")
	mustSet(t, kv, "a", "2") // anchored watermark = 2

	ddb.setHeadVersion(t, "a", 1) // operator rolls the store back while down

	require.ErrorIs(t, kv.anchor.Establish(ctx), ErrRollbackDetected)
}

// Per-read check: a live rollback under a running enclave is caught the moment
// the key is read, returns ErrRollbackDetected, and trips the halt flag.
func TestAnchor_PerReadDetectsRollback(t *testing.T) {
	kv, ddb, _ := newAnchoredKV(t)
	var halt atomic.Bool
	kv.anchor.halt = &halt
	ctx := context.Background()
	mustSet(t, kv, "a", "1")
	mustSet(t, kv, "a", "2") // in-memory version floor[a] = 2

	ddb.setHeadVersion(t, "a", 1) // live rollback after the write was acked

	_, _, err := kv.Get(ctx, "a")
	require.ErrorIs(t, err, ErrRollbackDetected)
	require.True(t, halt.Load(), "read-time rollback must set the halt flag")
}

// A read whose version meets or exceeds the version floor serves normally.
func TestAnchor_PerReadAllowsCurrent(t *testing.T) {
	kv, _, _ := newAnchoredKV(t)
	ctx := context.Background()
	mustSet(t, kv, "a", "1")
	mustSet(t, kv, "a", "2")

	val, _, err := kv.Get(ctx, "a")
	require.NoError(t, err)
	require.Equal(t, "2", string(val))
}

func TestAnchor_DeletedKeyDoesNotFalsePositive(t *testing.T) {
	kv, _, _ := newAnchoredKV(t)
	ctx := context.Background()
	mustSet(t, kv, "a", "1")
	_, _, err := kv.Del(ctx, "a") // tombstone bumps version to 2 and anchors it
	require.NoError(t, err)
	require.NoError(t, kv.anchor.Establish(ctx))
}

// An operator can append garbage versions (it lacks the DEK) but cannot lower
// the watermark or forge a rollback past it.
func TestAnchor_ForgedVersionsIgnored(t *testing.T) {
	kv, _, s3f := newAnchoredKV(t)
	ctx := context.Background()
	mustSet(t, kv, "a", "1")
	mustSet(t, kv, "a", "2")

	// Garbage appended over the real v2 object, and a high-numbered forgery.
	s3f.appendVersion(anchorObjectKey("a", 2), []byte("garbage"))
	s3f.appendVersion(anchorObjectKey("a", 99), []byte("garbage"))
	// Replay: copy the genuine v2 body under a higher name; the AAD binds the
	// version, so it must not be accepted as v99.
	s3f.appendVersion(anchorObjectKey("a", 99), s3f.latestBody(anchorObjectKey("a", 2)))

	av, err := kv.anchor.anchoredVersion(ctx, "a")
	require.NoError(t, err)
	require.Equal(t, uint64(2), av)
	require.NoError(t, kv.anchor.Establish(ctx))
}

func TestAnchor_DisabledIsNoop(t *testing.T) {
	kv := newEngineKV(newFakeDDB()) // no anchor wired
	ctx := context.Background()
	mustSet(t, kv, "a", "1")
	require.NoError(t, kv.anchor.Establish(ctx)) // nil receiver → no-op
}

func mustSet(t *testing.T, kv *KVStore, key, val string) {
	t.Helper()
	_, ok, err := kv.SetMode(context.Background(), key, []byte(val), 0, setAlways)
	require.NoError(t, err)
	require.True(t, ok, "set %q=%q not applied", key, val)
}
