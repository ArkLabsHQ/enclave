package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKVStore(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "unittest")
	t.Setenv("ENCLAVE_APP_NAME", "kvstore")

	ctx := context.Background()

	t.Run("aad binds version chunk and key", func(t *testing.T) {
		dek := testKVDEK()
		plaintext := []byte("the answer is 42")

		blob, err := dek.Seal(plaintext, getAAD("k", 5, 0, 0))
		require.NoError(t, err)

		got, err := dek.Open(blob, getAAD("k", 5, 0, 0))
		require.NoError(t, err)
		require.Equal(t, plaintext, got)

		cases := map[string][]byte{
			"older version": getAAD("k", 4, 0, 0),
			"newer version": getAAD("k", 6, 0, 0),
			"wrong index":   getAAD("k", 5, 1, 0),
			"wrong count":   getAAD("k", 5, 0, 2),
			"relabeled key": getAAD("other", 5, 0, 0),
			"wrong app":     []byte("unittest/evil/kv/k/v5/c0/0"),
		}

		for name, aad := range cases {
			t.Run(name, func(t *testing.T) {
				_, err := dek.Open(blob, aad)
				require.Error(t, err)
			})
		}
	})

	t.Run("set get versions and modes", func(t *testing.T) {
		kv, _, _, _ := newTestKV(t, ctx, nil, nil)

		v1, ok, err := kv.SetMode(ctx, "k", []byte("v1"), 0, setAlways)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, uint64(1), v1)

		got, ver, err := kv.Get(ctx, "k")
		require.NoError(t, err)
		require.Equal(t, []byte("v1"), got)
		require.Equal(t, v1, ver)

		_, ok, err = kv.SetMode(ctx, "k", []byte("nx"), 0, setNX)
		require.NoError(t, err)
		require.False(t, ok)

		got, _, err = kv.Get(ctx, "k")
		require.NoError(t, err)
		require.Equal(t, []byte("v1"), got)

		_, ok, err = kv.SetMode(ctx, "k", []byte("xx"), 0, setXX)
		require.NoError(t, err)
		require.True(t, ok)

		_, ok, err = kv.SetMode(ctx, "missing", []byte("x"), 0, setXX)
		require.NoError(t, err)
		require.False(t, ok)

		got, _, err = kv.Get(ctx, "k")
		require.NoError(t, err)
		require.Equal(t, []byte("xx"), got)

		_, _, err = kv.Get(ctx, "missing")
		require.ErrorIs(t, err, ErrKVNotFound)
	})

	t.Run("ttl expire and persist", func(t *testing.T) {
		kv, _, _, _ := newTestKV(t, ctx, nil, nil)

		ver, ok, err := kv.SetMode(ctx, "k", []byte("v"), 0, setAlways)
		require.NoError(t, err)
		require.True(t, ok)

		ttl, err := kv.TTL(ctx, "k")
		require.NoError(t, err)
		require.Equal(t, int64(-1), ttl)

		exists, expireVer, err := kv.Expire(ctx, "k", 60)
		require.NoError(t, err)
		require.True(t, exists)
		require.Equal(t, ver, expireVer)

		ttl, err = kv.TTL(ctx, "k")
		require.NoError(t, err)
		require.GreaterOrEqual(t, ttl, int64(0))

		persisted, err := kv.Persist(ctx, "k")
		require.NoError(t, err)
		require.True(t, persisted)

		ttl, err = kv.TTL(ctx, "k")
		require.NoError(t, err)
		require.Equal(t, int64(-1), ttl)

		exists, _, err = kv.Expire(ctx, "k", -1)
		require.NoError(t, err)
		require.True(t, exists)

		exists, err = kv.Exists(ctx, "k")
		require.NoError(t, err)
		require.False(t, exists)

		ttl, err = kv.TTL(ctx, "k")
		require.NoError(t, err)
		require.Equal(t, int64(-2), ttl)
	})

	t.Run("delete tombstone preserves version", func(t *testing.T) {
		kv, _, _, _ := newTestKV(t, ctx, nil, nil)

		v1, _, err := kv.SetMode(ctx, "k", []byte("v"), 0, setAlways)
		require.NoError(t, err)

		existed, deletedVersion, err := kv.Del(ctx, "k")
		require.NoError(t, err)
		require.True(t, existed)
		require.Greater(t, deletedVersion, v1)

		_, _, err = kv.Get(ctx, "k")
		require.ErrorIs(t, err, ErrKVNotFound)

		v3, ok, err := kv.SetMode(ctx, "k", []byte("again"), 0, setAlways)
		require.NoError(t, err)
		require.True(t, ok)
		require.Greater(t, v3, deletedVersion)
	})

	t.Run("incr", func(t *testing.T) {
		kv, _, _, _ := newTestKV(t, ctx, nil, nil)

		for _, tc := range []struct {
			name  string
			delta int64
			want  int64
		}{
			{name: "create", delta: 1, want: 1},
			{name: "add", delta: 5, want: 6},
			{name: "subtract", delta: -2, want: 4},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, _, err := kv.Incr(ctx, "n", tc.delta)
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			})
		}

		_, _, err := kv.SetMode(ctx, "bad", []byte("notanumber"), 0, setAlways)
		require.NoError(t, err)

		_, _, err = kv.Incr(ctx, "bad", 1)
		require.ErrorIs(t, err, ErrNotInteger)
	})

	t.Run("append getset rename", func(t *testing.T) {
		kv, _, _, _ := newTestKV(t, ctx, nil, nil)

		n, err := kv.Append(ctx, "a", []byte("foo"))
		require.NoError(t, err)
		require.Equal(t, 3, n)

		n, err = kv.Append(ctx, "a", []byte("bar"))
		require.NoError(t, err)
		require.Equal(t, 6, n)

		got, _, err := kv.Get(ctx, "a")
		require.NoError(t, err)
		require.Equal(t, []byte("foobar"), got)

		old, existed, err := kv.GetSet(ctx, "a", []byte("new"))
		require.NoError(t, err)
		require.True(t, existed)
		require.Equal(t, []byte("foobar"), old)

		_, existed, err = kv.GetSet(ctx, "fresh", []byte("v"))
		require.NoError(t, err)
		require.False(t, existed)

		require.NoError(t, kv.Rename(ctx, "a", "b"))

		_, _, err = kv.Get(ctx, "a")
		require.ErrorIs(t, err, ErrKVNotFound)

		got, _, err = kv.Get(ctx, "b")
		require.NoError(t, err)
		require.Equal(t, []byte("new"), got)

		err = kv.Rename(ctx, "missing", "x")
		require.ErrorIs(t, err, ErrKVNotFound)
	})

	t.Run("typed values", func(t *testing.T) {
		kv, _, _, _ := newTestKV(t, ctx, nil, nil)

		_, err := kv.ModifyTyped(ctx, "h", typeHash, func(cur []byte) ([]byte, bool, error) {
			require.Nil(t, cur)
			return []byte("blob-v1"), false, nil
		})
		require.NoError(t, err)

		typ, err := kv.TypeOf(ctx, "h")
		require.NoError(t, err)
		require.Equal(t, typeHash, typ)

		got, ok, err := kv.ReadTyped(ctx, "h", typeHash)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, []byte("blob-v1"), got)

		_, _, err = kv.ReadTyped(ctx, "h", typeList)
		require.ErrorIs(t, err, ErrWrongType)

		_, _, err = kv.Get(ctx, "h")
		require.ErrorIs(t, err, ErrWrongType)

		_, err = kv.ModifyTyped(ctx, "h", typeHash, func([]byte) ([]byte, bool, error) {
			return nil, true, nil
		})
		require.NoError(t, err)

		typ, err = kv.TypeOf(ctx, "h")
		require.NoError(t, err)
		require.Equal(t, "none", typ)
	})

	t.Run("chunked round trip", func(t *testing.T) {
		kv, _, _, _ := newTestKV(t, ctx, nil, nil)
		big := make([]byte, kvChunkSize*2+1234)

		_, err := rand.Read(big)
		require.NoError(t, err)

		_, ok, err := kv.SetMode(ctx, "blob", big, 0, setAlways)
		require.NoError(t, err)
		require.True(t, ok)

		got, _, err := kv.Get(ctx, "blob")
		require.NoError(t, err)
		require.Equal(t, big, got)
	})

	t.Run("scan returns live keys", func(t *testing.T) {
		kv, _, _, _ := newTestKV(t, ctx, nil, nil)

		_, _, err := kv.SetMode(ctx, "s", []byte("v"), 0, setAlways)
		require.NoError(t, err)

		_, err = kv.ModifyTyped(ctx, "h", typeHash, func([]byte) ([]byte, bool, error) {
			return []byte("typed"), false, nil
		})
		require.NoError(t, err)

		_, _, err = kv.SetMode(ctx, "gone", []byte("v"), 0, setAlways)
		require.NoError(t, err)

		_, _, err = kv.Del(ctx, "gone")
		require.NoError(t, err)

		_, _, err = kv.SetMode(ctx, "expired", []byte("v"), 0, setAlways)
		require.NoError(t, err)

		_, _, err = kv.Expire(ctx, "expired", -1)
		require.NoError(t, err)

		keys, next, err := kv.ScanKeys(ctx, "0", 10)
		require.NoError(t, err)
		require.Equal(t, "0", next)
		require.ElementsMatch(
			t,
			[]KVKeyInfo{{Key: "s", Type: "string"}, {Key: "h", Type: typeHash}},
			keys,
		)
	})

	t.Run("concurrent nx has one winner", func(t *testing.T) {
		kv, _, _, _ := newTestKV(t, ctx, nil, nil)
		const n = 32
		var wins int
		var mu sync.Mutex
		errCh := make(chan error, n)
		var wg sync.WaitGroup

		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, ok, err := kv.SetMode(ctx, "lock", []byte(strconv.Itoa(i)), 0, setNX)
				if err != nil {
					errCh <- err
					return
				}
				if ok {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}(i)
		}
		wg.Wait()
		close(errCh)

		for err := range errCh {
			require.NoError(t, err)
		}
		require.Equal(t, 1, wins)
	})

	t.Run("freshness anchor rejects rolled back head", func(t *testing.T) {
		ddb := newFakeDDB()
		s3f := newFakeS3()
		kv, _, _, _ := newTestKV(t, ctx, ddb, s3f)

		_, _, err := kv.SetMode(ctx, "k", []byte("v1"), 0, setAlways)
		require.NoError(t, err)
		v1Head := ddb.copyHead("k")
		require.NotNil(t, v1Head)

		_, _, err = kv.SetMode(ctx, "k", []byte("v2"), 0, setAlways)
		require.NoError(t, err)

		got, ver, err := kv.Get(ctx, "k")
		require.NoError(t, err)
		require.Equal(t, []byte("v2"), got)
		require.Equal(t, uint64(2), ver)

		ddb.replaceHead("k", v1Head)

		anchor, rt := newTestFreshnessAnchor(t, ctx, s3f)
		_, err = NewKVStore(ctx, ddb, newTestKVSSM(), testKVDEK(), anchor)
		require.ErrorIs(t, err, ErrRollbackDetected)
		require.True(t, rt.Halted())
	})
}

func newTestKV(
	t *testing.T,
	ctx context.Context,
	ddb *fakeDDB,
	s3f *fakeS3,
) (*kvStore, *fakeDDB, *fakeS3, *runtimeState) {
	t.Helper()
	if ddb == nil {
		ddb = newFakeDDB()
	}
	if s3f == nil {
		s3f = newFakeS3()
	}

	anchor, rt := newTestFreshnessAnchor(t, ctx, s3f)
	store, err := NewKVStore(ctx, ddb, newTestKVSSM(), testKVDEK(), anchor)
	require.NoError(t, err)

	kv, ok := store.(*kvStore)
	require.True(t, ok)
	return kv, ddb, s3f, rt
}

func newTestFreshnessAnchor(
	t *testing.T,
	ctx context.Context,
	s3f *fakeS3,
) (FreshnessAnchor, *runtimeState) {
	t.Helper()
	rt := newRuntimeState()
	anchor, err := NewFreshnessAnchor(ctx, rt, s3f, testKVDEK(), newTestKVSSM())
	require.NoError(t, err)
	return anchor, rt
}

func newTestKVSSM() SSM {
	return NewSSM(&fakeSSM{params: map[string]string{
		kvTableNameParam():  "kv-table",
		anchorBucketParam(): "anchor-bucket",
	}})
}

func testKVDEK() *dek {
	return &dek{key: bytes.Repeat([]byte{0x42}, 32)}
}
