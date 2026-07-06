package runtime

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnchor(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "unittest")
	t.Setenv("ENCLAVE_APP_NAME", "anchor")

	const bucketName = "anchor-bucket"
	ctx := context.Background()

	newAnchorWithS3 := func(t *testing.T, s3f *fakeS3) (FreshnessAnchor, *fakeS3, *runtimeState) {
		t.Helper()
		if s3f == nil {
			s3f = newFakeS3()
		}
		rt := newRuntimeState()
		ssm := NewSSM(&fakeSSM{params: map[string]string{anchorBucketParam(): bucketName}})

		anchor, err := NewFreshnessAnchor(
			ctx,
			rt,
			s3f,
			&dek{key: bytes.Repeat([]byte{0x42}, 32)},
			ssm,
		)
		require.NoError(t, err)
		return anchor, s3f, rt
	}
	newAnchor := func(t *testing.T) (FreshnessAnchor, *fakeS3, *runtimeState) {
		t.Helper()
		return newAnchorWithS3(t, nil)
	}

	t.Run("genesis passes", func(t *testing.T) {
		a, _, _ := newAnchor(t)
		require.NoError(t, a.Establish(ctx, map[string]uint64{}))
	})

	t.Run("establish passes after records", func(t *testing.T) {
		a, s3f, _ := newAnchor(t)

		require.NoError(t, a.Record(ctx, "a", 1))
		require.NoError(t, a.Record(ctx, "a", 2))
		require.NoError(t, a.Record(ctx, "b", 1))

		boot, _, _ := newAnchorWithS3(t, s3f)
		require.NoError(t, boot.Establish(ctx, map[string]uint64{"a": 2, "b": 1}))
	})

	t.Run("boot gate detects rollback", func(t *testing.T) {
		a, s3f, _ := newAnchor(t)

		require.NoError(t, a.Record(ctx, "a", 1))
		require.NoError(t, a.Record(ctx, "a", 2))

		boot, _, rt := newAnchorWithS3(t, s3f)
		err := boot.Establish(ctx, map[string]uint64{"a": 1})
		require.ErrorIs(t, err, ErrRollbackDetected)
		require.True(t, rt.Halted())
	})

	t.Run("check fresh detects rollback", func(t *testing.T) {
		a, _, rt := newAnchor(t)

		require.NoError(t, a.Record(ctx, "a", 1))
		require.NoError(t, a.Record(ctx, "a", 2))

		err := a.CheckFresh("a", 1)
		require.ErrorIs(t, err, ErrRollbackDetected)
		require.True(t, rt.Halted())
	})

	t.Run("check fresh allows current", func(t *testing.T) {
		a, _, _ := newAnchor(t)

		require.NoError(t, a.Record(ctx, "a", 1))
		require.NoError(t, a.Record(ctx, "a", 2))

		require.NoError(t, a.CheckFresh("a", 2))
		require.NoError(t, a.CheckFresh("a", 3))
	})

	t.Run("delete version does not false positive", func(t *testing.T) {
		a, s3f, _ := newAnchor(t)

		require.NoError(t, a.Record(ctx, "a", 1))
		require.NoError(t, a.Record(ctx, "a", 2))

		boot, _, _ := newAnchorWithS3(t, s3f)
		require.NoError(t, boot.Establish(ctx, map[string]uint64{"a": 2}))
	})

	t.Run("forged versions ignored", func(t *testing.T) {
		a, s3f, _ := newAnchor(t)

		require.NoError(t, a.Record(ctx, "a", 1))
		require.NoError(t, a.Record(ctx, "a", 2))
		genuineV2 := append([]byte(nil), s3f.latestBody(anchorObjectKey("a", 2))...)

		s3f.putRawObject(anchorObjectKey("a", 2), []byte("garbage"))
		s3f.putRawObject(anchorObjectKey("a", 99), []byte("garbage"))
		s3f.putRawObject(anchorObjectKey("a", 99), genuineV2)

		boot, _, _ := newAnchorWithS3(t, s3f)
		require.NoError(t, boot.Establish(ctx, map[string]uint64{"a": 2}))
	})
}
