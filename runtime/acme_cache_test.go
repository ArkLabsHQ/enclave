package runtime

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme/autocert"
)

func TestACMEStorageCache(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "unittest")
	t.Setenv("ENCLAVE_APP_NAME", "acme_cache")

	const bucketName = "cert-bucket"
	bucketParam := "/unittest/acme_cache/StorageBucketName"
	ctx := context.Background()

	newCache := func(t *testing.T) (*acmeStorageCache, *fakeS3) {
		t.Helper()
		s3f := newFakeS3()
		ssm := NewSSM(&fakeSSM{params: map[string]string{bucketParam: bucketName}})
		cache, err := NewAcmeStorageCache(ctx, s3f, &dek{key: bytes.Repeat([]byte{0x42}, 32)}, ssm)
		require.NoError(t, err)
		c, ok := cache.(*acmeStorageCache)
		require.True(t, ok)
		return c, s3f
	}

	t.Run("loads bucket from SSM", func(t *testing.T) {
		c, _ := newCache(t)
		require.Equal(t, bucketName, c.bucket)
	})

	t.Run("get miss", func(t *testing.T) {
		c, _ := newCache(t)
		_, err := c.Get(ctx, "example.com")
		require.ErrorIs(t, err, autocert.ErrCacheMiss)
	})

	t.Run("put get delete", func(t *testing.T) {
		c, s3f := newCache(t)
		key := prefixAcmeCacheKey("example.com")
		cert := []byte("cert material")

		require.NoError(t, c.Put(ctx, "example.com", cert))
		require.NotEmpty(t, s3f.latestBody(key))
		require.NotEqual(t, cert, s3f.latestBody(key))

		got, err := c.Get(ctx, "example.com")
		require.NoError(t, err)
		require.Equal(t, cert, got)

		require.NoError(t, c.Delete(ctx, "example.com"))
		_, err = c.Get(ctx, "example.com")
		require.ErrorIs(t, err, autocert.ErrCacheMiss)
	})

	t.Run("rejects relabeled object", func(t *testing.T) {
		c, s3f := newCache(t)
		require.NoError(t, c.Put(ctx, "example.com", []byte("cert material")))

		s3f.putRawObject(
			prefixAcmeCacheKey("other.example.com"),
			s3f.latestBody(prefixAcmeCacheKey("example.com")),
		)
		_, err := c.Get(ctx, "other.example.com")
		require.Error(t, err)
	})
}
