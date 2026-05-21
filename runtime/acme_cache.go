package runtime

import (
	"context"
	"errors"

	"golang.org/x/crypto/acme/autocert"
)

// acmeStoragePrefix namespaces ACME cache entries within the encrypted
// Storage K/V space, keeping them clear of user data and secrets.
const acmeStoragePrefix = "acme/"

// errStorageUnavailable signals that storage has settled but is not
// operational (no bucket provisioned). Internal to acmeStorageCache.await.
var errStorageUnavailable = errors.New("storage unavailable")

// acmeStorageCache is an autocert.Cache backed by the enclave's encrypted
// Storage subsystem. Cert material (the leaf cert + key and the ACME account
// key) is AES-GCM sealed under the storage DEK and persisted in S3, so it
// survives reboots and migrations without leaving the enclave in plaintext —
// the enclave reuses one cert instead of re-issuing on every boot, which
// would otherwise exhaust the Let's Encrypt rate limit.
//
// Storage initializes during Runtime.Init, which runs after Start (and thus
// after configureACME wires this cache). Every operation first waits on
// ready. If no storage bucket is provisioned the cache degrades to a no-op
// (a cache miss) — no worse than the in-memory cache it replaces.
type acmeStorageCache struct {
	ready   <-chan struct{} // closed by Runtime.Init once storage state is settled
	storage func() *Storage // resolves the Storage subsystem; valid once ready closes
}

var _ autocert.Cache = (*acmeStorageCache)(nil)

// await blocks until storage initialization has settled, then returns the
// operational Storage — or errStorageUnavailable if storage is not
// provisioned, or the context error if ready does not fire in time.
func (c *acmeStorageCache) await(ctx context.Context) (*Storage, error) {
	select {
	case <-c.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	s := c.storage()
	if s == nil || !s.HasDEK() {
		return nil, errStorageUnavailable
	}
	return s, nil
}

// Get returns the cached value for key, or autocert.ErrCacheMiss.
func (c *acmeStorageCache) Get(ctx context.Context, key string) ([]byte, error) {
	s, err := c.await(ctx)
	if errors.Is(err, errStorageUnavailable) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, err
	}
	data, err := s.Load(ctx, acmeStoragePrefix+key)
	if errors.Is(err, ErrNotFound) {
		return nil, autocert.ErrCacheMiss
	}
	return data, err
}

// Put persists data under key. With no storage provisioned it is a no-op:
// a fresh issuance still succeeds, since autocert keeps the cert in its
// in-memory Manager state for the process lifetime regardless.
func (c *acmeStorageCache) Put(ctx context.Context, key string, data []byte) error {
	s, err := c.await(ctx)
	if errors.Is(err, errStorageUnavailable) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.Store(ctx, acmeStoragePrefix+key, data)
}

// Delete removes key from the cache.
func (c *acmeStorageCache) Delete(ctx context.Context, key string) error {
	s, err := c.await(ctx)
	if errors.Is(err, errStorageUnavailable) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.Delete(ctx, acmeStoragePrefix+key)
}
