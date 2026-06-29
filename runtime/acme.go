package runtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// acmeRoundTripper is the ACME client's HTTP transport. It works around Pebble
// omitting the Location header on its finalize-order response, which leaves
// x/crypto/acme unable to poll the order: the order URL, remembered from an
// earlier Location header, is re-attached to any response missing one. A no-op
// against a directory that sets Location, such as real Let's Encrypt.
type acmeRoundTripper struct {
	base http.RoundTripper
	mu   sync.Mutex
	urls map[string]string // resource ID (trailing path segment) -> resource URL
}

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

// acmeStoragePrefix namespaces ACME cache entries within the encrypted
// Storage K/V space, keeping them clear of user data and secrets.
const acmeStoragePrefix = "acme/"

// errStorageUnavailable signals that storage has settled but is not
// operational (no bucket provisioned). Internal to acmeStorageCache.await.
var errStorageUnavailable = errors.New("storage unavailable")

// acmeClientForDirectory returns the acme.Client autocert should use for the
// given directory selector, or nil to let autocert default to Let's Encrypt
// production. A value beginning with "https://" is a literal ACME directory URL
// (a private or test ACME server such as Pebble); "letsencrypt-staging" maps to
// the Let's Encrypt staging directory; anything else returns (nil, nil).
//
// When caPEM is non-empty it is installed as the sole root for the client's
// HTTPS transport, so the enclave can verify a private ACME server's own
// (non-public) API certificate. caPEM is irrelevant for the public Let's
// Encrypt endpoints, which chain to the system roots baked into the EIF.
func acmeClientForDirectory(directory, caPEM string) (*acme.Client, error) {
	var dirURL string
	switch {
	case strings.HasPrefix(directory, "https://"):
		dirURL = directory
	case directory == "letsencrypt-staging":
		dirURL = acmeStagingDirectoryURL
	default:
		return nil, nil
	}
	client := &acme.Client{DirectoryURL: dirURL}
	if caPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("ENCLAVE_NITRIDING_ACME_CA: no certificates parsed")
		}
		client.HTTPClient = &http.Client{
			Timeout: 90 * time.Second,
			Transport: newACMERoundTripper(&http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			}),
		}
	}
	return client, nil
}

func newACMERoundTripper(base http.RoundTripper) *acmeRoundTripper {
	return &acmeRoundTripper{base: base, urls: make(map[string]string)}
}

func (rt *acmeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		slog.Warn("ACME http", "method", req.Method, "url", req.URL.String(), "error", err)
		return resp, err
	}

	lastPathSegment := func(s string) string {
		if i := strings.LastIndexByte(s, '/'); i >= 0 {
			return s[i+1:]
		}
		return s
	}

	loc := resp.Header.Get("Location")
	rt.mu.Lock()
	if loc != "" {
		rt.urls[lastPathSegment(loc)] = loc
	} else if known := rt.urls[lastPathSegment(req.URL.Path)]; known != "" {
		resp.Header.Set("Location", known)
		loc = known
	}
	rt.mu.Unlock()

	slog.Info("ACME http",
		"method", req.Method, "url", req.URL.String(), "status", resp.StatusCode, "location", loc)
	return resp, err
}

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
