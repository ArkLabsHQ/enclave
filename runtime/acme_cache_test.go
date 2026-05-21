package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func closedReadyChan() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

// With no operational storage, Get is a cache miss and Put/Delete are no-ops,
// so ACME issuance still succeeds (autocert keeps the cert in memory for the
// process lifetime regardless).
func TestACMEStorageCache_StorageUnavailable(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		storage func() *Storage
	}{
		{"nil storage", func() *Storage { return nil }},
		{"storage without DEK", func() *Storage { return NewStorage(nil, nil, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &acmeStorageCache{ready: closedReadyChan(), storage: tc.storage}
			if _, err := c.Get(ctx, "example.com"); !errors.Is(err, autocert.ErrCacheMiss) {
				t.Errorf("Get = %v, want ErrCacheMiss", err)
			}
			if err := c.Put(ctx, "example.com", []byte("cert")); err != nil {
				t.Errorf("Put = %v, want nil", err)
			}
			if err := c.Delete(ctx, "example.com"); err != nil {
				t.Errorf("Delete = %v, want nil", err)
			}
		})
	}
}

// Operations block on the ready signal; if the context expires first they
// return the context error rather than a (wrong) cache miss — otherwise a
// reboot would re-issue instead of reusing the persisted cert.
func TestACMEStorageCache_BlocksOnReady(t *testing.T) {
	c := &acmeStorageCache{
		ready:   make(chan struct{}), // never closed
		storage: func() *Storage { return nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Get(ctx, "example.com"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Get before ready = %v, want DeadlineExceeded", err)
	}
}
