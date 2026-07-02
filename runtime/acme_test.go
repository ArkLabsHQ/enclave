package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
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
		{"storage without DEK", func() *Storage { return NewStorage(nil) }},
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

// acmeTestCAPEM returns a freshly generated, parseable CERTIFICATE PEM block.
func acmeTestCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "acme test ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestACMEClientForDirectory(t *testing.T) {
	ca := acmeTestCAPEM(t)

	t.Run("custom https directory with CA", func(t *testing.T) {
		c, err := acmeClientForDirectory("https://pebble.internal:14000/dir", ca)
		if err != nil {
			t.Fatal(err)
		}
		if c == nil || c.DirectoryURL != "https://pebble.internal:14000/dir" {
			t.Fatalf("client = %+v, want DirectoryURL set", c)
		}
		if c.HTTPClient == nil {
			t.Error("HTTPClient = nil, want a client trusting the custom CA")
		}
	})

	t.Run("custom https directory without CA", func(t *testing.T) {
		c, err := acmeClientForDirectory("https://pebble.internal:14000/dir", "")
		if err != nil {
			t.Fatal(err)
		}
		if c == nil || c.HTTPClient != nil {
			t.Fatalf("client = %+v, want non-nil client with nil HTTPClient", c)
		}
	})

	t.Run("letsencrypt-staging maps to the staging URL", func(t *testing.T) {
		c, err := acmeClientForDirectory("letsencrypt-staging", "")
		if err != nil {
			t.Fatal(err)
		}
		if c == nil || c.DirectoryURL != acmeStagingDirectoryURL {
			t.Fatalf("client = %+v, want the staging directory URL", c)
		}
	})

	for _, dir := range []string{"letsencrypt", "self-signed", ""} {
		t.Run("no custom client for "+dir, func(t *testing.T) {
			c, err := acmeClientForDirectory(dir, "")
			if err != nil {
				t.Fatal(err)
			}
			if c != nil {
				t.Errorf("client = %+v, want nil (autocert default)", c)
			}
		})
	}

	t.Run("malformed CA is an error", func(t *testing.T) {
		if _, err := acmeClientForDirectory("https://pebble.internal/dir", "not a pem"); err == nil {
			t.Error("expected an error for a malformed CA PEM")
		}
	})
}
