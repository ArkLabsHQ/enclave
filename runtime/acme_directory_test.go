package runtime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

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
