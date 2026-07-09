package runtime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCertCallback(t *testing.T) {
	cert := tlsTestCertificate(t)
	for _, tc := range []struct {
		name, sni, wantSNI string
	}{
		{"nameless handshake resolves to FQDN", "", "enclave.test"},
		{"FQDN handshake passes through", "enclave.test", "enclave.test"},
		{"other server name is left untouched", "other.example", "other.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntimeState()
			delegated := make(chan string, 1)
			rt.SetTLSCertCallback(func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
				delegated <- h.ServerName
				return &cert, nil
			})

			serverConn, clientConn := net.Pipe()
			deadline := time.Now().Add(time.Second)
			_ = serverConn.SetDeadline(deadline)
			_ = clientConn.SetDeadline(deadline)

			serverDone := make(chan error, 1)
			go func() {
				server := tls.Server(
					serverConn,
					&tls.Config{GetCertificate: certCallback(rt, Config{FQDN: "enclave.test"})},
				)
				serverDone <- server.Handshake()
				_ = server.Close()
			}()

			client := tls.Client(
				clientConn,
				&tls.Config{ServerName: tc.sni, InsecureSkipVerify: true},
			)
			err := client.Handshake()
			_ = client.Close()

			require.NoError(t, err)
			require.NoError(t, <-serverDone)
			if got := <-delegated; got != tc.wantSNI {
				t.Fatalf("delegated SNI: got %q, want %q", got, tc.wantSNI)
			}
		})
	}
}

func tlsTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "enclave.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"enclave.test", "other.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestACMEClientForDirectory(t *testing.T) {
	ca := acmeTestCAPEM(t)

	t.Run("custom https directory with CA", func(t *testing.T) {
		c, err := acmeClientForDirectory("https://pebble.internal:14000/dir", ca)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, "https://pebble.internal:14000/dir", c.DirectoryURL)
		require.NotNil(t, c.HTTPClient)
	})

	t.Run("custom https directory without CA", func(t *testing.T) {
		c, err := acmeClientForDirectory("https://pebble.internal:14000/dir", "")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, "https://pebble.internal:14000/dir", c.DirectoryURL)
		require.Nil(t, c.HTTPClient)
	})

	t.Run("letsencrypt-staging maps to the staging URL", func(t *testing.T) {
		c, err := acmeClientForDirectory("letsencrypt-staging", "")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, acmeStagingDirectoryURL, c.DirectoryURL)
	})

	t.Run("empty directory disables custom client", func(t *testing.T) {
		c, err := acmeClientForDirectory("", "")
		require.NoError(t, err)
		require.Nil(t, c)
	})

	t.Run("unrecognized directory results in err", func(t *testing.T) {
		c, err := acmeClientForDirectory("/tmp/certs", "")
		require.ErrorContains(t, err, "unrecognized ACME directory")
		require.Nil(t, c)
	})

	t.Run("malformed CA is an error", func(t *testing.T) {
		_, err := acmeClientForDirectory("https://pebble.internal/dir", "not a pem")
		require.Error(t, err)
	})
}

func acmeTestCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "acme test ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NotNil(t, pemCert)
	return string(pemCert)
}
