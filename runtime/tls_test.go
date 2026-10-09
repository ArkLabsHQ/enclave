package runtime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWithDefaultSNI(t *testing.T) {
	cert := tlsTestCertificate(t)
	for _, tc := range []struct {
		name, sni, wantSNI string
	}{
		{"nameless handshake resolves to FQDN", "", "enclave.test"},
		{"FQDN handshake passes through", "enclave.test", "enclave.test"},
		{"other server name is left untouched", "other.example", "other.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delegated := make(chan string, 1)
			getCert := withDefaultSNI(
				"enclave.test",
				func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
					delegated <- h.ServerName
					return &cert, nil
				},
			)

			serverConn, clientConn := net.Pipe()
			deadline := time.Now().Add(time.Second)
			_ = serverConn.SetDeadline(deadline)
			_ = clientConn.SetDeadline(deadline)

			serverDone := make(chan error, 1)
			go func() {
				server := tls.Server(
					serverConn,
					&tls.Config{GetCertificate: getCert},
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

func TestWithDefaultSNINoFQDNLeavesSNIUntouched(t *testing.T) {
	var got string
	cb := withDefaultSNI("", func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		got = h.ServerName
		return nil, nil
	})
	_, _ = cb(&tls.ClientHelloInfo{})
	require.Empty(t, got)
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

// A fresh certificate store forces registration with the boot-provided signer.
func TestConfigureTLSUsesBootAccountKey(t *testing.T) {
	fx := newGenesisFixture(t, bytes.Repeat([]byte{1}, 48))
	result, err := fx.establish(t.Context())
	require.NoError(t, err)
	cfg := *stateOriginTestConfig()
	cfg.FQDN = "enclave.test"
	requests := make(chan []byte, 1)
	var endpoint string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "dGVzdC1ub25jZQ")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newAccount": endpoint + "/account",
				"newNonce":   endpoint + "/nonce",
				"newOrder":   endpoint + "/order",
			})
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/account":
			body, _ := io.ReadAll(r.Body)
			requests <- body
			w.Header().Set("Location", endpoint+"/accounts/1")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"status":"valid"}`)
		case "/order":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(
				w,
				`{"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"test stops after account registration"}`,
			)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	endpoint = srv.URL
	cfg.UseACME = true
	cfg.ACMEDirectory = endpoint + "/directory"
	cfg.ACMECA = string(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}),
	)
	_, ssm := stateOriginTestSSM(map[string]string{
		cfg.route53ZoneIDParam(): "zone",
		cfg.certBucketParam():    "certs",
		cfg.leaseBucketParam():   "leases",
	})
	s3 := newFakeS3()
	_, err = ConfigureTLS(
		t.Context(),
		&cfg,
		s3,
		result.dek,
		ssm,
		&fakeRoute53{},
		result.tlsKey,
		result.acmeAccountKey,
		&AttestationHashes{},
	)
	require.ErrorContains(t, err, "test stops after account registration")
	var body []byte
	select {
	case body = <-requests:
	default:
		t.Fatal("ACME client did not register with the boot-provided signer")
	}
	var jws struct{ Protected, Payload, Signature string }
	require.NoError(t, json.Unmarshal(body, &jws))
	decode := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		require.NoError(t, err)
		return b
	}
	var protected struct {
		Alg string
		JWK struct{ Kty, Crv, X, Y string }
	}
	require.NoError(t, json.Unmarshal(decode(jws.Protected), &protected))
	require.Equal(t, "ES256", protected.Alg)
	require.Equal(t, "EC", protected.JWK.Kty)
	require.Equal(t, "P-256", protected.JWK.Crv)
	key := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(decode(protected.JWK.X)),
		Y:     new(big.Int).SetBytes(decode(protected.JWK.Y)),
	}
	sig := decode(jws.Signature)
	require.Len(t, sig, 64)
	digest := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
	require.True(
		t,
		ecdsa.Verify(
			key,
			digest[:],
			new(big.Int).SetBytes(sig[:32]),
			new(big.Int).SetBytes(sig[32:]),
		),
		"the advertised key must sign the registration",
	)
	require.True(t, key.Equal(result.acmeAccountKey.Public()))
	require.False(t, key.Equal(result.tlsKey.Public()), "ACME and TLS use separate keys")
	for path := range s3.objects {
		require.NotContains(t, path, "account.key")
	}
}
