package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func testTLSCertificate(t *testing.T, key *ecdsa.PrivateKey, serial int64) tls.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestRetainedPinAcrossConnections(t *testing.T) {
	for _, protocol := range []string{"HTTP", "gRPC"} {
		t.Run(protocol, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			original := testTLSCertificate(t, key, 1)
			renewed := testTLSCertificate(t, key, 2)
			otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			other := testTLSCertificate(t, otherKey, 3)
			var active atomic.Pointer[tls.Config]
			setCert := func(cert tls.Certificate) {
				active.Store(
					&tls.Config{
						Certificates: []tls.Certificate{cert},
						NextProtos:   []string{"h2", "http/1.1"},
					},
				)
			}
			setCert(original)
			fe := &fakeEnclave{
				pcr0Hex:     strings.Repeat("ab", 48),
				attestedTLS: sha256.Sum256(original.Leaf.RawSubjectPublicKeyInfo),
			}
			var applicationCalls, handshakes atomic.Int32
			grpcServer := grpc.NewServer()
			t.Cleanup(grpcServer.Stop)
			healthpb.RegisterHealthServer(grpcServer, health.NewServer())
			handler := fe.handler()
			srv := httptest.NewUnstartedServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// ponytail: count HTTP and gRPC requests before dispatch.
					if r.URL.Path != "/enclave/attestation" {
						applicationCalls.Add(1)
					}
					if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
						grpcServer.ServeHTTP(w, r)
						return
					}
					handler.ServeHTTP(w, r)
				}),
			)
			srv.EnableHTTP2 = true
			srv.TLS = &tls.Config{
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					handshakes.Add(1)
					return active.Load(), nil
				},
			}
			srv.StartTLS()
			t.Cleanup(srv.Close)
			c, err := New(srv.URL, Options{ExpectedPCR0: fe.pcr0Hex, InsecureSkipCOSEVerify: true})
			require.NoError(t, err)
			t.Cleanup(c.httpClient.CloseIdleConnections)
			t.Cleanup(c.bootstrapClient.CloseIdleConnections)
			request := func(ctx context.Context) error {
				_, err := c.Get(ctx, "/application")
				return err
			}
			if protocol == "gRPC" {
				// The verified client's credentials must win over caller dial options.
				conn, err := c.GRPCConn(
					context.Background(),
					grpc.WithTransportCredentials(insecure.NewCredentials()),
				)
				require.NoError(t, err)
				t.Cleanup(func() { _ = conn.Close() })
				healthClient := healthpb.NewHealthClient(conn)
				request = func(ctx context.Context) error {
					for {
						_, err := healthClient.Check(
							ctx,
							&healthpb.HealthCheckRequest{},
							grpc.WaitForReady(true),
						)
						// WaitForReady does not retry an RPC already assigned to
						// the connection when the server force-closes it.
						if status.Code(err) != codes.Unavailable || ctx.Err() != nil {
							return err
						}
					}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			require.NoError(t, request(ctx))
			pin := c.currentTLSHash()
			setCert(renewed)
			// Evict idle HTTP connections before the server closes them so the
			// next request cannot race with noticing a stale HTTP/2 connection.
			c.bootstrapClient.CloseIdleConnections()
			c.httpClient.CloseIdleConnections()
			srv.CloseClientConnections()
			_, err = c.VerifyAttestation(ctx)
			require.NoError(t, err)
			require.NoError(
				t,
				request(ctx),
				"renewal with the same key must reconnect successfully",
			)
			require.Equal(t, pin, c.currentTLSHash())

			// Keep the attestation unchanged but replace the live key on a reconnect.
			beforeCalls, beforeHandshakes := applicationCalls.Load(), handshakes.Load()
			setCert(other)
			c.bootstrapClient.CloseIdleConnections()
			c.httpClient.CloseIdleConnections()
			srv.CloseClientConnections()
			failedCtx, failedCancel := context.WithTimeout(ctx, 2*time.Second)
			defer failedCancel()
			require.Error(t, request(failedCtx))
			require.Greater(
				t,
				handshakes.Load(),
				beforeHandshakes,
				"must exercise a fresh TLS handshake",
			)
			require.Equal(
				t,
				beforeCalls,
				applicationCalls.Load(),
				"wrong key must block application traffic",
			)
			require.Equal(t, pin, c.currentTLSHash())
		})
	}
}
