package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// GRPCConn returns a *grpc.ClientConn whose TLS handshake pins the
// enclave's leaf cert fingerprint to the value embedded in the NSM
// attestation document's user_data. The attestation chain (PCR0,
// optional secret PCRs, attestation key binding) is verified before
// the connection is established and the result is cached for the
// configured CacheTTL.
//
// Native gRPC requests bypass the framework's response-signing
// middleware, so per-response Schnorr verification is not available
// over this transport. Trust is established at TLS handshake time
// instead: a wrong PCR0 or a TLS cert that does not match the
// attestation's tlsKeyHash makes the handshake fail.
//
// Usage:
//
//	conn, err := c.GRPCConn(ctx)
//	if err != nil { return err }
//	defer conn.Close()
//	svc := pb.NewYourServiceClient(conn)
//	resp, err := svc.YourRPC(ctx, &pb.YourRequest{})
func (c *Client) GRPCConn(ctx context.Context, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	attest, err := c.ensureVerified(ctx)
	if err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}
	if attest.TLSKeyHash == "" {
		return nil, fmt.Errorf("attestation result has no TLS cert fingerprint")
	}

	tlsCfg := &tls.Config{
		// Disable the default chain check: nitriding's self-signed cert has
		// no PKI chain. Trust comes from VerifyPeerCertificate below.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificate presented")
			}
			got := sha256.Sum256(rawCerts[0])
			if !strings.EqualFold(hex.EncodeToString(got[:]), attest.TLSKeyHash) {
				return fmt.Errorf("TLS cert fingerprint mismatch: expected %s, got %x",
					attest.TLSKeyHash, got[:])
			}
			return nil
		},
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	}

	host := strings.TrimPrefix(c.baseURL, "https://")
	host = strings.TrimPrefix(host, "http://")

	dialOpts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	}, opts...)
	return grpc.NewClient(host, dialOpts...)
}
