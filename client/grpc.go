package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// GRPCConn returns a *grpc.ClientConn whose TLS handshake pins the
// enclave's TLS PublicKey fingerprint to the value embedded in the NSM
// attestation document's user_data. PCR0 and optional secret PCRs are verified
// before the connection is established, and the result is cached for the
// configured CacheTTL.
//
// HTTP and gRPC use the same trust model: verified Nitro attestation plus a TLS
// handshake pinned to its leaf hash. A wrong PCR0 or mismatched certificate
// makes the connection fail.
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
		return nil, fmt.Errorf("attestation result has no TLS public-key fingerprint")
	}

	tlsCfg := &tls.Config{
		// Disable the default chain check: nitriding's self-signed cert has
		// no PKI chain. Trust comes from the shared pin below.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyLeafCertPin(rawCerts, attest.TLSKeyHash)
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
