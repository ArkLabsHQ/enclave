package runtime

// Fleet-shared certificate storage.
//
// The certificate and its private key live in one DEK-sealed S3 object, so a
// write can never tear into a cert without its key. Every enclave of the same
// PCR0 derives the same DEK, so all of them can open it — that is what makes one
// certificate shareable across the fleet, and therefore what lets every enclave
// attest the same tlsKeyHash.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// errCertChanged reports a conditional write that lost: a peer rewrote the
// object while we were issuing.
var errCertChanged = errors.New("certificate store: object changed")

// storedCertV1 is the sealed object body.
type storedCertV1 struct {
	CertPEM []byte `json:"cert_pem"`
	KeyPEM  []byte `json:"key_pem"`
}

// certBundle is the parsed, ready-to-serve form. etag is the version of the
// stored object it came from, carried here so installing a certificate and
// recording its version cannot drift apart.
type certBundle struct {
	cert     *tls.Certificate
	notAfter time.Time
	leafHash [sha256.Size]byte
	etag     string
}

type certStore struct {
	s3     S3API
	dek    DEK
	bucket string
	fqdn   string
}

func newCertStore(s3api S3API, dek DEK, bucket, fqdn string) *certStore {
	return &certStore{s3: s3api, dek: dek, bucket: bucket, fqdn: fqdn}
}

func (c *certStore) certObjectKey() string {
	return prefixAcmeCacheKey(c.fqdn + "/cert")
}

func (c *certStore) accountObjectKey() string {
	return prefixAcmeCacheKey("account.key")
}

// certETag reports the current object's ETag, or "" when absent. Used by the
// refresher to notice a peer's renewal without downloading anything.
func (c *certStore) certETag(ctx context.Context) (string, error) {
	out, err := c.s3.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(c.certObjectKey()),
	})
	if err != nil {
		if isNoSuchKey(err) {
			return "", nil
		}
		return "", fmt.Errorf("head certificate: %w", err)
	}
	return aws.ToString(out.ETag), nil
}

// loadCert returns the stored bundle, or nil when the fleet has no certificate.
func (c *certStore) loadCert(ctx context.Context) (*certBundle, error) {
	raw, etag, err := c.get(ctx, c.certObjectKey())
	if err != nil || raw == nil {
		return nil, err
	}

	var stored storedCertV1
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("decode stored certificate: %w", err)
	}
	bundle, err := parseCertBundle(stored.CertPEM, stored.KeyPEM)
	if err != nil {
		return nil, err
	}
	bundle.etag = etag
	return bundle, nil
}

// saveCert writes the certificate conditionally. An empty expectedETag means
// "must not exist"; otherwise the object must still be exactly that version.
// Returns errCertChanged when the condition fails.
//
// This condition is the only thing containing a zombie issuer — an enclave whose
// lease lapsed while it was descheduled, which resumes with no way to know it was
// robbed. The lease cannot stop it. Never make this write unconditional.
func (c *certStore) saveCert(
	ctx context.Context,
	certPEM, keyPEM []byte,
	expectedETag string,
) (*certBundle, error) {
	// Parse before writing: a malformed chain stored here would poison every
	// enclave that later loads it.
	bundle, err := parseCertBundle(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(storedCertV1{CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		return nil, fmt.Errorf("encode certificate: %w", err)
	}
	etag, err := c.putConditional(ctx, c.certObjectKey(), body, expectedETag)
	if err != nil {
		return nil, err
	}
	bundle.etag = etag
	return bundle, nil
}

// loadAccountKey returns the fleet-shared ACME account key, or nil if unset.
func (c *certStore) loadAccountKey(ctx context.Context) ([]byte, error) {
	raw, _, err := c.get(ctx, c.accountObjectKey())
	return raw, err
}

// saveAccountKey stores the account key create-only, returning errCertChanged if
// a peer stored one first.
func (c *certStore) saveAccountKey(ctx context.Context, keyPEM []byte) error {
	_, err := c.putConditional(ctx, c.accountObjectKey(), keyPEM, "")
	return err
}

func (c *certStore) get(ctx context.Context, key string) ([]byte, string, error) {
	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isNoSuchKey(err) {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("get %q: %w", key, err)
	}
	defer func() { _ = out.Body.Close() }()

	sealed, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read %q: %w", key, err)
	}
	plaintext, err := c.dek.Open(sealed, []byte(key))
	if err != nil {
		return nil, "", fmt.Errorf("open %q: %w", key, err)
	}
	return plaintext, aws.ToString(out.ETag), nil
}

func (c *certStore) putConditional(
	ctx context.Context,
	key string,
	plaintext []byte,
	expectedETag string,
) (string, error) {
	sealed, err := c.dek.Seal(plaintext, []byte(key))
	if err != nil {
		return "", err
	}

	in := &s3.PutObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(sealed),
	}
	if expectedETag == "" {
		in.IfNoneMatch = aws.String("*")
	} else {
		in.IfMatch = aws.String(expectedETag)
	}

	out, err := c.s3.PutObject(ctx, in)
	if err != nil {
		if isPreconditionFailed(err) {
			return "", fmt.Errorf("%w: %s", errCertChanged, key)
		}
		return "", fmt.Errorf("put %q: %w", key, err)
	}
	return aws.ToString(out.ETag), nil
}

// parseCertBundle builds the served form and records the leaf fingerprint that
// clients pin against.
func parseCertBundle(certPEM, keyPEM []byte) (*certBundle, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load X509 key pair: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	cert.Leaf = leaf

	return &certBundle{
		cert:     &cert,
		notAfter: leaf.NotAfter,
		leafHash: sha256.Sum256(cert.Certificate[0]),
	}, nil
}
