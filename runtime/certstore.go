package runtime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// acmeStoragePrefix namespaces certificate material in the app storage bucket.
// The layout predates DNS-01 and is kept so existing deployments keep their
// certificate rather than re-issuing on upgrade.
const acmeStoragePrefix = "data/acme/"

func newCertStore(s3api S3API, dek DEK, bucket, fqdn string) *certStore {
	return &certStore{s3: s3api, dek: dek, bucket: bucket, fqdn: fqdn}
}

// LoadCert returns the stored bundle, or nil when the fleet has no certificate.
func (c *certStore) LoadCert(ctx context.Context) (*certBundle, error) {
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

func (c *certStore) SaveCert(
	ctx context.Context,
	certPEM, keyPEM []byte,
	expectedETag string,
) (*certBundle, error) {
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

// LoadOrCreateAccountKey returns ACME account key
func (c *certStore) LoadOrCreateAccountKey(ctx context.Context) (crypto.Signer, error) {
	pemBytes, err := c.loadAccountKey(ctx)
	if err != nil {
		return nil, err
	}
	if pemBytes != nil {
		return parseECKey(pemBytes)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ACME account key: %w", err)
	}
	encoded, err := encodeECKey(key)
	if err != nil {
		return nil, err
	}

	if err := c.saveAccountKey(ctx, encoded); err != nil {
		if !errors.Is(err, errCertChanged) {
			return nil, fmt.Errorf("store ACME account key: %w", err)
		}
		// A peer created the account between our load and our write. Theirs is
		// the fleet's key; discard the one we just generated.
		pemBytes, err = c.loadAccountKey(ctx)
		if err != nil {
			return nil, err
		}
		if pemBytes == nil {
			return nil, errors.New("ACME account key: create lost the race but no key is stored")
		}
		return parseECKey(pemBytes)
	}
	return key, nil
}

func objectKeyFor(name string) string {
	return getDeployment() + "/" + getAppName() + "/" + acmeStoragePrefix + name
}

func (c *certStore) certObjectKey() string {
	return objectKeyFor(c.fqdn + "/cert")
}

func (c *certStore) accountObjectKey() string {
	return objectKeyFor("account.key")
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
		// 412 means a peer moved the object. 409 is S3 losing an internal race
		// between concurrent conditional writes — different cause, same response
		// here: adopt whatever is there now rather than reporting a broken
		// issuance and burning another duplicate-certificate slot on a retry.
		if isPreconditionFailed(err) || isConditionalConflict(err) {
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
