package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ArkLabsHQ/enclave/runtime/nitriding"
	"golang.org/x/crypto/acme"
)

const (
	// acmeStagingDirectoryURL is Let's Encrypt's staging ACME endpoint — an
	// untrusted root with high rate limits, used for testing.
	acmeStagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	certificateOrg          = "AWS Nitro enclave application"
	certificateValidity     = time.Hour * 24 * 356
)

type TLSCertCallback func(*tls.ClientHelloInfo) (*tls.Certificate, error)

// withDefaultSNI fills a missing server name so IP/loopback probes reach the
// same cert source as named clients.
func withDefaultSNI(fqdn string, next TLSCertCallback) TLSCertCallback {
	if fqdn == "" {
		return next
	}
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != "" {
			return next(hello)
		}
		h := *hello
		h.ServerName = fqdn
		return next(&h)
	}
}

// ConfigureTLS picks the certificate source: self-signed when ACME is off,
// otherwise a fleet-shared certificate obtained via DNS-01.
//
// DNS-01 is the only supported challenge. tls-alpn-01 cannot survive a load
// balancer — the CA's connection is hashed to an arbitrary target while only the
// enclave that created the order holds the challenge certificate — so ACME
// requires a Route53 hosted zone.
func ConfigureTLS(
	ctx context.Context,
	cfg *Config,
	s3 S3API,
	dek DEK,
	ssm SSM,
	r53 Route53API,
	hashes AttestationHashes,
) (TLSCertCallback, error) {
	if err := loadTLSConfigOverridesFromSSM(ctx, ssm, cfg); err != nil {
		return nil, fmt.Errorf("failed to load TLS SSM overrides: %w", err)
	}

	if !cfg.UseACME {
		return configureSelfSignedCert(cfg, hashes)
	}

	// Outside an enclave there is no DEK to seal the shared store with, so ACME
	// is unavailable; local runs get a self-signed certificate.
	if !nitriding.InEnclave() {
		slog.Warn("not running in an enclave, serving a self-signed certificate")
		return configureSelfSignedCert(cfg, hashes)
	}

	zoneID, err := ssm.MayGet(ctx, route53ZoneIDParam())
	if err != nil {
		return nil, fmt.Errorf("failed to read Route53 zone ID: %w", err)
	}
	if zoneID == "" {
		// Fail rather than quietly serve self-signed: an operator who asked for
		// ACME and silently got an untrusted certificate finds out from clients.
		return nil, fmt.Errorf(
			"ACME is enabled but %s is unset; DNS-01 is the only supported challenge "+
				"and needs a Route53 hosted zone", route53ZoneIDParam(),
		)
	}
	return configureSharedDNS01Cert(ctx, cfg, s3, dek, ssm, r53, zoneID, hashes)
}

// configureSharedDNS01Cert brings up the fleet-shared certificate: load or issue
// one now, then keep it fresh in the background.
func configureSharedDNS01Cert(
	ctx context.Context,
	cfg *Config,
	s3 S3API,
	dek DEK,
	ssm SSM,
	r53 Route53API,
	zoneID string,
	hashes AttestationHashes,
) (TLSCertCallback, error) {
	bucket, err := ssm.MustGet(ctx, storageBucketParam())
	if err != nil {
		return nil, fmt.Errorf("failed to read storage bucket name: %w", err)
	}

	store := newCertStore(s3, dek, bucket, cfg.FQDN)

	accountKey, err := loadOrCreateAccountKey(ctx, store)
	if err != nil {
		return nil, err
	}
	client, err := acmeClientForDirectory(cfg.ACMEDirectory, cfg.ACMECA)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &acme.Client{DirectoryURL: acme.LetsEncryptURL}
	}
	client.Key = accountKey

	provider, err := newRoute53Provider(r53, zoneID)
	if err != nil {
		return nil, err
	}

	manager := newCertManager(
		store, newACMEIssuer(client, provider, cfg.ACMEEmail),
		s3, bucket, cfg.FQDN, hashes,
	)
	if err := manager.bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("failed to establish shared certificate: %w", err)
	}
	go manager.Run(ctx)

	slog.Info("serving fleet-shared certificate via DNS-01", "fqdn", cfg.FQDN, "zone", zoneID)
	return manager.GetCertificate, nil
}

func loadTLSConfigOverridesFromSSM(ctx context.Context, ssm SSM, cfg *Config) error {
	loadSSMOverride := func(name string, updateCfg func(val string)) error {
		val, err := ssm.MayGet(ctx, envVarOverridePath(name))
		if err != nil {
			return err
		}
		if val != "" {
			updateCfg(val)
		}
		return nil
	}

	if err := loadSSMOverride(
		"ENCLAVE_NITRIDING_FQDN",
		func(val string) { cfg.FQDN = val },
	); err != nil {
		return err
	}
	if err := loadSSMOverride("ENCLAVE_NITRIDING_USE_ACME", func(val string) {
		cfg.UseACME = strings.EqualFold(val, "true")
	}); err != nil {
		return err
	}
	if err := loadSSMOverride("ENCLAVE_NITRIDING_ACME_DIRECTORY", func(val string) {
		cfg.ACMEDirectory = val
	}); err != nil {
		return err
	}
	if err := loadSSMOverride(
		"ENCLAVE_NITRIDING_ACME_EMAIL",
		func(val string) { cfg.ACMEEmail = val },
	); err != nil {
		return err
	}
	if err := loadSSMOverride(
		"ENCLAVE_NITRIDING_ACME_CA",
		func(val string) { cfg.ACMECA = val },
	); err != nil {
		return err
	}

	return nil
}

// configureSelfSignedCert generates an ECDSA-P256 leaf cert, records its fingerprint
// in the attestation hashes so clients can pin it against the NSM document
func configureSelfSignedCert(cfg *Config, hashes AttestationHashes) (TLSCertCallback, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate cert key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate cert serial: %w", err)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{certificateOrg}},
		DNSNames:              []string{cfg.FQDN},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privKey.PublicKey,
		privKey,
	)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		return nil, fmt.Errorf("encode certificate to PEM")
	}

	leafFingerprint := func(raw []byte) ([sha256.Size]byte, error) {
		for len(raw) > 0 {
			var block *pem.Block
			block, raw = pem.Decode(raw)
			if block == nil {
				return [sha256.Size]byte{}, fmt.Errorf("pem.Decode found no PEM data")
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return [sha256.Size]byte{}, fmt.Errorf("parse certificate: %w", err)
			}
			if !cert.IsCA {
				return sha256.Sum256(cert.Raw), nil
			}
		}
		return [sha256.Size]byte{}, fmt.Errorf("no non-CA leaf certificate found in TLS chain")
	}

	h, err := leafFingerprint(pemCert)
	if err != nil {
		return nil, err
	}
	hashes.SetTLSKeyHash(h)

	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}

	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		return nil, fmt.Errorf("encode private key to PEM")
	}

	cert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		return nil, fmt.Errorf("load X509 key pair: %w", err)
	}

	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &cert, nil
	}, nil
}

// acmeClientForDirectory builds a custom client for https:// dirs or staging.
// nil uses autocert's default; caPEM sets roots for private/test ACME HTTPS.
func acmeClientForDirectory(directory, caPEM string) (*acme.Client, error) {
	var dirURL string
	switch {
	case directory == "":
		return nil, nil
	case strings.HasPrefix(directory, "https://"):
		dirURL = directory
	case directory == "letsencrypt-staging":
		dirURL = acmeStagingDirectoryURL
	default:
		return nil, fmt.Errorf("unrecognized ACME directory %q", directory)
	}
	client := &acme.Client{DirectoryURL: dirURL}
	if caPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, fmt.Errorf("ENCLAVE_NITRIDING_ACME_CA: no certificates parsed")
		}
		client.HTTPClient = &http.Client{
			Timeout: 90 * time.Second,
			Transport: newACMERoundTripper(&http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			}),
		}
	}
	return client, nil
}

// acmeRoundTripper restores missing Location headers for Pebble finalize-order replies.
type acmeRoundTripper struct {
	base http.RoundTripper
	mu   sync.Mutex
	urls map[string]string // resource ID (trailing path segment) -> resource URL
}

func newACMERoundTripper(base http.RoundTripper) *acmeRoundTripper {
	return &acmeRoundTripper{base: base, urls: make(map[string]string)}
}

func lastPathSegment(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func (rt *acmeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		slog.Warn("ACME http", "method", req.Method, "url", req.URL.String(), "error", err)
		return resp, err
	}

	loc := resp.Header.Get("Location")
	rt.mu.Lock()
	if loc != "" {
		rt.urls[lastPathSegment(loc)] = loc
	} else if known := rt.urls[lastPathSegment(req.URL.Path)]; known != "" {
		resp.Header.Set("Location", known)
		loc = known
	}
	rt.mu.Unlock()

	slog.Info("ACME http",
		"method", req.Method, "url", req.URL.String(), "status", resp.StatusCode, "location", loc)
	return resp, err
}
