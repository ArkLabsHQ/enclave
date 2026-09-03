package runtime

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

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
	tlsKey crypto.Signer,
	hashes *AttestationHashes,
) (TLSCertCallback, error) {
	if err := loadTLSConfigOverridesFromSSM(ctx, ssm, cfg); err != nil {
		return nil, fmt.Errorf("failed to load TLS SSM overrides: %w", err)
	}

	if !cfg.UseACME {
		return configureSelfSigned(ctx, cfg, s3, dek, ssm, tlsKey, hashes)
	}

	zoneID, err := ssm.MayGet(ctx, cfg.route53ZoneIDParam())
	if err != nil {
		return nil, fmt.Errorf("failed to read Route53 zone ID: %w", err)
	}
	if zoneID == "" {
		// Fail rather than quietly serve self-signed: an operator who asked for
		// ACME and silently got an untrusted certificate finds out from clients.
		return nil, fmt.Errorf(
			"ACME is enabled but %s is unset; DNS-01 is the only supported challenge "+
				"and needs a Route53 hosted zone", cfg.route53ZoneIDParam(),
		)
	}
	return configureDNS01Cert(ctx, cfg, s3, dek, ssm, r53, zoneID, tlsKey, hashes)
}

func configureDNS01Cert(
	ctx context.Context,
	cfg *Config,
	s3 S3API,
	dek DEK,
	ssm SSM,
	r53 Route53API,
	zoneID string,
	tlsKey crypto.Signer,
	hashes *AttestationHashes,
) (TLSCertCallback, error) {
	certBucket, err := ssm.MustGet(ctx, cfg.certBucketParam())
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate bucket name: %w", err)
	}
	leaseBucket, err := ssm.MustGet(ctx, cfg.leaseBucketParam())
	if err != nil {
		return nil, fmt.Errorf("failed to read lease bucket name: %w", err)
	}

	store := newCertStore(cfg, s3, dek, tlsKey, certBucket, cfg.FQDN)

	accountKey, err := store.LoadOrCreateAccountKey(ctx)
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

	issuer, err := newACMEIssuer(client, r53, zoneID, cfg.ACMEEmail)
	if err != nil {
		return nil, err
	}

	manager, err := newCertManager(
		ctx, cfg, store, issuer,
		s3, leaseBucket, cfg.FQDN, tlsKey, hashes,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to establish shared certificate: %w", err)
	}
	go manager.Run(ctx)

	slog.Info("serving fleet-shared certificate via DNS-01", "fqdn", cfg.FQDN, "zone", zoneID)
	return manager.GetCertificate, nil
}

func loadTLSConfigOverridesFromSSM(ctx context.Context, ssm SSM, cfg *Config) error {
	loadSSMOverride := func(name string, updateCfg func(val string)) error {
		val, err := ssm.MayGet(ctx, cfg.envVarOverridePath(name))
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

// configureSelfSigned shares one self-signed certificate across the fleet, so a
// client that pinned the leaf from any enclave reaches every other one.
func configureSelfSigned(
	ctx context.Context,
	cfg *Config,
	s3 S3API,
	dek DEK,
	ssm SSM,
	tlsKey crypto.Signer,
	hashes *AttestationHashes,
) (TLSCertCallback, error) {
	certBucket, err := ssm.MayGet(ctx, cfg.certBucketParam())
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate bucket name: %w", err)
	}
	leaseBucket, err := ssm.MayGet(ctx, cfg.leaseBucketParam())
	if err != nil {
		return nil, fmt.Errorf("failed to read lease bucket name: %w", err)
	}
	if certBucket == "" || leaseBucket == "" {
		return nil, fmt.Errorf(
			"the shared certificate store needs both %s and %s",
			cfg.certBucketParam(), cfg.leaseBucketParam(),
		)
	}

	store := newSelfSignedCertStore(cfg, s3, dek, tlsKey, certBucket, cfg.FQDN)
	manager, err := newCertManager(
		ctx, cfg, store, selfSignedIssuer{},
		s3, leaseBucket, cfg.FQDN, tlsKey, hashes,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to establish shared certificate: %w", err)
	}
	go manager.Run(ctx)

	slog.Info("serving fleet-shared self-signed certificate", "fqdn", cfg.FQDN)
	return manager.GetCertificate, nil
}

// selfSignedIssuer mints the certificate itself, for deployments with no public
// CA. It satisfies certIssuer, so the shared store, the issuance lease and
// renewal all behave exactly as they do for ACME.
type selfSignedIssuer struct{}

func (selfSignedIssuer) Issue(
	_ context.Context,
	domain string,
	key crypto.Signer,
) (certPEM []byte, err error) {
	if key == nil {
		return nil, fmt.Errorf("certificate key is required")
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate cert serial: %w", err)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{certificateOrg}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	// An endpoint addressed by IP needs the SAN to match, or nothing that checks
	// the name — including our own store — will accept the certificate.
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{domain}
	}
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		key.Public(),
		key,
	)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		return nil, fmt.Errorf("encode certificate to PEM")
	}
	return pemCert, nil
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
