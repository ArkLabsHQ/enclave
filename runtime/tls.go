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
	"encoding/hex"
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
	"golang.org/x/crypto/acme/autocert"
)

const (
	acmeCertCacheDir = "cert-cache"
	// acmeStagingDirectoryURL is Let's Encrypt's staging ACME endpoint — an
	// untrusted root with high rate limits, used for testing.
	acmeStagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	certificateOrg          = "AWS Nitro enclave application"
	certificateValidity     = time.Hour * 24 * 356
)

type TLSCertCallback func(*tls.ClientHelloInfo) (*tls.Certificate, error)

// withDefaultSNI fills a missing server name so IP/loopback probes reach the
// same cert source as named clients. autocert rejects an empty ServerName.
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

// ConfigureTLS selects one of three certificate sources:
//
//   - self-signed, when ACME is off;
//   - DNS-01 with a fleet-shared certificate, when a Route53 zone is configured.
//     This is the only mode that survives a load balancer, because tls-alpn-01
//     needs the CA's connection to reach the specific enclave holding the
//     challenge;
//   - tls-alpn-01 via autocert otherwise - the single-instance path, retained
//     unchanged for deployments addressed directly by IP.
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

	if !nitriding.InEnclave() {
		return configureACME(cfg, autocert.DirCache(acmeCertCacheDir), hashes)
	}

	zoneID, err := ssm.MayGet(ctx, route53ZoneIDParam())
	if err != nil {
		return nil, fmt.Errorf("failed to read Route53 zone ID: %w", err)
	}
	if zoneID != "" {
		return configureSharedDNS01Cert(ctx, cfg, s3, dek, ssm, r53, zoneID, hashes)
	}

	slog.Info("no Route53 zone configured, using tls-alpn-01 (single instance only)")
	acmeCache, err := NewAcmeStorageCache(ctx, s3, dek, ssm)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME cache: %w", err)
	}
	return configureACME(cfg, acmeCache, hashes)
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

func configureACME(
	cfg *Config,
	cache autocert.Cache,
	hashes AttestationHashes,
) (TLSCertCallback, error) {
	client, err := acmeClientForDirectory(cfg.ACMEDirectory, cfg.ACMECA)
	if err != nil {
		return nil, err
	}

	mgr := autocert.Manager{
		Cache:      cache,
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.FQDN),
		Email:      cfg.ACMEEmail,
		Client:     client,
	}

	// Hash live ACME leaf; autocert may rotate it.
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := mgr.GetCertificate(hello)
		if err == nil && cert != nil && len(cert.Certificate) > 0 {
			h := sha256.Sum256(cert.Certificate[0])
			if hashes.SetTLSKeyHashIfChanged(h) {
				slog.Info("TLS: bound attestation to ACME cert", "sha256", hex.EncodeToString(h[:]))
			}
		}
		return cert, err
	}, nil
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
