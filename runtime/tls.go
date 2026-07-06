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

	"github.com/ArkLabsHQ/introspector-enclave/runtime/nitriding"
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

func ConfigureTLS(
	ctx context.Context,
	cfg *Config,
	s3 S3API,
	dek DEK,
	ssm SSM,
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
	acmeCache, err := NewAcmeStorageCache(ctx, s3, dek, ssm)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME cache: %w", err)
	}
	return configureACME(cfg, acmeCache, hashes)
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

	if err := loadSSMOverride("ENCLAVE_NITRIDING_FQDN", func(val string) { cfg.FQDN = val }); err != nil {
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
	if err := loadSSMOverride("ENCLAVE_NITRIDING_ACME_EMAIL", func(val string) { cfg.ACMEEmail = val }); err != nil {
		return err
	}
	if err := loadSSMOverride("ENCLAVE_NITRIDING_ACME_CA", func(val string) { cfg.ACMECA = val }); err != nil {
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
	case strings.HasPrefix(directory, "https://"):
		dirURL = directory
	case directory == "letsencrypt-staging":
		dirURL = acmeStagingDirectoryURL
	default:
		return nil, nil
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
