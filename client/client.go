// Package client provides a verified HTTP client for AWS Nitro Enclaves.
//
// Every request first verifies the enclave's attestation document (PCR0 and
// optional secret PCRs), then pins the live TLS public key to the attested
// fingerprint. This ensures the expected code terminates the connection.
//
// Usage:
//
//	// Option A: Manual configuration.
//	c, err := client.New("https://1.2.3.4", client.Options{
//	    ExpectedPCR0: "79f5fb125b00ad80...",
//	    ExpectedPCRs: []string{"sha256-of-secret-pubkey"},
//	})
//
//	// Option B: From deployment manifest (GitHub Releases).
//	c, err := client.NewFromManifest(ctx,
//	    client.ManifestURL("myorg/my-app", "latest"),
//	    client.Options{},
//	)
//
//	resp, err := c.Get(ctx, "/my-endpoint")
package client

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ArkLabsHQ/enclave/internal/signing"
)

// Options configures the enclave client.
type Options struct {
	// ExpectedPCR0 is the hex-encoded PCR0 value to verify against.
	// This is the enclave's build measurement — it must match the
	// PCR0 from 'enclave build'.
	ExpectedPCR0 string

	// ExpectedPCRs is a list of hex-encoded SHA256 hashes of secret
	// compressed public keys, in the same order as secrets are defined
	// in enclave.yaml. Index 0 maps to PCR16, index 1 to PCR17, etc.
	// The enclave extends these PCRs with SHA256(compressed_pubkey)
	// at boot time.
	ExpectedPCRs []string

	// CacheTTL controls how long a verified attestation is cached.
	// Set to 0 to verify on every request. Default: 60s.
	CacheTTL time.Duration

	// InsecureTLS, when explicitly true, disables TLS cert pinning (raw,
	// unverified TLS). Default pins to the attested tlsKeyHash.
	InsecureTLS *bool

	// StrictTLS adds public CA + hostname validation on top of the pin (it
	// does not replace it). Mutually exclusive with InsecureTLS.
	StrictTLS bool

	// InsecureSkipCOSEVerify skips COSE Sign1 signature + AWS Nitro root cert
	// chain verification of the attestation document, while keeping PCR0 and
	// TLS-cert-fingerprint pinning intact. Intended for local QEMU integration
	// tests where the emulated NSM doesn't produce an AWS-rooted ECDSA384
	// signature. Never set this against a real production enclave.
	InsecureSkipCOSEVerify bool

	// SignedResponses asks the enclave to sign each response's status and body
	// with its attested response-signing key, bound to this request's method,
	// target, body, and a fresh nonce, and fails any response whose signature
	// is missing or invalid. It is checked on top of the TLS pin; behind a proxy
	// that terminates TLS, also set InsecureTLS.
	SignedResponses bool
}

// Response wraps an HTTP response with attestation verification metadata.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// AttestationResult contains the verified attestation state.
type AttestationResult struct {
	PCR0       string
	PCRs       map[uint]string
	TLSKeyHash string            // hex-encoded SHA-256 of the enclave TLS PublicKey
	SigningKey ed25519.PublicKey // response-signing key; nil if the enclave attests none
	// MigrationCooldown is how long after the attestation the enclave may hand
	// off to MigrationTargetPCR0; zero once it may, or when none is pending.
	MigrationCooldown time.Duration
	// MigrationTargetPCR0 is the hex PCR0 of the image the enclave has a
	// pending intent to migrate to; empty when none is pending.
	MigrationTargetPCR0 string
	// Timestamp is when the NSM produced the attestation document.
	Timestamp  time.Time
	Verified   bool
	VerifiedAt time.Time
}

// Client is a verified HTTP client for an AWS Nitro Enclave.
type Client struct {
	baseURL         string
	httpClient      *http.Client // pins the live cert to the attested tlsKeyHash
	bootstrapClient *http.Client // unpinned; only for GET /enclave/attestation
	opts            Options

	mu          sync.RWMutex
	cachedState *AttestationResult
}

// currentTLSHash is read by the pin callback each handshake. The pin lives in
// cachedState so it cannot disagree with the verify that produced it, and stays
// empty until one passes every check, so a pre-pin request fails closed.
func (c *Client) currentTLSHash() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cachedState == nil {
		return ""
	}
	return c.cachedState.TLSKeyHash
}

// New creates a new enclave client that verifies attestation before
// making requests. The baseURL should be the HTTPS endpoint of the
// enclave (e.g. "https://1.2.3.4").
func New(baseURL string, opts Options) (*Client, error) {
	if opts.ExpectedPCR0 == "" {
		return nil, fmt.Errorf("ExpectedPCR0 is required")
	}
	endpoint, err := requireHTTPSURL(baseURL)
	if err != nil {
		return nil, fmt.Errorf("base URL %w", err)
	}

	if opts.CacheTTL == 0 {
		opts.CacheTTL = 60 * time.Second
	}
	if opts.StrictTLS && opts.InsecureTLS != nil && *opts.InsecureTLS {
		return nil, fmt.Errorf("StrictTLS and InsecureTLS are mutually exclusive")
	}

	insecure := opts.InsecureTLS != nil && *opts.InsecureTLS

	c := &Client{
		baseURL: endpoint,
		opts:    opts,
	}

	// Bootstrap client: only GET /enclave/attestation (no secrets) runs before
	// the pin. The self-signed cert is accepted; strict mode applies public PKI.
	bootstrapTransport := http.DefaultTransport.(*http.Transport).Clone()
	bootstrapTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: !opts.StrictTLS,
		MinVersion:         tls.VersionTLS12,
	}
	c.bootstrapClient = &http.Client{
		Timeout:   30 * time.Second,
		Transport: httpsTransport{bootstrapTransport},
	}

	// Main client: pins every connection to the attested tlsKeyHash.
	mainTransport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		mainTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	} else {
		mainTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: !opts.StrictTLS,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				return verifyLeafKeyHash(rawCerts, c.currentTLSHash())
			},
			MinVersion: tls.VersionTLS12,
		}
	}
	c.httpClient = &http.Client{
		Timeout:   30 * time.Second,
		Transport: httpsTransport{mainTransport},
	}
	if opts.SignedResponses {
		// Don't follow redirects: signature verification uses the original request.
		// Verify and return the redirect response so the caller can handle it.
		c.httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return c, nil
}

// requireHTTPSURL returns rawURL without its trailing slash, rejecting anything
// that is not an absolute https URL with a host: the pin is only consulted
// during a TLS handshake, so a plaintext endpoint bypasses it entirely.
func requireHTTPSURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", fmt.Errorf(
			"must be an absolute https:// URL with a host, got %q", rawURL,
		)
	}
	return strings.TrimRight(rawURL, "/"), nil
}

// httpsTransport refuses a plaintext hop before anything is written, covering
// the first request and every redirect. Embedding keeps CloseIdleConnections
// promoted. Closing the body is the RoundTripper contract ("RoundTrip must
// always close the body, including on errors"), which http.Client.do relies on;
// doing it here keeps the public Do from closing a body the caller owns.
type httpsTransport struct{ *http.Transport }

func (t httpsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL != nil && req.URL.Scheme == "https" {
		return t.Transport.RoundTrip(req)
	}
	if req.Body != nil {
		_ = req.Body.Close()
	}
	return nil, fmt.Errorf("request URL must use https")
}

// PinnedHTTPClient returns a client that pins the live certificate's PublicKey
// to tlsKeyHashHex and rejects plaintext requests and redirects. strict adds
// public CA and hostname validation.
func PinnedHTTPClient(tlsKeyHashHex string, strict bool) (*http.Client, error) {
	if isAllZeroHex(tlsKeyHashHex) {
		return nil, fmt.Errorf("no TLS public-key fingerprint to pin against")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: !strict,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyLeafKeyHash(rawCerts, tlsKeyHashHex)
		},
		MinVersion: tls.VersionTLS12,
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: httpsTransport{transport}}, nil
}

// Get makes a verified GET request to the enclave.
func (c *Client) Get(ctx context.Context, path string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(path), nil)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, req)
}

// Post makes a verified POST request to the enclave.
func (c *Client) Post(ctx context.Context, path string, body io.Reader) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(path), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.Do(ctx, req)
}

// Do verifies attestation and activates the attested TLS pin before executing
// the request over the pinned connection. With SignedResponses it also
// verifies the response signature.
func (c *Client) Do(ctx context.Context, req *http.Request) (*Response, error) {
	attest, err := c.ensureVerified(ctx)
	if err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}

	var nonce, reqBody []byte
	if c.opts.SignedResponses {
		if attest.SigningKey == nil {
			return nil, fmt.Errorf("enclave attests no response signing key")
		}
		nonce = make([]byte, signing.NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generate nonce: %w", err)
		}
		// Sign a copy so the caller's headers stay unchanged; the body is still
		// consumed, as by any Do.
		req = req.Clone(req.Context())
		// Clone keeps a nil header map, which Set below would panic on.
		if req.Header == nil {
			req.Header = http.Header{}
		}
		// The request body is signed too: keep a copy to hash.
		if req.Body != nil {
			if reqBody, err = io.ReadAll(req.Body); err != nil {
				return nil, fmt.Errorf("read request body: %w", err)
			}
			_ = req.Body.Close()
			req.Body = io.NopCloser(bytes.NewReader(reqBody))
		}
		// Let the transport ask for gzip and decode it, so the body we hash is the
		// decoded one the runtime signed, even if a proxy compresses it.
		req.Header.Del("Accept-Encoding")
		req.Header.Set(signNonceHeader, hex.EncodeToString(nonce))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if c.opts.SignedResponses {
		msg := signing.ResponseMessage(
			cmp.Or(req.Method, http.MethodGet), signing.RequestTarget(req), nonce, reqBody,
			resp.StatusCode, body,
		)
		if err := verifyResponseSignature(attest.SigningKey, msg, resp.Header); err != nil {
			// The key may have changed (a fresh genesis, or the other generation
			// during a migration): attest again on the next call.
			c.mu.Lock()
			if c.cachedState == attest {
				c.cachedState = nil
			}
			c.mu.Unlock()
			// The status is unauthenticated; it only says what answered.
			return nil, fmt.Errorf("response signature (HTTP %d) for nonce %s: %w",
				resp.StatusCode, req.Header.Get(signNonceHeader), err)
		}
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
	}, nil
}

// VerifyAttestation manually triggers attestation verification,
// bypassing the cache. Returns the attestation result.
func (c *Client) VerifyAttestation(ctx context.Context) (*AttestationResult, error) {
	return c.verify(ctx)
}

// ensureVerified returns cached attestation or re-verifies.
func (c *Client) ensureVerified(ctx context.Context) (*AttestationResult, error) {
	c.mu.RLock()
	cached := c.cachedState
	c.mu.RUnlock()

	if cached != nil && cached.Verified && time.Since(cached.VerifiedAt) < c.opts.CacheTTL {
		return cached, nil
	}

	return c.verify(ctx)
}

// verify performs full attestation verification and caches the result.
func (c *Client) verify(ctx context.Context) (*AttestationResult, error) {
	// 1. Bootstrap over the unpinned client (carries no secrets).
	nitResult, err := fetchAndVerifyAttestation(
		ctx,
		c.bootstrapClient,
		c.baseURL,
		c.opts.ExpectedPCR0,
		c.opts.InsecureSkipCOSEVerify,
	)
	if err != nil {
		return nil, err
	}

	// 2. Extract the attested tlsKeyHash. It is published with cachedState at the
	// end, so a failure below leaves the last good pin in place.
	userData, err := parseUserData(nitResult)
	if err != nil {
		return nil, fmt.Errorf("parse user_data: %w", err)
	}

	// 3. Verify additional PCRs (secret pubkey hashes).
	pcrs, err := verifyPCRs(nitResult.Document.PCRs, c.opts.ExpectedPCRs)
	if err != nil {
		return nil, err
	}

	result := &AttestationResult{
		PCR0:                c.opts.ExpectedPCR0,
		PCRs:                pcrs,
		TLSKeyHash:          userData.tlsKeyHash,
		SigningKey:          userData.signingKey,
		MigrationCooldown:   userData.migrationCooldown,
		MigrationTargetPCR0: userData.migrationTargetPCR0,
		Timestamp:           time.UnixMilli(int64(nitResult.Document.Timestamp)),
		Verified:            true,
		VerifiedAt:          time.Now(),
	}

	c.mu.Lock()
	c.cachedState = result
	c.mu.Unlock()

	return result, nil
}

func (c *Client) url(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.baseURL + path
}

// Manifest is the deployment metadata published by the deploy GitHub Actions
// workflow as a GitHub Release asset (deployment.json).
type Manifest struct {
	BaseURL   string `json:"base_url"`
	PCR0      string `json:"pcr0"`
	PCR1      string `json:"pcr1"`
	PCR2      string `json:"pcr2"`
	Timestamp string `json:"timestamp"`
	Commit    string `json:"commit"`
}

// ManifestURL returns the GitHub Releases URL for a repo's deployment manifest.
// Use tag "latest" for the current deployment, or a specific deploy tag.
//
//	client.ManifestURL("myorg/my-app", "latest")
//	// => "https://github.com/myorg/my-app/releases/download/latest/deployment.json"
func ManifestURL(repo, tag string) string {
	return "https://github.com/" + repo + "/releases/download/" + tag + "/deployment.json"
}

// FetchManifest fetches and parses a deployment manifest from the given URL.
// Use ManifestURL to construct the URL from a GitHub repo and tag:
//
//	m, err := client.FetchManifest(ctx, client.ManifestURL("myorg/my-app", "latest"))
func FetchManifest(ctx context.Context, manifestURL string) (*Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf(
			"manifest status %d: %s",
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}

	if _, err := requireHTTPSURL(m.BaseURL); err != nil {
		return nil, fmt.Errorf("manifest base_url %w", err)
	}
	if m.PCR0 == "" {
		return nil, fmt.Errorf("manifest missing pcr0")
	}

	return &m, nil
}

// NewFromManifest creates a client by fetching deployment metadata from a URL.
// The manifest provides the enclave's base URL and PCR0, so callers only need
// to know the manifest endpoint. Additional options (ExpectedPCRs, CacheTTL)
// can be set to augment verification.
func NewFromManifest(ctx context.Context, manifestURL string, opts Options) (*Client, error) {
	m, err := FetchManifest(ctx, manifestURL)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}

	if opts.ExpectedPCR0 != "" && !strings.EqualFold(opts.ExpectedPCR0, m.PCR0) {
		return nil, fmt.Errorf(
			"manifest PCR0 %s does not match expected %s",
			m.PCR0,
			opts.ExpectedPCR0,
		)
	}
	opts.ExpectedPCR0 = m.PCR0

	return New(m.BaseURL, opts)
}
