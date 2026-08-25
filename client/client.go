// Package client provides a verified HTTP client for AWS Nitro Enclaves.
//
// Every request first verifies the enclave's attestation document (PCR0,
// optional secret PCRs, attestation key binding) and then verifies the
// Schnorr response signature. This ensures the enclave is running the
// expected code and that responses haven't been tampered with.
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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
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

	// SkipKeyBinding still verifies PCR0 and pins the TLS cert, but skips the
	// signing-key binding and Schnorr check.
	SkipKeyBinding bool

	// InsecureSkipCOSEVerify skips COSE Sign1 signature + AWS Nitro root cert
	// chain verification of the attestation document, while keeping PCR0 and
	// TLS-cert-fingerprint pinning intact. Intended for local QEMU integration
	// tests where the emulated NSM doesn't produce an AWS-rooted ECDSA384
	// signature. Never set this against a real production enclave.
	InsecureSkipCOSEVerify bool
}

// Response wraps an HTTP response with attestation verification metadata.
type Response struct {
	StatusCode        int
	Header            http.Header
	Body              []byte
	SignatureVerified bool
}

// AttestationResult contains the verified attestation state.
type AttestationResult struct {
	PCR0           string
	PCRs           map[uint]string
	AttestationKey string // hex-encoded compressed secp256k1 pubkey
	TLSKeyHash     string // hex-encoded SHA-256 of the enclave's TLS leaf cert (from user_data)
	Verified       bool
	VerifiedAt     time.Time
}

// Client is a verified HTTP client for an AWS Nitro Enclave.
type Client struct {
	baseURL         string
	httpClient      *http.Client // pins the live cert to the attested tlsKeyHash
	bootstrapClient *http.Client // unpinned; only for GET /enclave/attestation
	opts            Options

	mu          sync.RWMutex
	cachedState *AttestationResult
	pinHash     string // attested TLS leaf hash; read by httpClient's pin callback
}

// setPinHash records the attested fingerprint the main client pins against.
func (c *Client) setPinHash(h string) {
	c.mu.Lock()
	c.pinHash = h
	c.mu.Unlock()
}

// currentTLSHash is read by the pin callback each handshake; empty until the
// bootstrap attestation is verified, so a pre-pin request fails closed.
func (c *Client) currentTLSHash() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pinHash
}

// New creates a new enclave client that verifies attestation before
// making requests. The baseURL should be the HTTPS endpoint of the
// enclave (e.g. "https://1.2.3.4").
func New(baseURL string, opts Options) (*Client, error) {
	if opts.ExpectedPCR0 == "" {
		return nil, fmt.Errorf("ExpectedPCR0 is required")
	}

	if opts.CacheTTL == 0 {
		opts.CacheTTL = 60 * time.Second
	}
	if opts.StrictTLS && opts.InsecureTLS != nil && *opts.InsecureTLS {
		return nil, fmt.Errorf("StrictTLS and InsecureTLS are mutually exclusive")
	}

	insecure := opts.InsecureTLS != nil && *opts.InsecureTLS

	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		opts:    opts,
	}

	// Bootstrap client: only GET /enclave/attestation (no secrets) runs before
	// the pin. The self-signed cert is accepted; strict mode applies public PKI.
	bootstrapTransport := http.DefaultTransport.(*http.Transport).Clone()
	bootstrapTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: !opts.StrictTLS,
		MinVersion:         tls.VersionTLS12,
	}
	c.bootstrapClient = &http.Client{Timeout: 30 * time.Second, Transport: bootstrapTransport}

	// Main client: pins every connection to the attested tlsKeyHash.
	mainTransport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		mainTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	} else {
		mainTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: !opts.StrictTLS,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				return verifyLeafCertPin(rawCerts, c.currentTLSHash())
			},
			MinVersion: tls.VersionTLS12,
		}
	}
	c.httpClient = &http.Client{Timeout: 30 * time.Second, Transport: mainTransport}

	return c, nil
}

// PinnedHTTPClient returns a client that pins the live leaf cert to tlsKeyHashHex
// (same check as the HTTP/gRPC clients). strict adds public CA/hostname validation.
func PinnedHTTPClient(tlsKeyHashHex string, strict bool) (*http.Client, error) {
	if isAllZeroHex(tlsKeyHashHex) {
		return nil, fmt.Errorf("no TLS cert fingerprint to pin against")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: !strict,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyLeafCertPin(rawCerts, tlsKeyHashHex)
		},
		MinVersion: tls.VersionTLS12,
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}, nil
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

// Do makes a verified HTTP request to the enclave. It:
//  1. Verifies attestation (PCR0, optional PCRs, key binding)
//  2. Executes the request
//  3. Verifies the response signature (Schnorr)
func (c *Client) Do(ctx context.Context, req *http.Request) (*Response, error) {
	// Step 1: Verify attestation (uses cache if valid).
	attestResult, err := c.ensureVerified(ctx)
	if err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}

	// Step 2: Execute the actual request.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Step 3: Verify response signature.
	sigVerified := false
	if attestResult.AttestationKey != "" {
		sigHex := resp.Header.Get("X-Attestation-Signature")
		if sigHex != "" {
			if err := verifySchnorrSignature(
				body,
				sigHex,
				attestResult.AttestationKey,
			); err == nil {
				sigVerified = true
			}
		}
	}

	return &Response{
		StatusCode:        resp.StatusCode,
		Header:            resp.Header,
		Body:              body,
		SignatureVerified: sigVerified,
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

	// 2. Extract the attested tlsKeyHash and activate the pin before any further request.
	tlsKeyHash, err := extractTLSKeyHash(nitResult)
	if err != nil {
		return nil, fmt.Errorf("extract tlsKeyHash: %w", err)
	}
	c.setPinHash(tlsKeyHash)

	// 3. Verify additional PCRs (secret pubkey hashes).
	pcrs := make(map[uint]string)
	for idx, pcrBytes := range nitResult.Document.PCRs {
		if len(pcrBytes) > 0 {
			pcrs[idx] = fmt.Sprintf("%x", pcrBytes)
		}
	}

	for i, expectedHash := range c.opts.ExpectedPCRs {
		pcrIndex := uint(16) + uint(i)
		actual, ok := pcrs[pcrIndex]
		if !ok {
			return nil, fmt.Errorf("PCR%d not found in attestation document", pcrIndex)
		}
		if !strings.EqualFold(actual, expectedHash) {
			return nil, fmt.Errorf(
				"PCR%d mismatch: expected %s, got %s",
				pcrIndex,
				expectedHash,
				actual,
			)
		}
	}

	// 4. Verify the signing-key binding over the pinned client, unless skipped.
	var attestKey string
	if !c.opts.SkipKeyBinding {
		attestKey, err = verifyKeyBinding(ctx, c.httpClient, c.baseURL, nitResult)
		if err != nil {
			return nil, fmt.Errorf("key binding verification: %w", err)
		}
	}

	result := &AttestationResult{
		PCR0:           c.opts.ExpectedPCR0,
		PCRs:           pcrs,
		AttestationKey: attestKey,
		TLSKeyHash:     tlsKeyHash,
		Verified:       true,
		VerifiedAt:     time.Now(),
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

	if m.BaseURL == "" {
		return nil, fmt.Errorf("manifest missing base_url")
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
