package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
	"github.com/stretchr/testify/require"
)

// TestPinnedHTTPClient drives a real TLS handshake: a matching fingerprint
// reaches the handler; a mismatch fails closed before the request is sent.
func TestPinnedHTTPClient(t *testing.T) {
	var reached bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	goodHash := hex.EncodeToString(sum[:])

	// Match → handler runs.
	c, err := PinnedHTTPClient(goodHash, false)
	require.NoError(t, err)
	resp, err := c.Get(srv.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.True(t, reached)

	// Mismatch → fail closed, handler NOT reached.
	reached = false
	bad, err := PinnedHTTPClient(strings.Repeat("cd", 32), false)
	require.NoError(t, err)
	_, err = bad.Get(srv.URL)
	require.ErrorContains(t, err, "TLS public-key fingerprint mismatch")
	require.False(t, reached, "handler must not run when the pin fails")
}

// fakeEnclave serves a COSE-skip attestation whose user_data carries attestedTLS,
// and records every non-attestation path it receives.
type fakeEnclave struct {
	pcr0Hex     string
	pcr16Hex    string
	attestedTLS [32]byte // tlsKeyHash embedded in user_data
	mu          sync.Mutex
	appPaths    []string
}

func (f *fakeEnclave) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/enclave/attestation" {
			nonceHex := r.URL.Query().Get("nonce")
			nonce, _ := hex.DecodeString(nonceHex)
			pcr0, _ := hex.DecodeString(f.pcr0Hex)
			ud := append([]byte("sha256:"), f.attestedTLS[:]...)
			pcrs := map[uint][]byte{0: pcr0}
			if f.pcr16Hex != "" {
				pcrs[16], _ = hex.DecodeString(f.pcr16Hex)
			}
			_, _ = w.Write([]byte(buildInsecureCOSEDoc(nitrite.Document{
				PCRs:     pcrs,
				Nonce:    nonce,
				UserData: ud,
			})))
			return
		}
		f.appPaths = append(f.appPaths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"test","previous_pcr0":"genesis"}`))
	})
}

func buildInsecureCOSEDoc(doc nitrite.Document) string {
	payload, _ := cbor.Marshal(&doc)
	env := struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected cbor.RawMessage
		Payload     []byte
		Signature   []byte
	}{Protected: []byte{}, Unprotected: cbor.RawMessage{0xa0}, Payload: payload, Signature: []byte{}}
	out, _ := cbor.Marshal(&env)
	return base64.StdEncoding.EncodeToString(out)
}

// TestClientBootstrapPinSequencing is the headline #129 test: the live cert is
// pinned to the attested tlsKeyHash, and a mismatch blocks every app request.
func TestClientBootstrapPinSequencing(t *testing.T) {
	pcr0 := strings.Repeat("ab", 48)

	t.Run("match → app request allowed", func(t *testing.T) {
		fe := &fakeEnclave{pcr0Hex: pcr0}
		srv := httptest.NewTLSServer(fe.handler())
		defer srv.Close()
		fe.attestedTLS = sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)

		c, err := New(
			srv.URL,
			Options{ExpectedPCR0: pcr0, InsecureSkipCOSEVerify: true},
		)
		require.NoError(t, err)
		resp, err := c.Get(context.Background(), "/enclave/v1/info")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		fe.mu.Lock()
		defer fe.mu.Unlock()
		require.Equal(t, []string{"/enclave/v1/info"}, fe.appPaths)
	})

	t.Run("mismatch → fail closed, no app request sent", func(t *testing.T) {
		fe := &fakeEnclave{pcr0Hex: pcr0}
		srv := httptest.NewTLSServer(fe.handler())
		defer srv.Close()
		// Attest a DIFFERENT cert than the one the server actually serves.
		for i := range fe.attestedTLS {
			fe.attestedTLS[i] = 0xCD
		}

		c, err := New(
			srv.URL,
			Options{ExpectedPCR0: pcr0, InsecureSkipCOSEVerify: true},
		)
		require.NoError(t, err)
		_, err = c.Get(context.Background(), "/enclave/v1/info")
		require.ErrorContains(t, err, "TLS public-key fingerprint mismatch")
		fe.mu.Lock()
		defer fe.mu.Unlock()
		require.Empty(t, fe.appPaths, "no app request must be sent on a pin mismatch")
	})
}

func TestClientTrustOptions(t *testing.T) {
	cases := []struct {
		name        string
		baseURL     string
		expectedTLS string
		insecureTLS bool
		wantErr     string
	}{
		{name: "HTTPS", baseURL: "https://example.com"},
		{name: "HTTP", baseURL: "http://example.com", wantErr: "absolute HTTPS URL"},
		{
			name:        "HTTP with insecure TLS",
			baseURL:     "http://example.com",
			insecureTLS: true,
			wantErr:     "absolute HTTPS URL",
		},
		{name: "missing scheme", baseURL: "example.com", wantErr: "absolute HTTPS URL"},
		{name: "missing host", baseURL: "https:///path", wantErr: "absolute HTTPS URL"},
		{name: "empty authority", baseURL: "https://", wantErr: "absolute HTTPS URL"},
		{name: "malformed URL", baseURL: "://", wantErr: "absolute HTTPS URL"},
		{
			name:        "short fingerprint",
			baseURL:     "https://example.com",
			expectedTLS: "bad",
			wantErr:     "ExpectedTLSKeyHash",
		},
		{
			name:        "non-hex fingerprint",
			baseURL:     "https://example.com",
			expectedTLS: strings.Repeat("gg", 32),
			wantErr:     "ExpectedTLSKeyHash",
		},
		{
			name:        "zero fingerprint",
			baseURL:     "https://example.com",
			expectedTLS: strings.Repeat("00", 32),
			wantErr:     "ExpectedTLSKeyHash",
		},
		{
			name:        "valid fingerprint",
			baseURL:     "https://example.com",
			expectedTLS: strings.Repeat("ab", 32),
		},
		{
			name:        "fingerprint with insecure TLS",
			baseURL:     "https://example.com",
			expectedTLS: strings.Repeat("ab", 32),
			insecureTLS: true,
			wantErr:     "mutually exclusive",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.baseURL, Options{
				ExpectedPCR0:       "ab",
				ExpectedTLSKeyHash: tc.expectedTLS,
				InsecureTLS:        &tc.insecureTLS,
			})
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestPinnedHTTPClientTrustOptions(t *testing.T) {
	cases := []struct {
		name    string
		hash    string
		wantErr string
	}{
		{name: "empty fingerprint", hash: "", wantErr: "64 hex characters"},
		{name: "short fingerprint", hash: "bad", wantErr: "64 hex characters"},
		{name: "non-hex fingerprint", hash: strings.Repeat("gg", 32), wantErr: "64 hex characters"},
		{name: "zero fingerprint", hash: strings.Repeat("00", 32), wantErr: "64 hex characters"},
		{name: "valid fingerprint", hash: strings.Repeat("ab", 32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PinnedHTTPClient(tc.hash, false)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestClientRetainsTLSIdentity(t *testing.T) {
	pcr0, pcr16 := strings.Repeat("ab", 48), strings.Repeat("cd", 32)
	fe := &fakeEnclave{pcr0Hex: pcr0}
	srv := httptest.NewTLSServer(fe.handler())
	defer srv.Close()
	goodHash := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	otherHash := sha256.Sum256([]byte("another deployment"))
	goodHex := hex.EncodeToString(goodHash[:])

	cases := []struct {
		name               string
		expectedTLS        string
		previouslyVerified bool
		attestedTLS        [32]byte
		pcr16              string
		wantErr            string
	}{
		{name: "first use accepts key", attestedTLS: goodHash, pcr16: pcr16},
		{
			name:        "first use rejects missing PCR",
			attestedTLS: goodHash,
			pcr16:       "",
			wantErr:     "PCR16 not found",
		},
		{
			name:        "supplied fingerprint matches case-insensitively",
			expectedTLS: strings.ToUpper(goodHex),
			attestedTLS: goodHash,
			pcr16:       pcr16,
		},
		{
			name:        "supplied fingerprint rejects different key",
			expectedTLS: goodHex,
			attestedTLS: otherHash,
			pcr16:       pcr16,
			wantErr:     "TLS public-key fingerprint mismatch",
		},
		{
			name:        "supplied fingerprint rejects missing PCR",
			expectedTLS: goodHex,
			attestedTLS: goodHash,
			pcr16:       "",
			wantErr:     "PCR16 not found",
		},
		{
			name:               "first-use key survives refresh",
			previouslyVerified: true,
			attestedTLS:        goodHash,
			pcr16:              pcr16,
		},
		{
			name:               "supplied key survives refresh",
			expectedTLS:        goodHex,
			previouslyVerified: true,
			attestedTLS:        goodHash,
			pcr16:              pcr16,
		},
		{
			name:               "refresh rejects different first-use key",
			previouslyVerified: true,
			attestedTLS:        otherHash,
			pcr16:              pcr16,
			wantErr:            "TLS public-key fingerprint mismatch",
		},
		{
			name:               "refresh rejects different supplied key",
			expectedTLS:        goodHex,
			previouslyVerified: true,
			attestedTLS:        otherHash,
			pcr16:              pcr16,
			wantErr:            "TLS public-key fingerprint mismatch",
		},
		{
			name:               "refresh rejects wrong PCR with same key",
			previouslyVerified: true,
			attestedTLS:        goodHash,
			pcr16:              strings.Repeat("ef", 32),
			wantErr:            "PCR16 mismatch",
		},
		{
			name:               "refresh rejects wrong PCR with different key",
			previouslyVerified: true,
			attestedTLS:        otherHash,
			pcr16:              strings.Repeat("ef", 32),
			wantErr:            "PCR16 mismatch",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fe.mu.Lock()
			fe.attestedTLS, fe.pcr16Hex, fe.appPaths = goodHash, pcr16, nil
			fe.mu.Unlock()
			c, err := New(srv.URL, Options{
				ExpectedPCR0:           pcr0,
				ExpectedPCRs:           []string{pcr16},
				ExpectedTLSKeyHash:     tc.expectedTLS,
				InsecureSkipCOSEVerify: true,
				CacheTTL:               -1,
			})
			require.NoError(t, err)
			defer c.httpClient.CloseIdleConnections()
			defer c.bootstrapClient.CloseIdleConnections()
			if tc.previouslyVerified {
				_, err = c.VerifyAttestation(context.Background())
				require.NoError(t, err)
			}
			previous, previousHash := c.cachedState, c.currentTLSHash()

			fe.mu.Lock()
			fe.attestedTLS, fe.pcr16Hex = tc.attestedTLS, tc.pcr16
			fe.mu.Unlock()
			_, err = c.Get(context.Background(), "/application")
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.True(t, previous == c.cachedState)
				require.Equal(t, previousHash, c.currentTLSHash())
				fe.mu.Lock()
				defer fe.mu.Unlock()
				require.Empty(
					t,
					fe.appPaths,
					"failed verification must not send application traffic",
				)
				return
			}
			require.NoError(t, err)
			require.Equal(t, goodHex, c.currentTLSHash())
			require.Equal(t, goodHex, c.cachedState.TLSKeyHash)
			require.Equal(t, pcr16, c.cachedState.PCRs[16])
			fe.mu.Lock()
			defer fe.mu.Unlock()
			require.Equal(t, []string{"/application"}, fe.appPaths)
		})
	}
}

func TestClientVerificationStateIsCallerIndependent(t *testing.T) {
	fe := &fakeEnclave{pcr0Hex: strings.Repeat("ab", 48), pcr16Hex: strings.Repeat("cd", 32)}
	srv := httptest.NewTLSServer(fe.handler())
	defer srv.Close()
	fe.attestedTLS = sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	opts := Options{
		ExpectedPCR0: fe.pcr0Hex, ExpectedPCRs: []string{fe.pcr16Hex},
		InsecureSkipCOSEVerify: true, CacheTTL: -1,
	}
	c, err := New(srv.URL, opts)
	require.NoError(t, err)
	defer c.httpClient.CloseIdleConnections()
	defer c.bootstrapClient.CloseIdleConnections()
	result, err := c.VerifyAttestation(context.Background())
	require.NoError(t, err)
	result.TLSKeyHash = "changed by caller"
	result.PCRs[16] = "changed by caller"
	opts.ExpectedPCRs[0] = "changed by caller"
	require.Equal(t, fe.pcr16Hex, c.cachedState.PCRs[16])
	require.Equal(t, hex.EncodeToString(fe.attestedTLS[:]), c.currentTLSHash())
	_, err = c.Get(context.Background(), "/refresh")
	require.NoError(t, err)
}

func TestClientPersistsIdentityAcrossSuccessorPCR0(t *testing.T) {
	fe := &fakeEnclave{pcr0Hex: strings.Repeat("ab", 48)}
	srv := httptest.NewTLSServer(fe.handler())
	defer srv.Close()
	fe.attestedTLS = sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	c, err := New(srv.URL, Options{ExpectedPCR0: fe.pcr0Hex, InsecureSkipCOSEVerify: true})
	require.NoError(t, err)
	defer c.bootstrapClient.CloseIdleConnections()
	previous, err := c.VerifyAttestation(context.Background())
	require.NoError(t, err)

	successorPCR0 := strings.Repeat("ef", 48)
	fe.mu.Lock()
	fe.pcr0Hex = successorPCR0
	fe.mu.Unlock()
	successor, err := New(srv.URL, Options{
		ExpectedPCR0: successorPCR0, ExpectedTLSKeyHash: previous.TLSKeyHash,
		InsecureSkipCOSEVerify: true,
	})
	require.NoError(t, err)
	defer successor.bootstrapClient.CloseIdleConnections()
	result, err := successor.VerifyAttestation(context.Background())
	require.NoError(t, err)
	require.Equal(t, successorPCR0, result.PCR0)
	require.Equal(t, previous.TLSKeyHash, result.TLSKeyHash)
}

func TestHTTPSOnly(t *testing.T) {
	clients := []struct {
		name        string
		pinnedOnly  bool
		insecureTLS bool
	}{
		{name: "verified", pinnedOnly: false, insecureTLS: false},
		{name: "pinned", pinnedOnly: true, insecureTLS: false},
		{name: "insecure TLS", pinnedOnly: false, insecureTLS: true},
	}
	requests := []struct {
		name                     string
		redirectStatus           int
		wantVerifiedAttestations int32
	}{
		{"direct HTTP", 0, 0},
		{"301 downgrade", http.StatusMovedPermanently, 1},
		{"302 downgrade", http.StatusFound, 1},
		{"303 downgrade", http.StatusSeeOther, 1},
		{"307 body replay", http.StatusTemporaryRedirect, 1},
		{"308 body replay", http.StatusPermanentRedirect, 1},
	}
	for _, mode := range clients {
		t.Run(mode.name, func(t *testing.T) {
			for _, tc := range requests {
				t.Run(tc.name, func(t *testing.T) {
					var plaintextRequests, attestations atomic.Int32
					plaintext := httptest.NewServer(
						http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
							plaintextRequests.Add(1)
							w.WriteHeader(http.StatusOK)
						}),
					)
					defer plaintext.Close()
					fe := &fakeEnclave{pcr0Hex: strings.Repeat("ab", 48)}
					handler := fe.handler()
					srv := httptest.NewTLSServer(
						http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							if r.URL.Path == "/redirect" {
								http.Redirect(w, r, plaintext.URL, tc.redirectStatus)
								return
							}
							if r.URL.Path == "/enclave/attestation" {
								attestations.Add(1)
							}
							handler.ServeHTTP(w, r)
						}),
					)
					defer srv.Close()
					fe.attestedTLS = sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
					var do func(*http.Request) error
					if mode.pinnedOnly {
						c, err := PinnedHTTPClient(hex.EncodeToString(fe.attestedTLS[:]), false)
						require.NoError(t, err)
						defer c.CloseIdleConnections()
						do = func(req *http.Request) error {
							resp, err := c.Do(req)
							if resp != nil {
								_ = resp.Body.Close()
							}
							return err
						}
					} else {
						c, err := New(srv.URL, Options{
							ExpectedPCR0:           fe.pcr0Hex,
							InsecureSkipCOSEVerify: true,
							InsecureTLS:            &mode.insecureTLS,
						})
						require.NoError(t, err)
						defer c.httpClient.CloseIdleConnections()
						defer c.bootstrapClient.CloseIdleConnections()
						do = func(req *http.Request) error {
							_, err := c.Do(req.Context(), req)
							return err
						}
					}
					target := plaintext.URL
					if tc.redirectStatus != 0 {
						target = srv.URL + "/redirect"
					}
					req, err := http.NewRequest(
						http.MethodPost,
						target,
						strings.NewReader("secret body"),
					)
					require.NoError(t, err)
					req.Header.Set("Authorization", "Bearer secret")
					req.Header.Set("X-Application-Secret", "secret header")
					require.ErrorContains(t, do(req), "must use HTTPS")
					require.Zero(t, plaintextRequests.Load(), "no headers or bodies may reach HTTP")
					if mode.pinnedOnly {
						require.Zero(t, attestations.Load())
					} else {
						require.Equal(t, tc.wantVerifiedAttestations, attestations.Load())
					}
				})
			}
		})
	}
}

func TestConcurrentVerificationRetainsFirstCommit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fe := &fakeEnclave{pcr0Hex: strings.Repeat("ab", 48)}
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var calls atomic.Int32
	handler := fe.handler()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/enclave/attestation" && calls.Add(1) == 1 {
			close(firstStarted)
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return
			}
			// This attempt started first, but loses the commit race with a different key.
			other := &fakeEnclave{pcr0Hex: fe.pcr0Hex, attestedTLS: sha256.Sum256([]byte("other"))}
			other.handler().ServeHTTP(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer srv.Close()
	fe.attestedTLS = sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	c, err := New(srv.URL, Options{ExpectedPCR0: fe.pcr0Hex, InsecureSkipCOSEVerify: true})
	require.NoError(t, err)
	defer c.httpClient.CloseIdleConnections()
	defer c.bootstrapClient.CloseIdleConnections()
	firstDone := make(chan error, 1)
	go func() {
		_, err := c.VerifyAttestation(ctx)
		firstDone <- err
	}()
	select {
	case <-firstStarted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	accepted, err := c.VerifyAttestation(ctx)
	require.NoError(t, err)
	close(releaseFirst)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			result, err := c.VerifyAttestation(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			if result.TLSKeyHash != accepted.TLSKeyHash ||
				c.currentTLSHash() != accepted.TLSKeyHash {
				t.Error("verification changed the retained identity")
			}
			if _, err := c.Get(ctx, "/concurrent"); err != nil {
				t.Error(err)
			}
		})
	}
	require.ErrorContains(t, <-firstDone, "TLS public-key fingerprint mismatch")
	wg.Wait()
	require.Equal(t, accepted.TLSKeyHash, c.cachedState.TLSKeyHash)
	require.Equal(t, accepted.TLSKeyHash, c.currentTLSHash())
}
