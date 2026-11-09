package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArkLabsHQ/enclave/internal/signing"
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
	attestedTLS [32]byte           // tlsKeyHash embedded in user_data
	signingKey  ed25519.PrivateKey // attested and used to sign when asked; nil attests none
	tamper      bool               // alter the body after signing it
	relabel     int                // if set, the status sent instead of the one signed
	mu          sync.Mutex
	appPaths    []string
}

func (f *fakeEnclave) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/enclave/attestation" {
			nonceHex := r.URL.Query().Get("nonce")
			nonce, _ := hex.DecodeString(nonceHex)
			pcr0, _ := hex.DecodeString(f.pcr0Hex)
			signingPub := make([]byte, ed25519.PublicKeySize)
			if f.signingKey != nil {
				signingPub = f.signingKey.Public().(ed25519.PublicKey)
			}
			ud := testUserData(f.attestedTLS, signingPub)
			_, _ = w.Write([]byte(buildInsecureCOSEDoc(nitrite.Document{
				PCRs:     map[uint][]byte{0: pcr0},
				Nonce:    nonce,
				UserData: ud,
			})))
			return
		}
		f.mu.Lock()
		f.appPaths = append(f.appPaths, r.URL.Path)
		f.mu.Unlock()
		body := []byte(`{"version":"test","previous_pcr0":"genesis"}`)
		status := http.StatusOK
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/enclave/v1/info")
			status = http.StatusSeeOther
		}
		if nonce := r.Header.Get(signNonceHeader); nonce != "" && f.signingKey != nil {
			rawNonce, err := hex.DecodeString(nonce)
			if err != nil || len(rawNonce) != signing.NonceSize {
				http.Error(w, "bad nonce", http.StatusBadRequest)
				return
			}
			reqBody, _ := io.ReadAll(r.Body)
			msg := signing.ResponseMessage(
				r.Method, signing.RequestTarget(r), rawNonce, reqBody, status, body,
			)
			w.Header().Set(signatureHeader,
				base64.StdEncoding.EncodeToString(ed25519.Sign(f.signingKey, msg)))
			if f.tamper {
				body = []byte(`{"version":"forged","previous_pcr0":"genesis"}`)
			}
			if f.relabel != 0 {
				status = f.relabel
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
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
		attest, err := c.VerifyAttestation(context.Background())
		require.NoError(t, err)
		require.Equal(t, 24*time.Hour, attest.MigrationCooldown)
		require.Empty(t, attest.MigrationTargetPCR0, "no migration pending")
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

func TestClientSignedResponses(t *testing.T) {
	pcr0 := strings.Repeat("ab", 48)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))

	postTo := func(t *testing.T, fe *fakeEnclave, path string) (*Response, error) {
		srv := httptest.NewTLSServer(fe.handler())
		t.Cleanup(srv.Close)
		fe.attestedTLS = sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
		c, err := New(srv.URL, Options{
			ExpectedPCR0: pcr0, InsecureSkipCOSEVerify: true, SignedResponses: true,
		})
		require.NoError(t, err)
		return c.Post(context.Background(), path, strings.NewReader(`{"amount":10}`))
	}
	post := func(t *testing.T, fe *fakeEnclave) (*Response, error) {
		return postTo(t, fe, "/orders?x=1")
	}

	t.Run("leaves the caller's request unchanged", func(t *testing.T) {
		fe := &fakeEnclave{pcr0Hex: pcr0, signingKey: key}
		srv := httptest.NewTLSServer(fe.handler())
		t.Cleanup(srv.Close)
		fe.attestedTLS = sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
		c, err := New(srv.URL, Options{
			ExpectedPCR0: pcr0, InsecureSkipCOSEVerify: true, SignedResponses: true,
		})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/orders", nil)
		require.NoError(t, err)
		_, err = c.Do(context.Background(), req)
		require.NoError(t, err)
		require.Empty(t, req.Header, "no nonce or Authorization added to the caller's request")
	})

	t.Run("signs a request built without a header map", func(t *testing.T) {
		fe := &fakeEnclave{pcr0Hex: pcr0, signingKey: key}
		srv := httptest.NewTLSServer(fe.handler())
		t.Cleanup(srv.Close)
		fe.attestedTLS = sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
		c, err := New(srv.URL, Options{
			ExpectedPCR0: pcr0, InsecureSkipCOSEVerify: true, SignedResponses: true,
		})
		require.NoError(t, err)
		u, err := url.Parse(srv.URL + "/orders")
		require.NoError(t, err)
		req := &http.Request{Method: http.MethodGet, URL: u}
		resp, err := c.Do(context.Background(), req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Nil(t, req.Header, "the caller's request is left as it was")
	})

	t.Run("verifies a body a proxy compressed", func(t *testing.T) {
		fe := &fakeEnclave{pcr0Hex: pcr0, signingKey: key}
		enclave := fe.handler()
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := httptest.NewRecorder()
			enclave.ServeHTTP(rec, r)
			maps.Copy(w.Header(), rec.Header())
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				w.WriteHeader(rec.Code)
				_, _ = w.Write(rec.Body.Bytes())
				return
			}
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(rec.Code)
			zw := gzip.NewWriter(w)
			_, _ = zw.Write(rec.Body.Bytes())
			_ = zw.Close()
		}))
		t.Cleanup(srv.Close)
		fe.attestedTLS = sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
		c, err := New(srv.URL, Options{
			ExpectedPCR0: pcr0, InsecureSkipCOSEVerify: true, SignedResponses: true,
		})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/orders", nil)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip") // would otherwise stop Go decompressing
		_, err = c.Do(context.Background(), req)
		require.NoError(t, err)
	})

	t.Run("a failed signature drops the cached attestation", func(t *testing.T) {
		fe := &fakeEnclave{pcr0Hex: pcr0, signingKey: key, tamper: true}
		srv := httptest.NewTLSServer(fe.handler())
		t.Cleanup(srv.Close)
		fe.attestedTLS = sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
		c, err := New(srv.URL, Options{
			ExpectedPCR0: pcr0, InsecureSkipCOSEVerify: true, SignedResponses: true,
		})
		require.NoError(t, err)
		_, err = c.Get(context.Background(), "/orders")
		require.ErrorContains(t, err, "response signature (HTTP 200)")
		require.Nil(t, c.cachedState, "the next call must attest again")
	})

	t.Run("valid signature", func(t *testing.T) {
		resp, err := post(t, &fakeEnclave{pcr0Hex: pcr0, signingKey: key})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("a redirect is returned, not followed", func(t *testing.T) {
		fe := &fakeEnclave{pcr0Hex: pcr0, signingKey: key}
		resp, err := postTo(t, fe, "/redirect")
		require.NoError(t, err)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		require.Equal(t, []string{"/redirect"}, fe.appPaths)
	})

	t.Run("a relabelled status fails", func(t *testing.T) {
		fe := &fakeEnclave{pcr0Hex: pcr0, signingKey: key, relabel: http.StatusOK}
		_, err := postTo(t, fe, "/redirect")
		require.ErrorContains(t, err, "missing or invalid X-Enclave-Signature")
	})

	t.Run("tampered body fails", func(t *testing.T) {
		_, err := post(t, &fakeEnclave{pcr0Hex: pcr0, signingKey: key, tamper: true})
		require.ErrorContains(t, err, "missing or invalid X-Enclave-Signature")
	})

	// A proxy that changes what the enclave answers cannot pass the answer off
	// as the response to the request the client sent.
	t.Run("a response to another method, target or body fails", func(t *testing.T) {
		for name, mutate := range map[string]func(*http.Request){
			"method": func(r *http.Request) { r.Method = http.MethodPut },
			"path":   func(r *http.Request) { r.RequestURI, r.URL.Path = "/refunds?x=1", "/refunds" },
			"query":  func(r *http.Request) { r.RequestURI, r.URL.RawQuery = "/orders?x=2", "x=2" },
			"body": func(r *http.Request) {
				r.Body = io.NopCloser(strings.NewReader(`{"amount":1000}`))
			},
		} {
			fe := &fakeEnclave{pcr0Hex: pcr0, signingKey: key}
			enclave := fe.handler()
			srv := httptest.NewTLSServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/enclave/attestation" {
						mutate(r)
					}
					enclave.ServeHTTP(w, r)
				}),
			)
			t.Cleanup(srv.Close)
			fe.attestedTLS = sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
			c, err := New(srv.URL, Options{
				ExpectedPCR0: pcr0, InsecureSkipCOSEVerify: true, SignedResponses: true,
			})
			require.NoError(t, err)
			_, err = c.Post(context.Background(), "/orders?x=1", strings.NewReader(`{"amount":10}`))
			require.ErrorContains(t, err, "missing or invalid X-Enclave-Signature", name)
		}
	})

	t.Run("no attested signing key fails before the request", func(t *testing.T) {
		fe := &fakeEnclave{pcr0Hex: pcr0}
		_, err := post(t, fe)
		require.ErrorContains(t, err, "attests no response signing key")
		require.Empty(t, fe.appPaths)
	})
}

// A TLS-terminating proxy may route attestation and app requests independently.
// The response must verify against the key from the expected image's attestation.
func TestClientSignedResponsesAcrossGenerations(t *testing.T) {
	currentKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	previousKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	currentPCR0, previousPCR0 := strings.Repeat("ab", 48), strings.Repeat("cd", 48)

	for _, tc := range []struct {
		name    string
		pcr0    string
		key     ed25519.PrivateKey
		wantErr bool
	}{
		{name: "same generation replica", pcr0: currentPCR0, key: currentKey},
		{name: "predecessor", pcr0: previousPCR0, key: previousKey, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := &fakeEnclave{pcr0Hex: currentPCR0, signingKey: currentKey}
			responder := &fakeEnclave{pcr0Hex: tc.pcr0, signingKey: tc.key}
			attestHandler, appHandler := current.handler(), responder.handler()
			proxy := httptest.NewTLSServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/enclave/attestation" {
						attestHandler.ServeHTTP(w, r)
						return
					}
					appHandler.ServeHTTP(w, r)
				}),
			)
			t.Cleanup(proxy.Close)
			// The enclave's attested TLS key differs from the proxy's certificate.
			current.attestedTLS = sha256.Sum256([]byte("current enclave TLS key"))
			insecureTLS := true
			c, err := New(proxy.URL, Options{
				ExpectedPCR0:           currentPCR0,
				InsecureTLS:            &insecureTLS,
				InsecureSkipCOSEVerify: true,
				SignedResponses:        true,
			})
			require.NoError(t, err)

			resp, err := c.Get(context.Background(), "/orders")
			if tc.wantErr {
				require.ErrorContains(t, err, "missing or invalid X-Enclave-Signature")
				require.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
			}
			require.Equal(t, []string{"/orders"}, responder.appPaths)
			require.Empty(t, current.appPaths)
		})
	}
}
