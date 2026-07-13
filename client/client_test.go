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
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
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

	sum := sha256.Sum256(srv.Certificate().Raw)
	goodHash := hex.EncodeToString(sum[:])

	// Match → handler runs.
	c, err := PinnedHTTPClient(goodHash, false)
	if err != nil {
		t.Fatalf("PinnedHTTPClient: %v", err)
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("pinned request to matching cert must succeed: %v", err)
	}
	_ = resp.Body.Close()
	if !reached {
		t.Fatal("handler should have been reached on a matching pin")
	}

	// Mismatch → fail closed, handler NOT reached.
	reached = false
	bad, err := PinnedHTTPClient(strings.Repeat("cd", 32), false)
	if err != nil {
		t.Fatalf("PinnedHTTPClient: %v", err)
	}
	if _, err := bad.Get(srv.URL); err == nil {
		t.Fatal("pinned request to a non-matching cert must fail")
	}
	if reached {
		t.Fatal("handler must NOT run when the pin fails (request must not be sent)")
	}
}

// fakeEnclave serves a COSE-skip attestation whose user_data carries attestedTLS,
// and records every non-attestation path it receives.
type fakeEnclave struct {
	pcr0Hex     string
	attestedTLS [32]byte // tlsKeyHash embedded in user_data
	mu          sync.Mutex
	appPaths    []string
}

func (f *fakeEnclave) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/enclave/attestation" {
			nonceHex := r.URL.Query().Get("nonce")
			nonce, _ := hex.DecodeString(nonceHex)
			pcr0, _ := hex.DecodeString(f.pcr0Hex)
			ud := append([]byte("sha256:"), f.attestedTLS[:]...)
			ud = append(ud, ';')
			ud = append(ud, []byte("sha256:")...)
			ud = append(ud, make([]byte, 32)...) // attestation signing key hash all-zero (unregistered)
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
		fe.attestedTLS = sha256.Sum256(srv.Certificate().Raw) // attest the real cert

		c, err := New(srv.URL, Options{ExpectedPCR0: pcr0, InsecureSkipCOSEVerify: true, SkipKeyBinding: true})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		resp, err := c.Get(context.Background(), "/v1/enclave-info")
		if err != nil {
			t.Fatalf("matching pin must allow /v1/enclave-info: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})

	t.Run("strict default vs SkipKeyBinding (no signing key registered)", func(t *testing.T) {
		fe := &fakeEnclave{pcr0Hex: pcr0} // handler serves an all-zero signing-key hash
		srv := httptest.NewTLSServer(fe.handler())
		defer srv.Close()
		fe.attestedTLS = sha256.Sum256(srv.Certificate().Raw) // pin matches

		// Strict default: a missing signing key is a hard failure (no silent skip).
		strict, _ := New(srv.URL, Options{ExpectedPCR0: pcr0, InsecureSkipCOSEVerify: true})
		if _, err := strict.Get(context.Background(), "/v1/enclave-info"); err == nil {
			t.Fatal("strict default must fail when no signing key is registered")
		}

		// Explicit PCR0 + pin only: proceeds (this is curl's mode).
		lite, _ := New(srv.URL, Options{ExpectedPCR0: pcr0, InsecureSkipCOSEVerify: true, SkipKeyBinding: true})
		if _, err := lite.Get(context.Background(), "/v1/enclave-info"); err != nil {
			t.Fatalf("SkipKeyBinding must proceed without a signing key: %v", err)
		}
	})

	t.Run("mismatch → fail closed, no app request sent", func(t *testing.T) {
		fe := &fakeEnclave{pcr0Hex: pcr0}
		srv := httptest.NewTLSServer(fe.handler())
		defer srv.Close()
		// Attest a DIFFERENT cert than the one the server actually serves.
		for i := range fe.attestedTLS {
			fe.attestedTLS[i] = 0xCD
		}

		c, err := New(srv.URL, Options{ExpectedPCR0: pcr0, InsecureSkipCOSEVerify: true, SkipKeyBinding: true})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := c.Get(context.Background(), "/v1/enclave-info"); err == nil {
			t.Fatal("cert mismatch must fail closed")
		}
		fe.mu.Lock()
		defer fe.mu.Unlock()
		if len(fe.appPaths) != 0 {
			t.Fatalf("no app request must be sent on a pin mismatch; got %v", fe.appPaths)
		}
	})
}
