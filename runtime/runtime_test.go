package runtime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// tagRoundTripper is an http.RoundTripper that reports its own name in the
// response Status, so a test can tell which transport handled a request.
type tagRoundTripper string

func (t tagRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{Status: string(t)}, nil
}

func TestProtocolSwitchTransport(t *testing.T) {
	tr := &protocolSwitchTransport{
		h1:  tagRoundTripper("h1"),
		h2c: tagRoundTripper("h2c"),
	}
	for _, tc := range []struct {
		protoMajor int
		want       string
	}{
		{1, "h1"},
		{2, "h2c"},
	} {
		resp, err := tr.RoundTrip(&http.Request{ProtoMajor: tc.protoMajor})
		if err != nil {
			t.Fatalf("ProtoMajor %d: RoundTrip: %v", tc.protoMajor, err)
		}
		if resp.Status != tc.want {
			t.Errorf("ProtoMajor %d routed to %q, want %q", tc.protoMajor, resp.Status, tc.want)
		}
	}
}

func TestUpstreamTransport(t *testing.T) {
	if _, ok := upstreamTransport("h2c").(*http2.Transport); !ok {
		t.Errorf(`upstreamTransport("h2c"): not *http2.Transport`)
	}
	if _, ok := upstreamTransport("h1").(*http.Transport); !ok {
		t.Errorf(`upstreamTransport("h1"): not *http.Transport`)
	}
	for _, mode := range []string{"auto", "", "bogus"} {
		if _, ok := upstreamTransport(mode).(*protocolSwitchTransport); !ok {
			t.Errorf("upstreamTransport(%q): not *protocolSwitchTransport (want auto fallback)", mode)
		}
	}
}

func TestCorsWildcard_Preflight(t *testing.T) {
	calls := 0
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ })
	h := corsWildcard(inner)

	req := httptest.NewRequest(http.MethodOptions, "/v1/enclave-info", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("OPTIONS status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if calls != 0 {
		t.Errorf("inner handler called %d times on OPTIONS, want 0", calls)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
}

func TestCorsWildcard_PassthroughAndHeaders(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h := corsWildcard(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/enclave-info", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called {
		t.Errorf("inner handler not called on GET")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	for _, hdr := range []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
		"Access-Control-Expose-Headers",
	} {
		if got := rec.Header().Get(hdr); got != "*" {
			t.Errorf("%s = %q, want %q", hdr, got, "*")
		}
	}
}

// TestUpstreamExited_DefaultsFalse verifies a fresh runtime reports the app
// as not-exited (the only state observable until cmd/runtime/main.go calls
// MarkUpstreamExited).
func TestUpstreamExited_DefaultsFalse(t *testing.T) {
	e := &Runtime{}
	exited, msg := e.UpstreamExited()
	if exited {
		t.Errorf("UpstreamExited() exited=true on fresh runtime, want false")
	}
	if msg != "" {
		t.Errorf("UpstreamExited() msg=%q on fresh runtime, want empty", msg)
	}
}

// TestUpstreamExited_RecordsError flips the latch with a non-nil error and
// confirms both the bool and the error string round-trip.
func TestUpstreamExited_RecordsError(t *testing.T) {
	e := &Runtime{}
	e.MarkUpstreamExited(errors.New("exit status 1"))
	exited, msg := e.UpstreamExited()
	if !exited {
		t.Errorf("UpstreamExited() exited=false after MarkUpstreamExited(err), want true")
	}
	if msg != "exit status 1" {
		t.Errorf("UpstreamExited() msg=%q, want %q", msg, "exit status 1")
	}
}

// TestUpstreamExited_RecordsCleanExit: nil error means "app exited cleanly"
// — still marks the latch, but message stays empty.
func TestUpstreamExited_RecordsCleanExit(t *testing.T) {
	e := &Runtime{}
	e.MarkUpstreamExited(nil)
	exited, msg := e.UpstreamExited()
	if !exited {
		t.Errorf("UpstreamExited() exited=false after MarkUpstreamExited(nil), want true")
	}
	if msg != "" {
		t.Errorf("UpstreamExited() msg=%q after clean exit, want empty", msg)
	}
}

// TestUpstreamAppInfo_JSONShape locks in the JSON field names that
// test/run.sh and external clients depend on (.upstream_app.exited,
// .upstream_app.error).
func TestUpstreamAppInfo_JSONShape(t *testing.T) {
	cases := []struct {
		name string
		in   UpstreamAppInfo
		want string
	}{
		{
			name: "not exited — no error field",
			in:   UpstreamAppInfo{Exited: false},
			want: `{"exited":false}`,
		},
		{
			name: "exited cleanly — no error field",
			in:   UpstreamAppInfo{Exited: true},
			want: `{"exited":true}`,
		},
		{
			name: "exited with error — error included",
			in:   UpstreamAppInfo{Exited: true, Error: "exit status 1"},
			want: `{"exited":true,"error":"exit status 1"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(b) != tc.want {
				t.Errorf("json shape mismatch:\n  got:  %s\n  want: %s", b, tc.want)
			}
		})
	}
}

// TestSetCertFingerprint covers the #129 hardening: a chain with no non-CA leaf
// must fail TLS setup rather than silently leave an all-zero tlsKeyHash.
func TestSetCertFingerprint(t *testing.T) {
	e := &Runtime{hashes: &AttestationHashes{}}

	// CA-only chain → error (no leaf to fingerprint).
	if err := e.setCertFingerprint(genCertPEM(t, true)); err == nil {
		t.Fatal("CA-only chain must error (no non-CA leaf)")
	}
	if e.hashes.tlsKeyHash != ([32]byte{}) {
		t.Fatal("tlsKeyHash must stay zero when no leaf is found")
	}

	// A non-CA leaf → fingerprint set, no error.
	if err := e.setCertFingerprint(genCertPEM(t, false)); err != nil {
		t.Fatalf("leaf cert must set fingerprint: %v", err)
	}
	if e.hashes.tlsKeyHash == ([32]byte{}) {
		t.Fatal("tlsKeyHash must be set after a non-CA leaf")
	}
}

func genCertPEM(t *testing.T, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
