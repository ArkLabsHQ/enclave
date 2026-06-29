package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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

// TestGenSelfSignedCert covers the #129 hardening: genSelfSignedCert must bind
// the served leaf's fingerprint into the attestation rather than leave an
// all-zero tlsKeyHash, and the bound hash must match the cert it serves.
func TestGenSelfSignedCert(t *testing.T) {
	e := &Runtime{cfg: &Config{FQDN: "enclave.example.com"}, hashes: &AttestationHashes{}}
	if e.hashes.tlsKeyHash != ([sha256.Size]byte{}) {
		t.Fatal("attestation must start unbound")
	}

	if err := e.genSelfSignedCert(); err != nil {
		t.Fatalf("genSelfSignedCert: %v", err)
	}
	if e.hashes.tlsKeyHash == ([sha256.Size]byte{}) {
		t.Fatal("tlsKeyHash must be bound after genSelfSignedCert")
	}

	cert, err := e.tlsGetCert(nil)
	if err != nil {
		t.Fatalf("tlsGetCert: %v", err)
	}
	if want := sha256.Sum256(cert.Certificate[0]); e.hashes.tlsKeyHash != want {
		t.Fatal("bound fingerprint must match the served leaf certificate")
	}
}

// A recorded predecessor with a missing/UNSET attestation must fail closed —
// otherwise blanking the SSM param bypasses the PCR31 commitment check.
func TestVerifyPredecessorCommitment_FailsClosedOnMissingAttestation(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")

	e := &Runtime{aws: &AWSClient{SSM: &fakeSSM{params: map[string]string{
		"/prod/myapp/MigrationPreviousPCR0": "aabbcc",
	}}}}

	if err := e.VerifyPredecessorCommitment(context.Background(), "ddeeff"); err == nil {
		t.Fatal("must fail closed when predecessor PCR0 is set but attestation is missing")
	}
}

// Genesis (no predecessor) and rolled-back-onto-self must remain no-ops and not
// require an attestation.
func TestVerifyPredecessorCommitment_NoOpWhenGenesisOrSelf(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	ctx := context.Background()

	genesis := &Runtime{aws: &AWSClient{SSM: &fakeSSM{params: map[string]string{}}}}
	if err := genesis.VerifyPredecessorCommitment(ctx, "ddeeff"); err != nil {
		t.Fatalf("genesis should be a no-op, got: %v", err)
	}

	self := &Runtime{aws: &AWSClient{SSM: &fakeSSM{params: map[string]string{
		"/prod/myapp/MigrationPreviousPCR0": "ddeeff",
	}}}}
	if err := self.VerifyPredecessorCommitment(ctx, "ddeeff"); err != nil {
		t.Fatalf("self-handoff should be a no-op, got: %v", err)
	}
}
