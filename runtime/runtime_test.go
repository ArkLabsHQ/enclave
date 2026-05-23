package runtime

import (
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
