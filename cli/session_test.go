package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// fakeSessionStarter is a test sessionStarter that returns a pre-configured
// port + cleanup recorder (or a fixed error).
type fakeSessionStarter struct {
	port     int
	cleanups int
	err      error
}

func (f *fakeSessionStarter) StartPortForward(ctx context.Context, instanceID, region, profile, remotePort string) (int, func(), error) {
	if f.err != nil {
		return 0, nil, f.err
	}
	return f.port, func() { f.cleanups++ }, nil
}

func portOf(t *testing.T, ts *httptest.Server) int {
	t.Helper()
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse test server port: %v", err)
	}
	return p
}

// Drives a ~1.4 MB body through httpViaSession to prove no truncation and that
// cleanup runs on Body.Close().
func TestHttpViaSession_HappyPath(t *testing.T) {
	body := strings.Repeat(`{"id":"x","message":"hello"}`+"\n", 50_000)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = io.WriteString(w, body)
	}))
	defer ts.Close()

	fake := &fakeSessionStarter{port: portOf(t, ts)}
	ac := &awsClients{region: "us-east-1", sessions: fake}

	resp, err := ac.httpViaSession(context.Background(), "i-test", "/enclave-logs")
	if err != nil {
		t.Fatalf("httpViaSession: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}

	if len(got) != len(body) {
		t.Errorf("body length = %d, want %d (truncated?)", len(got), len(body))
	}
	if fake.cleanups != 1 {
		t.Errorf("cleanups = %d, want 1", fake.cleanups)
	}
}

// fetchSupervisor must surface non-2xx status codes with the response body.
func TestFetchSupervisor_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "upstream unavailable")
	}))
	defer ts.Close()

	fake := &fakeSessionStarter{port: portOf(t, ts)}
	ac := &awsClients{region: "us-east-1", sessions: fake}

	_, err := ac.fetchSupervisor(context.Background(), "i-test", "/enclave-logs")
	requireErrContains(t, err, "502")
	requireErrContains(t, err, "upstream unavailable")
	if fake.cleanups != 1 {
		t.Errorf("cleanups = %d, want 1 (error path must still tear down session)", fake.cleanups)
	}
}

// Plugin-missing surfaces the install hint and never invokes cleanup (nothing
// to clean up — the starter never returned a session).
func TestHttpViaSession_PluginMissing(t *testing.T) {
	fake := &fakeSessionStarter{err: errPluginMissing}
	ac := &awsClients{region: "us-east-1", sessions: fake}

	_, err := ac.httpViaSession(context.Background(), "i-test", "/enclave-logs")
	if !errors.Is(err, errPluginMissing) {
		t.Errorf("err = %v, want errPluginMissing", err)
	}
	if fake.cleanups != 0 {
		t.Errorf("cleanups = %d, want 0", fake.cleanups)
	}
}

// Generic session-start error must surface as-is; no cleanup expected.
func TestHttpViaSession_StartError(t *testing.T) {
	fake := &fakeSessionStarter{err: errors.New("boom")}
	ac := &awsClients{region: "us-east-1", sessions: fake}

	_, err := ac.httpViaSession(context.Background(), "i-test", "/enclave-logs")
	if err == nil || err.Error() != "boom" {
		t.Errorf("err = %v, want %q", err, "boom")
	}
	if fake.cleanups != 0 {
		t.Errorf("cleanups = %d, want 0", fake.cleanups)
	}
}

// sessionClosingBody.Close must close the wrapped ReadCloser AND run the
// cleanup func exactly once.
func TestSessionClosingBody_Close(t *testing.T) {
	cleanupCalls := 0
	b := sessionClosingBody{
		rc:      io.NopCloser(strings.NewReader("hello")),
		cleanup: func() { cleanupCalls++ },
	}

	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("read = %q, want %q", got, "hello")
	}

	if err := b.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if cleanupCalls != 1 {
		t.Errorf("cleanup calls = %d, want 1", cleanupCalls)
	}
}
