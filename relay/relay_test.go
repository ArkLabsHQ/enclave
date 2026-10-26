package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// seen is what the enclave received for one request.
type seen struct {
	Proto, Method, Host, Target, Nonce, Body string
}

func TestNewForwardsListedRoutesUnchanged(t *testing.T) {
	var mu sync.Mutex
	var received []seen
	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, seen{
			r.Proto, r.Method, r.Host, r.RequestURI, r.Header.Get("X-Enclave-Sign-Nonce"),
			string(body),
		})
		mu.Unlock()
		w.Header().Set("X-Enclave-Signature", "sig")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
		}
		_, _ = w.Write([]byte("answer"))
	}
	enclave := httptest.NewUnstartedServer(http.HandlerFunc(handler))
	enclave.EnableHTTP2 = true // as the enclave runtime negotiates
	enclave.StartTLS()
	t.Cleanup(enclave.Close)
	h, err := New(enclave.URL, "/emulator/v1/")
	require.NoError(t, err)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{"tx":"..."}`))
	require.NoError(t, err)
	// Browsers send "|" unescaped; ReverseProxy alone would escape it and drop
	// the query parameter with ";", changing the target the signature covers.
	req.URL.Opaque, req.URL.RawQuery = "/emulator/v1/a|b", "x=1;y=2"
	req.Host = "arkd.example"
	req.Header.Set("X-Enclave-Sign-Nonce", "n1")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	answer, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	// The signature covers the status and body: both come back unchanged.
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	require.Equal(t, "answer", string(answer))
	require.Equal(t, "sig", resp.Header.Get("X-Enclave-Signature"), "the signature is returned")

	// A browser sends a CORS preflight first when the request has custom
	// headers; the enclave answers it.
	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		req, err := http.NewRequest(method, srv.URL+"/enclave/attestation?nonce=ab", nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, method)
	}

	for _, path := range []string{"/v1/info", "/enclave/v1/info", "/health", "/emulator"} {
		resp, err := http.Get(srv.URL + path)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusNotFound, resp.StatusCode, path)
	}

	mu.Lock()
	defer mu.Unlock()
	host := strings.TrimPrefix(srv.URL, "http://")
	require.Equal(t, []seen{
		{"HTTP/2.0", "POST", "arkd.example", "/emulator/v1/a|b?x=1;y=2", "n1", `{"tx":"..."}`},
		{"HTTP/2.0", "GET", host, "/enclave/attestation?nonce=ab", "", ""},
		{"HTTP/2.0", "OPTIONS", host, "/enclave/attestation?nonce=ab", "", ""},
	}, received, "only listed routes arrive, each with the client's Host and request")
}

func TestNewRefusesUnsafeOrInvalidConfiguration(t *testing.T) {
	for _, pattern := range []string{
		"/", "GET /", "example.com/", "/{path...}", "GET /{name}/v1/", "emulator", "/emulator/{",
	} {
		_, err := New("https://enclave.internal", pattern)
		require.Error(t, err, pattern)
	}
	_, err := New("https://enclave.internal", "/enclave/attestation")
	require.Error(t, err, "attestation is always relayed; listing it again conflicts")
	for _, enclaveURL := range []string{
		"", "enclave.internal", "ftp://enclave.internal", "https://enclave.internal/base",
	} {
		_, err := New(enclaveURL)
		require.Error(t, err, enclaveURL)
	}
}
