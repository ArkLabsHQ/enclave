package client

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// This literal pins the same wire contract in the two independent Go modules.
func TestSignedRequestWireFormat(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://API.Example:443/orders?x=1", nil)
	require.NoError(t, err)
	req.Header = http.Header{
		"Authorization": {" Bearer alice\t"},
		"Content-Type":  {"application/json"},
		signNonceHeader: {"n1"},
		"X-Tenant":      {"one", "two"},
	}
	signingContext, err := captureResponseSigningContext(req, []byte("amount=10"))
	require.NoError(t, err)
	// X-Tenant is not a covered header.
	canonical := "authorization:QmVhcmVyIGFsaWNl\n" +
		"content-type:YXBwbGljYXRpb24vanNvbg==\n" +
		"x-enclave-sign-nonce:bjE=\n"
	headersHash := sha256.Sum256([]byte(canonical))
	reqHash := sha256.Sum256([]byte("amount=10"))
	respHash := sha256.Sum256([]byte("echo:amount=10"))
	msg := signingContext.responseMessage(respHash, http.StatusCreated)
	require.Equal(t,
		"enclave-signed-response\nPOST /orders?x=1\napi.example:443\n"+
			hex.EncodeToString(headersHash[:])+"\n"+hex.EncodeToString(reqHash[:])+
			"\n201\n"+hex.EncodeToString(respHash[:]),
		string(msg))
	req.Header["Authorization"][0] = "Bearer bob"
	req.Header.Del("X-Tenant")
	req.Header.Set("X-Admin", "true")
	require.Equal(t, msg, signingContext.responseMessage(respHash, http.StatusCreated),
		"later changes to header values and names must not change the captured message")
}

func TestSignedRequestHeaderCanonicalization(t *testing.T) {
	for _, tc := range []struct {
		name  string
		a, b  http.Header
		equal bool
	}{
		{
			"name case and edge whitespace",
			http.Header{"authorization": {" \tBearer alice\t "}},
			http.Header{"Authorization": {"Bearer alice"}},
			true,
		},
		{
			"internal whitespace matters",
			http.Header{"Authorization": {"Bearer  alice"}},
			http.Header{"Authorization": {"Bearer alice"}},
			false,
		},
		{
			"empty is not absent",
			http.Header{"Authorization": {""}},
			http.Header{},
			false,
		},
		{
			"nil values are absent",
			http.Header{"Authorization": nil},
			http.Header{},
			true,
		},
		{
			"duplicates are not comma folding",
			http.Header{"Authorization": {"alice", "bob"}},
			http.Header{"Authorization": {"alice,bob"}},
			false,
		},
		{
			"duplicate order matters",
			http.Header{"Authorization": {"alice", "bob"}},
			http.Header{"Authorization": {"bob", "alice"}},
			false,
		},
		{
			"differently cased keys preserve wire order",
			http.Header{"Authorization": {"one"}, "authorization": {"two"}},
			http.Header{"Authorization": {"one", "two"}},
			true,
		},
		{
			"uncovered headers are ignored",
			http.Header{
				"Cookie": {"session=bob"}, "Origin": {"https://evil.example"},
				"X-Forwarded-For": {"10.0.0.1"}, "X-Tenant-ID": {"bob"},
				"User-Agent": {"browser"}, "Connection": {"close"},
			},
			http.Header{},
			true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := hashHeaders(tc.a)
			b := hashHeaders(tc.b)
			require.Equal(t, tc.equal, a == b)
		})
	}
}

func TestSignedRequestCoversListedHeaders(t *testing.T) {
	for _, name := range []string{"Authorization", "Content-Type", signNonceHeader} {
		t.Run(name, func(t *testing.T) {
			before := hashHeaders(nil)
			present := hashHeaders(http.Header{name: {"alice"}})
			changed := hashHeaders(http.Header{name: {"bob"}})
			duplicate := hashHeaders(http.Header{name: {"alice", "bob"}})
			require.NotEqual(t, before, present, "insertion/removal must change the signature")
			require.NotEqual(t, present, changed)
			require.NotEqual(t, present, duplicate)
		})
	}
}

func TestSignedRequestAuthority(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://backend.example/orders?", nil)
	require.NoError(t, err)
	req.Host = "Bücher.Example:8443"
	signingContext, err := captureResponseSigningContext(req, nil)
	require.NoError(t, err)
	require.Equal(t, "xn--bcher-kva.example:8443", signingContext.authority)
	require.Equal(t, "/orders", signingContext.uri)
	req.Header.Set("Host", "untrusted.example")
	again, err := captureResponseSigningContext(req, nil)
	require.NoError(t, err)
	respHash := sha256.Sum256(nil)
	require.Equal(t, signingContext.responseMessage(respHash, http.StatusOK),
		again.responseMessage(respHash, http.StatusOK), "Host in Header is not the HTTP authority")
}

func TestSignedRequestRejectsAmbiguousForwarding(t *testing.T) {
	for _, option := range []string{"Authorization", "Cookie", "X-Tenant-ID", "upgrade"} {
		t.Run(option, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "https://api.example/", nil)
			require.NoError(t, err)
			req.Header.Set("Connection", "keep-alive, "+option)
			_, err = captureResponseSigningContext(req, nil)
			require.ErrorContains(t, err, "Connection")
		})
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.example/", strings.NewReader("body"))
	require.NoError(t, err)
	req.Trailer = http.Header{"Authorization": {"Bearer alice"}}
	_, err = captureResponseSigningContext(req, nil)
	require.ErrorContains(t, err, "trailers")
}

func TestPrepareResponseSigningContextCapturesURLCredentials(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://alice:password@api.example/orders", nil)
	require.NoError(t, err)
	signingContext, err := prepareResponseSigningContext(req)
	require.NoError(t, err)
	require.Equal(t, "Basic YWxpY2U6cGFzc3dvcmQ=", req.Header.Get("Authorization"))
	require.Equal(
		t,
		hashHeaders(req.Header),
		signingContext.headersHash,
	)
	req.Header.Set("Authorization", "Bearer substituted")
	require.NotEqual(
		t,
		hashHeaders(req.Header),
		signingContext.headersHash,
		"verification must use the pre-transport snapshot",
	)
}

func TestSignedRequestTarget(t *testing.T) {
	// Received requests: sign the target as sent, which browsers leave unescaped.
	for target, want := range map[string]string{
		"/items/a|b?q=x^y": "/items/a|b?q=x^y",
		"/a%7Cb":           "/a%7Cb",
		"/a?":              "/a",
		"/a?b?":            "/a?b?",
	} {
		raw := "GET " + target + " HTTP/1.1\r\nHost: api.example\r\n\r\n"
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		require.NoError(t, err)
		signingContext, err := captureResponseSigningContext(req, nil)
		require.NoError(t, err)
		require.Equal(t, want, signingContext.uri, target)
	}

	// Client requests: sign what Go's transport sends, without an empty "?".
	req, err := http.NewRequest(http.MethodGet, "https://[fe80::1%25eth0]:8443/items/a|b?", nil)
	require.NoError(t, err)
	signingContext, err := captureResponseSigningContext(req, nil)
	require.NoError(t, err)
	require.Equal(t, "/items/a%7Cb", signingContext.uri)
	require.Equal(t, "[fe80::1]:8443", signingContext.authority, "the transport drops the zone")
}
