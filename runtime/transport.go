package runtime

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

// protocolSwitchTransport forwards each proxied request to the user app over
// the same HTTP version the client used — h2c for HTTP/2 inbound, HTTP/1.1 for
// HTTP/1.1 — via the inbound ProtoMajor that ReverseProxy preserves on RoundTrip.
type protocolSwitchTransport struct {
	h1  http.RoundTripper
	h2c http.RoundTripper
}

func (t *protocolSwitchTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.ProtoMajor == 1 {
		return t.h1.RoundTrip(r)
	}
	return t.h2c.RoundTrip(r)
}

// upstreamTransport builds the reverse-proxy transport for the runtime->app
// hop, selected by ENCLAVE_NITRIDING_UPSTREAM: "h2c" or "h1" pin a single
// protocol; "auto" (the default) matches the inbound protocol per request.
// h2c is required for gRPC; h1 suits a plain HTTP/1.1 app.
func upstreamTransport(mode string) http.RoundTripper {
	h1 := &http.Transport{}
	h2c := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	switch mode {
	case "h2c":
		return h2c
	case "h1":
		return h1
	default:
		return &protocolSwitchTransport{h1: h1, h2c: h2c}
	}
}

// corsWildcard wraps an http.Handler to send permissive CORS headers on every
// response and short-circuit OPTIONS preflight with 204. Used on the runtime's
// /v1/* admin endpoints so a browser SPA can call them cross-origin (e.g.,
// GET /v1/enclave-info for attestation). The catch-all upstream proxy is not
// wrapped — the user app sets its own CORS on its own responses.
func corsWildcard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "*")
		h.Set("Access-Control-Allow-Headers", "*")
		h.Set("Access-Control-Expose-Headers", "*")
		h.Set("Access-Control-Max-Age", "600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
