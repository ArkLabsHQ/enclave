// Package relay serves enclave endpoints from a server that clients reach
// instead of the enclave, such as a gateway, without breaking what they verify.
//
//	h, err := relay.New("https://enclave.internal", "/emulator/v1/")
//	mux.Handle("/enclave/attestation", h)
//	mux.Handle("/emulator/v1/", h)
package relay

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// New returns a handler forwarding /enclave/attestation, and the requests
// matching patterns, to the enclave at enclaveURL unchanged. Patterns are
// http.ServeMux patterns such as "/emulator/v1/", listing exactly the routes
// clients may reach; everything else gets 404 or 405, and a pattern matching
// arbitrary paths, such as "/", is refused.
//
// Clients verify the attestation and signed responses end to end, as if they
// called the enclave: the relay keeps the Host, request target, headers and
// body they sent, caches nothing, and returns redirects. The enclave
// application must serve the same paths, since a signature covers the path it
// receives. The relay forwards HTTP as HTTP; a call translated into another
// request, gRPC included, could not be verified. The hop to the enclave is not
// authenticated, so relayed requests must carry no secrets.
func New(enclaveURL string, patterns ...string) (http.Handler, error) {
	target, err := url.Parse(enclaveURL)
	// Requests keep their own path, so the URL names only the enclave.
	if err != nil || (target.Scheme != "https" && target.Scheme != "http") || target.Host == "" ||
		(target.Path != "" && target.Path != "/") || target.RawQuery != "" {
		return nil, fmt.Errorf("enclave URL %q must be http(s)://host[:port]", enclaveURL)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// No certificate check: clients verify the attestation document and the
	// signature themselves.
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// Out copies the client's request, so the method, headers and body
			// the signature covers pass through. SetURL points it at the
			// enclave but would send the enclave's host: restore the client's,
			// the authority it rebuilds the message with.
			r.SetURL(target)
			r.Out.Host = r.In.Host
			// ReverseProxy would re-escape some paths, such as one with "|",
			// and drop query parameters it cannot parse: send the target as
			// the client sent it.
			if uri := r.In.RequestURI; strings.HasPrefix(uri, "/") {
				r.Out.URL.Opaque, r.Out.URL.RawQuery, r.Out.URL.ForceQuery = strings.Cut(uri, "?")
			}
		},
		Transport: transport,
	}
	mux := http.NewServeMux()
	// Any method: the enclave answers CORS preflights for its endpoints.
	for _, pattern := range append([]string{"/enclave/attestation"}, patterns...) {
		if err := route(mux, pattern, proxy); err != nil {
			return nil, err
		}
	}
	return mux, nil
}

// route registers pattern, refusing one whose first path segment is not
// literal, as in "/" or "/{path...}", and reports an invalid or conflicting
// pattern as an error rather than ServeMux's panic.
func route(mux *http.ServeMux, pattern string, h http.Handler) (err error) {
	if i := strings.Index(pattern, "/"); i >= 0 && (pattern[i:] == "/" || pattern[i+1] == '{') {
		return fmt.Errorf("relay pattern %q would forward arbitrary paths to the enclave", pattern)
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("relay pattern %q: %v", pattern, r)
		}
	}()
	mux.Handle(pattern, h)
	return nil
}
