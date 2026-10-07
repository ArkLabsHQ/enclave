package client

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"
)

const signedResponse = "enclave-signed-response"

// responseSigningContext holds the request details bound to a response signature.
// Keep this wire format and canonicalization identical in client and runtime.
type responseSigningContext struct {
	method      string
	uri         string
	authority   string
	headersHash [sha256.Size]byte
	bodyHash    [sha256.Size]byte
}

// captureResponseSigningContext snapshots the request before transport/proxy
// code can mutate it. It does not create a signature.
func captureResponseSigningContext(r *http.Request, body []byte) (responseSigningContext, error) {
	if r.URL == nil {
		return responseSigningContext{}, fmt.Errorf("signed request has no URL")
	}
	if len(r.Trailer) != 0 || r.Header.Get("Trailer") != "" {
		return responseSigningContext{}, fmt.Errorf("signed requests do not support trailers")
	}
	// ReverseProxy removes headers nominated by Connection. Do not attest an
	// Authorization (or other application header) that the app will never see.
	for _, value := range r.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			switch strings.ToLower(strings.TrimSpace(token)) {
			case "", "close", "keep-alive":
			default:
				return responseSigningContext{}, fmt.Errorf(
					"signed requests do not support Connection header options",
				)
			}
		}
	}
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	authority, err := httpguts.PunycodeHostPort(removeZone(authority))
	if err != nil || authority == "" || !httpguts.ValidHostHeader(authority) {
		return responseSigningContext{}, fmt.Errorf("invalid signed request authority")
	}
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	return responseSigningContext{
		method: method, uri: requestTarget(r),
		authority:   strings.ToLower(authority),
		headersHash: hashHeaders(r.Header), bodyHash: sha256.Sum256(body),
	}, nil
}

// requestTarget is the path and query as sent. A received request keeps them
// exactly as on the wire, since Go would re-escape characters such as "|" that
// browsers send unencoded. An empty query is dropped: clients differ on
// sending "/a?" or "/a".
func requestTarget(r *http.Request) string {
	if strings.HasPrefix(r.RequestURI, "/") {
		if r.URL.RawQuery == "" {
			return strings.TrimSuffix(r.RequestURI, "?")
		}
		return r.RequestURI
	}
	u := *r.URL
	u.ForceQuery = false
	return u.RequestURI()
}

// removeZone drops an IPv6 zone ("[fe80::1%eth0]"), as Go's transport does
// before sending Host.
func removeZone(host string) string {
	if !strings.HasPrefix(host, "[") {
		return host
	}
	i := strings.LastIndex(host, "]")
	if i < 0 {
		return host
	}
	j := strings.LastIndex(host[:i], "%")
	if j < 0 {
		return host
	}
	return host[:j] + host[i:]
}

// responseMessage builds the message to sign or verify, binding the captured
// request details to the response body hash and status.
func (r responseSigningContext) responseMessage(bodyHash [sha256.Size]byte, status int) []byte {
	return fmt.Appendf(nil, "%s\n%s %s\n%s\n%x\n%x\n%d\n%x",
		signedResponse, r.method, r.uri, r.authority,
		r.headersHash, r.bodyHash, status, bodyHash)
}

// signedHeaders are the request headers a signature covers, lowercase and
// sorted; the nonce is bound as one of them. Every other header, browser and
// proxy metadata included, varies in transit and is not covered: applications
// must not rely on it in a signed request.
var signedHeaders = []string{"authorization", "content-type", "x-enclave-sign-nonce"}

// hashHeaders covers signedHeaders, including absence: adding, removing or
// changing one changes the hash. Sorted lowercase names precede comma-separated
// base64 values and a newline. Empty and repeated values remain distinct; only
// edge SP/HTAB is trimmed as HTTP parsers do.
func hashHeaders(h http.Header) [sha256.Size]byte {
	fields := make(map[string][]string)
	// Go writes differently-cased map keys in sorted order; preserve that order
	// if callers bypass Header.Set and supply aliases of the same field name.
	for _, name := range slices.Sorted(maps.Keys(h)) {
		lower := strings.ToLower(name)
		if !slices.Contains(signedHeaders, lower) {
			continue
		}
		for _, value := range h[name] {
			fields[lower] = append(fields[lower], strings.Trim(value, " \t"))
		}
	}
	var canonical strings.Builder
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		values := fields[name]
		canonical.WriteString(name)
		canonical.WriteByte(':')
		for i, value := range values {
			if i > 0 {
				canonical.WriteByte(',')
			}
			canonical.WriteString(base64.StdEncoding.EncodeToString([]byte(value)))
		}
		canonical.WriteByte('\n')
	}
	return sha256.Sum256([]byte(canonical.String()))
}
