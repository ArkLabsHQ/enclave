// Package signing is the signed-response wire format: the runtime signs with it
// and the client verifies with it.
package signing

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
)

const signedResponse = "enclave-signed-response"

// NonceSize is the length of the X-Enclave-Sign-Nonce value before its
// lowercase hex encoding, the same as the attestation nonce, so one nonce can
// bind both.
const NonceSize = 20

// ResponseMessage builds the message to sign or verify, binding the request's
// method, target, nonce, and body to the response's status and body: for HTTP
// the request body, the status code, and the decoded response body; for gRPC
// the request and response messages without gRPC framing and the grpc-status.
// Browser verifiers implement this wire format from the README, so keep it in
// step with the README.
func ResponseMessage(
	method, target string, nonce, request []byte, status int, response []byte,
) []byte {
	return fmt.Appendf(nil, "%s\n%s %s\n%x\n%x\n%d\n%x",
		signedResponse, method, target, nonce, sha256.Sum256(request),
		status, sha256.Sum256(response))
}

// RequestTarget is the path and query as sent; for gRPC, the :path naming the
// method. A received request keeps them exactly as on the wire, since Go would
// re-escape characters such as "|" that browsers send unencoded. An empty query
// is dropped: clients differ on sending "/a?" or "/a".
func RequestTarget(r *http.Request) string {
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
