package nitriding

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Local additions (not from upstream). Keep upstream-vendored files
// byte-identical by defining our extensions here.

// SetAttestationKeyHash registers the SHA-256 hash of the enclave
// application's attestation key. Upstream exposes this only via the
// POST /enclave/hash HTTP handler (see hashHandler in handlers.go); we
// call it directly from the in-process runtime to skip the HTTP round-trip.
func (e *Enclave) SetAttestationKeyHash(hash [32]byte) {
	copy(e.hashes.appKeyHash[:], hash[:])
}

// PubMux returns the public-facing chi router so the in-process runtime
// can register its own management routes on the same listener (port 443
// via TLS) instead of spinning up a second http.Server. Eliminating the
// runtime's :7073 listener removes one reverse-proxy hop and one
// middleware stack — both of which were breaking HTTP/2 streaming RPCs.
func (e *Enclave) PubMux() *chi.Mux {
	return e.pubSrv.Handler.(*chi.Mux)
}

// UseMiddleware wraps the public-facing chi router with a standard
// http.Handler middleware. Wrapping at pubSrv.Handler (rather than via
// chi.Use) applies the middleware to every route on the mux, including
// those registered before this call. Use this to attach the runtime's
// response-signing Middleware once, instead of wrapping it around a
// downstream proxy hop.
func (e *Enclave) UseMiddleware(mw func(http.Handler) http.Handler) {
	e.pubSrv.Handler = mw(e.pubSrv.Handler)
}

// AppWebSrvAddr returns the URL that PubMux's catch-all reverse-proxy
// dials. Used by tests; production callers should set it via
// nitriding.Config.AppWebSrv when constructing the Enclave.
func (e *Enclave) AppWebSrvAddr() string {
	if e.cfg.AppWebSrv == nil {
		return ""
	}
	return e.cfg.AppWebSrv.String()
}
