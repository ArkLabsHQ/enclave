package nitriding

// Local additions (not from upstream). Keep upstream-vendored files
// byte-identical by defining our extensions here.

// SetAttestationKeyHash registers the SHA-256 hash of the enclave
// application's attestation key. Upstream exposes this only via the
// POST /enclave/hash HTTP handler (see hashHandler in handlers.go); we
// call it directly from the in-process runtime to skip the HTTP round-trip.
func (e *Enclave) SetAttestationKeyHash(hash [32]byte) {
	copy(e.hashes.appKeyHash[:], hash[:])
}
