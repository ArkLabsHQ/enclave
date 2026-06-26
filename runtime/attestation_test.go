package runtime

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestAttestationHashesSerialize(t *testing.T) {
	var h AttestationHashes
	for i := range h.tlsKeyHash {
		h.tlsKeyHash[i] = byte(i)
	}
	for i := range h.appKeyHash {
		h.appKeyHash[i] = byte(i + 1)
	}

	got := h.Serialize()

	wantLen := sha256.Size*2 + len(hashPrefix)*2 + len(hashSeparator)
	if len(got) != wantLen {
		t.Fatalf("serialized length: got %d, want %d", len(got), wantLen)
	}

	if !bytes.HasPrefix(got, []byte(hashPrefix)) {
		t.Fatalf("missing leading hash prefix: got %q", got[:len(hashPrefix)])
	}
	if !strings.Contains(string(got), hashSeparator+hashPrefix) {
		t.Fatalf("missing separator + second prefix in %q", got)
	}

	tlsStart := len(hashPrefix)
	tlsEnd := tlsStart + sha256.Size
	if !bytes.Equal(got[tlsStart:tlsEnd], h.tlsKeyHash[:]) {
		t.Fatalf("tlsKeyHash bytes: got %x, want %x", got[tlsStart:tlsEnd], h.tlsKeyHash[:])
	}

	appStart := tlsEnd + len(hashSeparator) + len(hashPrefix)
	if !bytes.Equal(got[appStart:], h.appKeyHash[:]) {
		t.Fatalf("appKeyHash bytes: got %x, want %x", got[appStart:], h.appKeyHash[:])
	}
}

// A loaded attestation key reports ready, exposes a compressed pubkey, and
// produces a working response signature.
func TestAttestation_KeyReadyAndSigns(t *testing.T) {
	a := &Attestation{}
	if a.Ready() || a.Pubkey() != "" {
		t.Fatal("empty Attestation should not be ready")
	}
	seed := make([]byte, 32)
	seed[31] = 7
	a.key, _ = btcec.PrivKeyFromBytes(seed)
	if !a.Ready() || len(a.Pubkey()) != 66 {
		t.Fatalf("loaded key: ready=%v pubkeyLen=%d", a.Ready(), len(a.Pubkey()))
	}
	if a.Sign([]byte("hello")) == "" {
		t.Fatal("the attestation key must sign HTTP responses")
	}
}

func TestAttestationHashesSerializeZeroValue(t *testing.T) {
	var h AttestationHashes
	got := h.Serialize()

	wantLen := sha256.Size*2 + len(hashPrefix)*2 + len(hashSeparator)
	if len(got) != wantLen {
		t.Fatalf("zero-value length: got %d, want %d", len(got), wantLen)
	}
	zero := make([]byte, sha256.Size)
	tlsStart := len(hashPrefix)
	if !bytes.Equal(got[tlsStart:tlsStart+sha256.Size], zero) {
		t.Fatalf("zero-value tlsKeyHash should be all zeros, got %x", got[tlsStart:tlsStart+sha256.Size])
	}
}
