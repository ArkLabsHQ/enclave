package cli

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// fakeAttestation builds a skip-sig-parseable COSE Sign1 doc with the given PCRs and
// user_data (no real signature — for the dev/skip path only).
func fakeAttestation(t *testing.T, pcrs map[uint][]byte, userData []byte) string {
	t.Helper()
	payload, err := cbor.Marshal(map[string]any{"pcrs": pcrs, "user_data": userData})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	cose := make([]cbor.RawMessage, 4)
	cose[0], _ = cbor.Marshal([]byte{})
	cose[1], _ = cbor.Marshal(map[int]int{})
	cose[2], _ = cbor.Marshal(payload) // payload as a CBOR byte string
	cose[3], _ = cbor.Marshal([]byte{})
	raw, err := cbor.Marshal(cose)
	if err != nil {
		t.Fatalf("marshal cose: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func genesisEntryFor(t *testing.T, d deploymentDescriptor) (map[string]lineageEntryV1, []byte) {
	t.Helper()
	descBytes, err := cbor.Marshal(d)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	h := sha256.Sum256(descBytes)
	att := fakeAttestation(t, map[uint][]byte{0: {0xaa}}, h[:])
	entries := map[string]lineageEntryV1{
		strings.ToLower(d.GenesisPCR0): {
			Schema: lineageSchemaV1, Purpose: lineagePurposeGenesis,
			SelfPCR0: d.GenesisPCR0, SelfAttestation: att, Descriptor: descBytes,
		},
	}
	return entries, descBytes
}

func TestVerifyGenesisDescriptor(t *testing.T) {
	d := deploymentDescriptor{
		Schema: "enclave.deployment_descriptor.v1", Deployment: "prod", App: "my-app",
		Region: "us-east-1", GenesisPCR0: "aabbcc", AnchorBucket: "anc", LineageBucket: "lin",
	}

	t.Run("genesis-attested descriptor verifies", func(t *testing.T) {
		entries, _ := genesisEntryFor(t, d)
		if err := verifyGenesisDescriptor(entries, d.GenesisPCR0, &d, true); err != nil {
			t.Fatalf("expected pass, got %v", err)
		}
	})

	t.Run("a tampered pinned descriptor is rejected", func(t *testing.T) {
		entries, _ := genesisEntryFor(t, d)
		bad := d
		bad.AnchorBucket = "evil-fork-bucket"
		if err := verifyGenesisDescriptor(entries, d.GenesisPCR0, &bad, true); err == nil {
			t.Fatal("expected rejection of mismatched descriptor")
		}
	})

	t.Run("user_data not bound to the descriptor is rejected", func(t *testing.T) {
		entries, _ := genesisEntryFor(t, d)
		// Re-sign with a user_data that is NOT sha256(descriptor).
		e := entries[strings.ToLower(d.GenesisPCR0)]
		e.SelfAttestation = fakeAttestation(t, map[uint][]byte{0: {0xaa}}, []byte("wrong"))
		entries[strings.ToLower(d.GenesisPCR0)] = e
		if err := verifyGenesisDescriptor(entries, d.GenesisPCR0, &d, true); err == nil {
			t.Fatal("expected rejection when user_data != sha256(descriptor)")
		}
	})

	t.Run("missing descriptor is rejected", func(t *testing.T) {
		entries, _ := genesisEntryFor(t, d)
		e := entries[strings.ToLower(d.GenesisPCR0)]
		e.Descriptor = nil
		entries[strings.ToLower(d.GenesisPCR0)] = e
		if err := verifyGenesisDescriptor(entries, d.GenesisPCR0, &d, true); err == nil {
			t.Fatal("expected rejection when genesis entry has no descriptor")
		}
	})
}
