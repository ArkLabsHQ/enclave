package nitriding

import (
	"testing"
)

func TestArePCRsIdentical(t *testing.T) {
	pcr1 := map[uint][]byte{
		1: []byte("foobar"),
	}
	pcr2 := map[uint][]byte{
		1: []byte("foobar"),
	}
	if !arePCRsIdentical(pcr1, pcr2) {
		t.Fatal("Failed to recognize identical PCRs as such.")
	}

	// Add a new PCR value, so our two maps are no longer identical.
	pcr1[2] = []byte("barfoo")
	if arePCRsIdentical(pcr1, pcr2) {
		t.Fatal("Failed to recognize different PCRs as such.")
	}

	// Add the same PCR ID but with a different value.
	pcr2[2] = []byte("foobar")
	if arePCRsIdentical(pcr1, pcr2) {
		t.Fatal("Failed to recognize different PCRs as such.")
	}
}

// TestAttestationHashes used to live here but exercised the deleted
// nitriding.Enclave struct. The /enclave/{attestation,hash} flow is now
// owned by *runtime.Runtime — see runtime/server_handlers.go. A focused
// replacement test against *Runtime can be added in a follow-up.
