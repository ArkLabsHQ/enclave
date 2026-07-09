package nitriding

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

const (
	nonceLen       = 20           // The size of a nonce in bytes.
	nonceNumDigits = nonceLen * 2 // The number of hex digits in a nonce.
	maxAttDocLen   = 5000         // A (reasonable?) upper limit for attestation doc lengths.
	hashPrefix     = "sha256:"
	hashSeparator  = ";"
)

var (
	errBadForm           = "failed to parse POST form data"
	errNoNonce           = "could not find nonce in URL query parameters"
	errBadNonceFormat    = fmt.Sprintf("unexpected nonce format; must be %d-digit hex string", nonceNumDigits)
	errFailedAttestation = "failed to obtain attestation document from hypervisor"
	errProfilingSet      = "attestation disabled because profiling is enabled"

	// getPCRValues is a variable pointing to a function that returns PCR
	// values.  Using a variable allows us to easily mock the function in our
	// unit tests.
	getPCRValues = func() (map[uint][]byte, error) { return _getPCRValues() }
)

// AttestationHashes contains hashes over public key material which we embed in
// the enclave's attestation document for clients to verify.
type AttestationHashes struct {
	tlsKeyHash [sha256.Size]byte // Always set.
	appKeyHash [sha256.Size]byte // Sometimes set, depending on application.
}

// Serialize returns a byte slice that contains our concatenated hashes.  Note
// that all hashes are always present.  If a hash was not initialized, it's set
// to 0-bytes.
func (a *AttestationHashes) Serialize() []byte {
	str := fmt.Sprintf("%s%s%s%s%s",
		hashPrefix,
		a.tlsKeyHash,
		hashSeparator,
		hashPrefix,
		a.appKeyHash)
	return []byte(str)
}

// _getPCRValues returns the enclave's platform configuration register (PCR)
// values.
func _getPCRValues() (map[uint][]byte, error) {
	rawAttDoc, err := attest(nil, nil, nil)
	if err != nil {
		return nil, err
	}

	// In dev the QEMU NSM emits unsigned mock documents, so nitrite.Verify (which
	// requires the AWS Nitro root chain) fails.
	if devMode() {
		return pcrsFromAttestationDoc(rawAttDoc)
	}

	res, err := nitrite.Verify(rawAttDoc, nitrite.VerifyOptions{})
	if err != nil {
		return nil, err
	}

	return res.Document.PCRs, nil
}

func devMode() bool {
	if v := strings.TrimSpace(os.Getenv("ENCLAVE_DEV")); v != "" {
		return strings.EqualFold(v, "true")
	}
	return strings.TrimSpace(os.Getenv("ENCLAVE_DEPLOYMENT")) == "dev"
}

func pcrsFromAttestationDoc(doc []byte) (map[uint][]byte, error) {
	var envelope struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected cbor.RawMessage
		Payload     []byte
		Signature   []byte
	}
	if err := cbor.Unmarshal(doc, &envelope); err != nil {
		return nil, fmt.Errorf("decode COSE Sign1 envelope: %w", err)
	}
	if len(envelope.Payload) == 0 {
		return nil, errors.New("COSE Sign1 payload empty")
	}
	var parsed nitrite.Document
	if err := cbor.Unmarshal(envelope.Payload, &parsed); err != nil {
		return nil, fmt.Errorf("decode attestation document: %w", err)
	}
	return parsed.PCRs, nil
}

// arePCRsIdentical returns true if (and only if) the two given PCR maps are
// identical.
func arePCRsIdentical(ourPCRs, theirPCRs map[uint][]byte) bool {
	if len(ourPCRs) != len(theirPCRs) {
		return false
	}

	for pcr, ourValue := range ourPCRs {
		theirValue, exists := theirPCRs[pcr]
		if !exists {
			return false
		}
		if !bytes.Equal(ourValue, theirValue) {
			return false
		}
	}
	return true
}

// Attest asks the NSM hypervisor for a signed attestation document
// binding the given nonce, userData, and publicKey.
func Attest(nonce, userData, publicKey []byte) ([]byte, error) {
	return attest(nonce, userData, publicKey)
}

// ArePCRsIdentical reports whether two PCR maps have the same keys and values.
func ArePCRsIdentical(ourPCRs, theirPCRs map[uint][]byte) bool {
	return arePCRsIdentical(ourPCRs, theirPCRs)
}

func ArePCRsIdenticalForKeys(ourPCRs, theirPCRs map[uint][]byte, keys []uint) bool {
	for _, k := range keys {
		ourValue, ok := ourPCRs[k]
		if !ok {
			return false
		}
		theirValue, ok := theirPCRs[k]
		if !ok {
			return false
		}
		if !bytes.Equal(ourValue, theirValue) {
			return false
		}
	}
	return true
}

// GetPCRs returns this enclave's current PCR values (from a fresh attestation).
// Used by peer-to-peer handshakes to compare a remote enclave's PCRs to our own.
func GetPCRs() (map[uint][]byte, error) {
	return getPCRValues()
}

// CurrentTime returns the clock nitrite verification should use (UTC now).
// Exposed so peer handshakes verify remote attestations against the same clock.
func CurrentTime() time.Time {
	return currentTime()
}

// attest takes as input a nonce, user-provided data and a public key, and then
// asks the Nitro hypervisor to return a signed attestation document that
// contains all three values.
func attest(nonce, userData, publicKey []byte) ([]byte, error) {
	s, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = s.Close(); err != nil {
			elog.Printf("Attestation: Failed to close default NSM session: %s", err)
		}
	}()

	res, err := s.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  userData,
		PublicKey: publicKey,
	})
	if err != nil {
		return nil, err
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("NSM device did not return an attestation")
	}

	return res.Attestation.Document, nil
}
