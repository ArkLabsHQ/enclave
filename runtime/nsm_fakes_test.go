package runtime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
	"github.com/stretchr/testify/require"
)

// Doubles shared by the runtime tests. One that holds a map or channel either
// works from its zero value or is built with its newX constructor.

type signedAttestation struct {
	doc    []byte
	docB64 string
	roots  *x509.CertPool
}

// fakeNSM stands in for the Nitro Security Module and the AWS Nitro PKI behind
// it: documents it attests chain to roots, and VerifyAttestationSig trusts them.
// A struct literal has no PKI; build one with newFakeNSM to attest.
type fakeNSM struct {
	t       *testing.T
	caDER   []byte
	leafDER []byte
	leafKey *ecdsa.PrivateKey
	roots   *x509.CertPool

	session      *fakeNSMSession
	openErr      error
	verifyResult *nitrite.Result
	verifyErr    error
	verifyDocs   [][]byte
}

// newFakeNSM mints a fresh Nitro PKI, valid for an hour either side of now.
func newFakeNSM(t *testing.T) *fakeNSM {
	t.Helper()
	now := time.Now()
	return newFakeNSMValid(t, now.Add(-time.Hour), now.Add(time.Hour))
}

// newFakeNSMValid mints a Nitro PKI valid only between notBefore and notAfter.
func newFakeNSMValid(t *testing.T, notBefore, notAfter time.Time) *fakeNSM {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), cryptorand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-nitro-root"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}
	caDER, err := x509.CreateCertificate(cryptorand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), cryptorand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-nitro-leaf"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}
	leafDER, err := x509.CreateCertificate(
		cryptorand.Reader,
		leafTmpl,
		caCert,
		&leafKey.PublicKey,
		caKey,
	)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	return &fakeNSM{
		t:       t,
		caDER:   caDER,
		leafDER: leafDER,
		leafKey: leafKey,
		roots:   roots,
	}
}

// peer is another enclave on the same AWS root, as every enclave is in production.
func (f *fakeNSM) peer() *fakeNSM {
	return &fakeNSM{t: f.t, caDER: f.caDER, leafDER: f.leafDER, leafKey: f.leafKey, roots: f.roots}
}

// withPCRs gives f a stateful session measuring pcrs that signs with f's PKI.
func (f *fakeNSM) withPCRs(pcrs map[uint][]byte) *fakeNSM {
	f.session = &fakeNSMSession{
		nsm:              f,
		pcrs:             clonePCRs(pcrs),
		locks:            map[uint]bool{},
		attestationRoots: x509.NewCertPool(),
	}
	return f
}

// attest signs a document as this NSM would.
func (f *fakeNSM) attest(
	pcrs map[uint][]byte,
	timestamp time.Time,
	userData []byte,
	publicKey ...[]byte,
) signedAttestation {
	f.t.Helper()
	return f.attestWithNonce(pcrs, timestamp, userData, nil, publicKey...)
}

func (f *fakeNSM) attestWithNonce(
	pcrs map[uint][]byte,
	timestamp time.Time,
	userData []byte,
	nonce []byte,
	publicKey ...[]byte,
) signedAttestation {
	f.t.Helper()

	document := &nitrite.Document{
		ModuleID:    "test-module",
		Timestamp:   uint64(timestamp.UnixMilli()),
		Digest:      "SHA384",
		PCRs:        pcrs,
		Certificate: f.leafDER,
		CABundle:    [][]byte{f.caDER},
		UserData:    userData,
		Nonce:       nonce,
	}
	if len(publicKey) > 0 {
		document.PublicKey = publicKey[0]
	}

	payload, err := cbor.Marshal(document)
	require.NoError(f.t, err)

	doc := coseSign1(f.t, payload, f.leafKey)

	return signedAttestation{
		doc:    doc,
		docB64: base64.StdEncoding.EncodeToString(doc),
		roots:  f.roots,
	}
}

// forge returns a document that no root signed.
func (f *fakeNSM) forge(pcrs map[uint][]byte, publicKey []byte) []byte {
	f.t.Helper()
	payload, err := cbor.Marshal(&nitrite.Document{
		ModuleID:    "forged",
		Timestamp:   uint64(time.Now().UnixMilli()),
		Digest:      "SHA384",
		PCRs:        pcrs,
		Certificate: make([]byte, 64),
		CABundle:    [][]byte{make([]byte, 64)},
		PublicKey:   publicKey,
	})
	require.NoError(f.t, err)

	out, err := cbor.Marshal(&coseEnvelope{
		Protected:   coseProtectedHeader(f.t),
		Unprotected: cbor.RawMessage{0xa0},
		Payload:     payload,
		Signature:   make([]byte, 96),
	})
	require.NoError(f.t, err)
	return out
}

func (f *fakeNSM) OpenSession() (nsmSession, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	if f.session == nil {
		f.session = &fakeNSMSession{}
	}
	return f.session, nil
}

func (f *fakeNSM) VerifyAttestationSig(doc []byte) (*nitrite.Result, error) {
	f.verifyDocs = append(f.verifyDocs, append([]byte(nil), doc...))
	if f.verifyErr != nil || f.verifyResult != nil {
		return f.verifyResult, f.verifyErr
	}
	if f.roots != nil {
		return (&awsNSM{roots: f.roots}).VerifyAttestationSig(doc)
	}
	return f.verifyResult, f.verifyErr
}

func coseSign1(t *testing.T, payload []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	protected := coseProtectedHeader(t)

	sigStruct, err := cbor.Marshal(&struct {
		_           struct{} `cbor:",toarray"`
		Context     string
		Protected   []byte
		ExternalAAD []byte
		Payload     []byte
	}{
		Context:     "Signature1",
		Protected:   protected,
		ExternalAAD: []byte{},
		Payload:     payload,
	})
	require.NoError(t, err)

	digest := sha512.Sum384(sigStruct)
	r, s, err := ecdsa.Sign(cryptorand.Reader, key, digest[:])
	require.NoError(t, err)
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])

	out, err := cbor.Marshal(&coseEnvelope{
		Protected:   protected,
		Unprotected: cbor.RawMessage{0xa0},
		Payload:     payload,
		Signature:   sig,
	})
	require.NoError(t, err)
	return out
}

type coseEnvelope struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

func coseProtectedHeader(t *testing.T) []byte {
	t.Helper()
	h, err := cbor.Marshal(struct {
		Alg int64 `cbor:"1,keyasint"`
	}{Alg: -35})
	require.NoError(t, err)
	return h
}

type fakeNSMSession struct {
	readBytes []byte
	readErr   error
	readCalls int

	responses []response.Response
	sendErr   error
	sendFunc  func(request.Request) (response.Response, error)
	requests  []request.Request

	nsm              *fakeNSM
	pcrs             map[uint][]byte
	locks            map[uint]bool
	attestationRoots *x509.CertPool

	closed bool
}

func (f *fakeNSMSession) Read(p []byte) (int, error) {
	f.readCalls++
	if f.readErr != nil {
		return 0, f.readErr
	}
	if len(f.readBytes) > 0 {
		n := copy(p, f.readBytes)
		f.readBytes = f.readBytes[n:]
		return n, nil
	}
	return cryptorand.Read(p)
}

func (f *fakeNSMSession) Send(req request.Request) (response.Response, error) {
	f.requests = append(f.requests, req)
	if f.sendErr != nil {
		return response.Response{}, f.sendErr
	}
	if f.sendFunc != nil {
		return f.sendFunc(req)
	}
	if len(f.responses) == 0 {
		if f.pcrs != nil {
			return f.sendStateful(req)
		}
		return response.Response{}, nil
	}
	res := f.responses[0]
	f.responses = f.responses[1:]
	return res, nil
}

func (f *fakeNSMSession) sendStateful(req request.Request) (response.Response, error) {
	switch r := req.(type) {
	case *request.DescribePCR:
		index := uint(r.Index)
		return response.Response{DescribePCR: &response.DescribePCR{
			Data: f.currentPCR(index),
			Lock: f.locks[index],
		}}, nil
	case *request.ExtendPCR:
		index := uint(r.Index)
		if f.locks[index] {
			return response.Response{Error: "PCR is locked"}, nil
		}
		cur := f.currentPCR(index)
		h := sha512.Sum384(append(cur, r.Data...))
		f.pcrs[index] = append([]byte(nil), h[:]...)
		return response.Response{ExtendPCR: &response.ExtendPCR{Data: f.currentPCR(index)}}, nil
	case *request.LockPCR:
		if f.locks == nil {
			f.locks = map[uint]bool{}
		}
		f.locks[uint(r.Index)] = true
		return response.Response{LockPCR: &response.LockPCR{}}, nil
	case *request.Attestation:
		if f.nsm == nil {
			return response.Response{}, errors.New("stateful fake NSM session has no NSM")
		}
		// The nonce must survive into the document: it is the only freshness signal
		// a verifier has, so a fake that dropped it would make replay untestable.
		att := f.nsm.attestWithNonce(
			clonePCRs(f.pcrs), time.Now(), r.UserData, r.Nonce, r.PublicKey,
		)
		f.attestationRoots = att.roots
		return attestationDocumentResponse(att.doc), nil
	default:
		return response.Response{}, nil
	}
}

func (f *fakeNSMSession) currentPCR(index uint) []byte {
	if pcr, ok := f.pcrs[index]; ok {
		return append([]byte(nil), pcr...)
	}
	return make([]byte, 48)
}

func (f *fakeNSMSession) Close() error {
	f.closed = true
	return nil
}

func verifyDocResult(pcrs map[uint][]byte, userData []byte) *nitrite.Result {
	return &nitrite.Result{Document: &nitrite.Document{PCRs: pcrs, UserData: userData}}
}

func clonePCRs(pcrs map[uint][]byte) map[uint][]byte {
	out := make(map[uint][]byte, len(pcrs))
	for index, pcr := range pcrs {
		out[index] = append([]byte(nil), pcr...)
	}
	return out
}

func attestationDocumentResponse(doc []byte) response.Response {
	return response.Response{Attestation: &response.Attestation{Document: doc}}
}
