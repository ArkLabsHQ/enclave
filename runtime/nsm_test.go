package runtime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
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

func TestAWSNSMVerifyAttestationSig(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0xab}, 48)

	t.Run("signed trusted doc", func(t *testing.T) {
		att := buildSignedAttestation(t, map[uint][]byte{0: pcr0})

		res, err := (&awsNSM{roots: att.roots}).VerifyAttestationSig(att.doc)

		require.NoError(t, err)
		require.True(t, res.SignatureOK)
		require.Equal(t, pcr0, res.Document.PCRs[0])
	})

	t.Run("forged doc", func(t *testing.T) {
		_, err := (&awsNSM{}).VerifyAttestationSig(
			buildForgedAttestation(t, map[uint][]byte{0: pcr0}),
		)

		require.Error(t, err)
	})

	t.Run("signed doc with untrusted root", func(t *testing.T) {
		att := buildSignedAttestation(t, map[uint][]byte{0: pcr0})
		other := buildSignedAttestation(t, map[uint][]byte{0: pcr0})

		_, err := (&awsNSM{roots: other.roots}).VerifyAttestationSig(att.doc)

		require.Error(t, err)
	})

	t.Run("cert expired now but valid at attestation timestamp", func(t *testing.T) {
		now := time.Now()
		att := buildSignedAttestationCustom(t, map[uint][]byte{0: pcr0},
			now.Add(-3*time.Hour), now.Add(-time.Hour), now.Add(-2*time.Hour), nil)

		_, err := (&awsNSM{roots: att.roots}).VerifyAttestationSig(att.doc)

		require.NoError(t, err)
	})

	t.Run("unsigned mode parses forged doc", func(t *testing.T) {
		res, err := (&awsNSM{unsigned: true}).VerifyAttestationSig(
			buildForgedAttestation(t, map[uint][]byte{0: pcr0}),
		)

		require.NoError(t, err)
		require.False(t, res.SignatureOK)
		require.Equal(t, pcr0, res.Document.PCRs[0])
	})
}

func TestNSMVerifyAttestation(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	userData := []byte("expected user data")
	doc := []byte("attestation doc")
	docB64 := base64.StdEncoding.EncodeToString(doc)

	t.Run("bad base64", func(t *testing.T) {
		fake := &fakeNSM{}
		nsm := &nsmW{nsm: fake}

		err := nsm.VerifyAttestation("not base64", map[uint]string{}, nil)

		require.Error(t, err)
		require.Empty(t, fake.verifyDocs)
	})

	t.Run("verifier error", func(t *testing.T) {
		fake := &fakeNSM{verifyErr: errors.New("verify failed")}
		nsm := &nsmW{nsm: fake}

		err := nsm.VerifyAttestation(docB64, map[uint]string{}, nil)

		require.Error(t, err)
		require.Equal(t, [][]byte{doc}, fake.verifyDocs)
	})

	t.Run("PCR match and user_data match", func(t *testing.T) {
		fake := &fakeNSM{verifyResult: attestationResult(map[uint][]byte{0: pcr0}, userData)}
		nsm := &nsmW{nsm: fake}

		err := nsm.VerifyAttestation(docB64, map[uint]string{0: hex.EncodeToString(pcr0)}, userData)

		require.NoError(t, err)
	})

	t.Run("missing PCR", func(t *testing.T) {
		fake := &fakeNSM{verifyResult: attestationResult(map[uint][]byte{1: pcr0}, userData)}
		nsm := &nsmW{nsm: fake}

		err := nsm.VerifyAttestation(docB64, map[uint]string{0: hex.EncodeToString(pcr0)}, userData)

		require.Error(t, err)
	})

	t.Run("PCR mismatch", func(t *testing.T) {
		fake := &fakeNSM{verifyResult: attestationResult(map[uint][]byte{0: pcr0}, userData)}
		nsm := &nsmW{nsm: fake}

		err := nsm.VerifyAttestation(
			docB64,
			map[uint]string{0: hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 48))},
			userData,
		)

		require.Error(t, err)
	})

	t.Run("user_data mismatch", func(t *testing.T) {
		fake := &fakeNSM{verifyResult: attestationResult(map[uint][]byte{0: pcr0}, userData)}
		nsm := &nsmW{nsm: fake}

		err := nsm.VerifyAttestation(
			docB64,
			map[uint]string{0: hex.EncodeToString(pcr0)},
			[]byte("wrong"),
		)

		require.Error(t, err)
	})
}

func TestBuildAttestationDocument(t *testing.T) {
	doc := []byte("attestation doc")
	attestationResponse := response.Response{Attestation: &response.Attestation{Document: doc}}

	t.Run("default call sends generated 32-byte nonce", func(t *testing.T) {
		nonce := bytes.Repeat([]byte{0x42}, 32)
		session := &fakeNSMSession{
			readBytes: nonce,
			responses: []response.Response{attestationResponse},
		}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		got, key, err := nsm.BuildAttestationDocument()

		require.NoError(t, err)
		require.Nil(t, key)
		require.Equal(t, doc, got)
		require.Len(t, session.requests, 1)
		req, ok := session.requests[0].(*request.Attestation)
		require.True(t, ok)
		require.Equal(t, nonce, req.Nonce)
		require.Empty(t, req.UserData)
		require.Empty(t, req.PublicKey)
		require.True(t, session.closed)
	})

	t.Run("WithNonce sends exact nonce", func(t *testing.T) {
		nonce := []byte("caller nonce")
		session := &fakeNSMSession{responses: []response.Response{attestationResponse}}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		_, _, err := nsm.BuildAttestationDocument(WithNonce(nonce))

		require.NoError(t, err)
		req, ok := session.requests[0].(*request.Attestation)
		require.True(t, ok)
		require.Equal(t, nonce, req.Nonce)
		require.Zero(t, session.readCalls)
	})

	t.Run("WithUserData sends exact user_data", func(t *testing.T) {
		userData := []byte("bound data")
		session := &fakeNSMSession{responses: []response.Response{attestationResponse}}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		_, _, err := nsm.BuildAttestationDocument(
			WithNonce([]byte("nonce")),
			WithUserData(userData),
		)

		require.NoError(t, err)
		req, ok := session.requests[0].(*request.Attestation)
		require.True(t, ok)
		require.Equal(t, userData, req.UserData)
	})

	t.Run("WithPublicKey returns RSA private key and sends public key", func(t *testing.T) {
		session := &fakeNSMSession{responses: []response.Response{attestationResponse}}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		_, key, err := nsm.BuildAttestationDocument(WithPublicKey(), WithNonce([]byte("nonce")))

		require.NoError(t, err)
		require.NotNil(t, key)
		req, ok := session.requests[0].(*request.Attestation)
		require.True(t, ok)
		require.NotEmpty(t, req.PublicKey)
		pub, err := x509.ParsePKIXPublicKey(req.PublicKey)
		require.NoError(t, err)
		parsedPub, ok := pub.(*rsa.PublicKey)
		require.True(t, ok)
		require.Equal(t, &key.PublicKey, parsedPub)
	})

	t.Run("session open error", func(t *testing.T) {
		nsm := &nsmW{nsm: &fakeNSM{openErr: errors.New("open failed")}}

		_, _, err := nsm.BuildAttestationDocument()

		require.Error(t, err)
	})

	t.Run("session read error", func(t *testing.T) {
		session := &fakeNSMSession{readErr: errors.New("read failed")}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		_, _, err := nsm.BuildAttestationDocument()

		require.Error(t, err)
	})

	t.Run("session send error", func(t *testing.T) {
		session := &fakeNSMSession{sendErr: errors.New("send failed")}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		_, _, err := nsm.BuildAttestationDocument(WithNonce([]byte("nonce")))

		require.Error(t, err)
	})

	t.Run("missing attestation document", func(t *testing.T) {
		session := &fakeNSMSession{responses: []response.Response{{}}}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		_, _, err := nsm.BuildAttestationDocument(WithNonce([]byte("nonce")))

		require.Error(t, err)
	})
}

func TestPCR0(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	nonce := bytes.Repeat([]byte{0x42}, 32)

	t.Run("returns raw PCR0 bytes", func(t *testing.T) {
		session := &fakeNSMSession{
			readBytes: nonce,
			responses: []response.Response{attestationDocumentResponse(
				buildForgedAttestation(t, map[uint][]byte{0: pcr0}),
			)},
		}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		got, err := nsm.PCR0()

		require.NoError(t, err)
		require.Equal(t, pcr0, got)
	})

	t.Run("missing PCR0", func(t *testing.T) {
		session := &fakeNSMSession{
			readBytes: nonce,
			responses: []response.Response{attestationDocumentResponse(
				buildForgedAttestation(t, map[uint][]byte{1: pcr0}),
			)},
		}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		_, err := nsm.PCR0()

		require.Error(t, err)
	})

	t.Run("malformed COSE", func(t *testing.T) {
		session := &fakeNSMSession{
			readBytes: nonce,
			responses: []response.Response{attestationDocumentResponse([]byte("nope"))},
		}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		_, err := nsm.PCR0()

		require.Error(t, err)
	})
}

func TestPCRMethods(t *testing.T) {
	t.Run("LockPCR sends request.LockPCR", func(t *testing.T) {
		session := &fakeNSMSession{responses: []response.Response{{LockPCR: &response.LockPCR{}}}}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		err := nsm.LockPCR(7)

		require.NoError(t, err)
		require.Len(t, session.requests, 1)
		req, ok := session.requests[0].(*request.LockPCR)
		require.True(t, ok)
		require.Equal(t, uint16(7), req.Index)
	})

	t.Run("ExtendPCR sends request.ExtendPCR", func(t *testing.T) {
		data := []byte("extension")
		session := &fakeNSMSession{
			responses: []response.Response{
				{ExtendPCR: &response.ExtendPCR{Data: pcrExtendFromZero(data)}},
			},
		}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		err := nsm.ExtendPCR(8, data)

		require.NoError(t, err)
		require.Len(t, session.requests, 1)
		req, ok := session.requests[0].(*request.ExtendPCR)
		require.True(t, ok)
		require.Equal(t, uint16(8), req.Index)
		require.Equal(t, data, req.Data)
	})

	t.Run("DescribePCR returns data and locked", func(t *testing.T) {
		data := bytes.Repeat([]byte{0xcd}, 48)
		extended := pcrExtendFromZero(data)
		session := &fakeNSMSession{
			responses: []response.Response{
				{DescribePCR: &response.DescribePCR{Data: extended, Lock: true}},
			},
		}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		got, locked, err := nsm.DescribePCR(9)

		require.NoError(t, err)
		require.True(t, locked)
		require.Equal(t, extended, got)
		req, ok := session.requests[0].(*request.DescribePCR)
		require.True(t, ok)
		require.Equal(t, uint16(9), req.Index)
	})
}

func TestCommitPCR(t *testing.T) {
	data := bytes.Repeat([]byte{0xaa}, 48)
	extended := pcrExtendFromZero(data)
	zero := make([]byte, 48)

	t.Run("zero current PCR extends then locks", func(t *testing.T) {
		session := &fakeNSMSession{responses: []response.Response{
			{DescribePCR: &response.DescribePCR{Data: zero, Lock: false}},
			{ExtendPCR: &response.ExtendPCR{Data: extended}},
			{LockPCR: &response.LockPCR{}},
		}}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		err := nsm.CommitPCR(31, data)

		require.NoError(t, err)
		require.Len(t, session.requests, 3)
		describe, ok := session.requests[0].(*request.DescribePCR)
		require.True(t, ok)
		require.Equal(t, uint16(31), describe.Index)
		extend, ok := session.requests[1].(*request.ExtendPCR)
		require.True(t, ok)
		require.Equal(t, uint16(31), extend.Index)
		require.Equal(t, data, extend.Data)
		lock, ok := session.requests[2].(*request.LockPCR)
		require.True(t, ok)
		require.Equal(t, uint16(31), lock.Index)
	})

	t.Run("already equal and unlocked locks only", func(t *testing.T) {
		session := &fakeNSMSession{responses: []response.Response{
			{DescribePCR: &response.DescribePCR{Data: extended, Lock: false}},
			{LockPCR: &response.LockPCR{}},
		}}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		err := nsm.CommitPCR(31, data)

		require.NoError(t, err)
		require.Len(t, session.requests, 2)
		describe, ok := session.requests[0].(*request.DescribePCR)
		require.True(t, ok)
		require.Equal(t, uint16(31), describe.Index)
		lock, ok := session.requests[1].(*request.LockPCR)
		require.True(t, ok)
		require.Equal(t, uint16(31), lock.Index)
	})

	t.Run("already equal and locked no-op", func(t *testing.T) {
		session := &fakeNSMSession{responses: []response.Response{
			{DescribePCR: &response.DescribePCR{Data: extended, Lock: true}},
		}}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		err := nsm.CommitPCR(31, data)

		require.NoError(t, err)
		require.Len(t, session.requests, 1)
		describe, ok := session.requests[0].(*request.DescribePCR)
		require.True(t, ok)
		require.Equal(t, uint16(31), describe.Index)
	})

	t.Run("unexpected current PCR errors", func(t *testing.T) {
		session := &fakeNSMSession{responses: []response.Response{
			{DescribePCR: &response.DescribePCR{
				Data: pcrExtendFromZero(bytes.Repeat([]byte{0xbb}, 48)),
				Lock: false,
			}},
		}}
		nsm := &nsmW{nsm: &fakeNSM{session: session}}

		err := nsm.CommitPCR(31, data)

		require.Error(t, err)
		require.Len(t, session.requests, 1)
		describe, ok := session.requests[0].(*request.DescribePCR)
		require.True(t, ok)
		require.Equal(t, uint16(31), describe.Index)
	})
}

type signedAttestation struct {
	doc    []byte
	docB64 string
	roots  *x509.CertPool
}

func buildSignedAttestation(t *testing.T, pcrs map[uint][]byte) signedAttestation {
	t.Helper()
	now := time.Now()
	return buildSignedAttestationCustom(t, pcrs, now.Add(-time.Hour), now.Add(time.Hour), now, nil)
}

func buildSignedAttestationCustom(
	t *testing.T,
	pcrs map[uint][]byte,
	certNotBefore, certNotAfter, timestamp time.Time,
	userData []byte,
	publicKey ...[]byte,
) signedAttestation {
	t.Helper()
	return newTestAttestationSigner(t, certNotBefore, certNotAfter).
		build(t, pcrs, timestamp, userData, publicKey...)
}

type testAttestationSigner struct {
	caDER   []byte
	leafDER []byte
	leafKey *ecdsa.PrivateKey
	roots   *x509.CertPool
}

func newTestAttestationSigner(
	t *testing.T,
	certNotBefore, certNotAfter time.Time,
) *testAttestationSigner {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), cryptorand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-nitro-root"},
		NotBefore:             certNotBefore,
		NotAfter:              certNotAfter,
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
		NotBefore:             certNotBefore,
		NotAfter:              certNotAfter,
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

	return &testAttestationSigner{
		caDER:   caDER,
		leafDER: leafDER,
		leafKey: leafKey,
		roots:   roots,
	}
}

func (s *testAttestationSigner) build(
	t *testing.T,
	pcrs map[uint][]byte,
	timestamp time.Time,
	userData []byte,
	publicKey ...[]byte,
) signedAttestation {
	t.Helper()

	document := &nitrite.Document{
		ModuleID:    "test-module",
		Timestamp:   uint64(timestamp.UnixMilli()),
		Digest:      "SHA384",
		PCRs:        pcrs,
		Certificate: s.leafDER,
		CABundle:    [][]byte{s.caDER},
		UserData:    userData,
	}
	if len(publicKey) > 0 {
		document.PublicKey = publicKey[0]
	}

	payload, err := cbor.Marshal(document)
	require.NoError(t, err)

	doc := coseSign1(t, payload, s.leafKey)

	return signedAttestation{
		doc:    doc,
		docB64: base64.StdEncoding.EncodeToString(doc),
		roots:  s.roots,
	}
}

func buildForgedAttestation(t *testing.T, pcrs map[uint][]byte) []byte {
	return buildForgedAttestationWithPublicKey(t, pcrs, nil)
}

func buildForgedAttestationWithPublicKey(
	t *testing.T,
	pcrs map[uint][]byte,
	publicKey []byte,
) []byte {
	t.Helper()
	payload, err := cbor.Marshal(&nitrite.Document{
		ModuleID:    "forged",
		Timestamp:   uint64(time.Now().UnixMilli()),
		Digest:      "SHA384",
		PCRs:        pcrs,
		Certificate: make([]byte, 64),
		CABundle:    [][]byte{make([]byte, 64)},
		PublicKey:   publicKey,
	})
	require.NoError(t, err)

	out, err := cbor.Marshal(&coseEnvelope{
		Protected:   coseProtectedHeader(t),
		Unprotected: cbor.RawMessage{0xa0},
		Payload:     payload,
		Signature:   make([]byte, 96),
	})
	require.NoError(t, err)
	return out
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

type fakeNSM struct {
	session      nsmSession
	openErr      error
	verifyResult *nitrite.Result
	verifyErr    error
	verifyDocs   [][]byte
	verifyRoots  *x509.CertPool
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
	if f.verifyRoots != nil {
		return (&awsNSM{roots: f.verifyRoots}).VerifyAttestationSig(doc)
	}
	return f.verifyResult, f.verifyErr
}

type fakeNSMSession struct {
	readBytes []byte
	readErr   error
	readCalls int

	responses []response.Response
	sendErr   error
	sendFunc  func(request.Request) (response.Response, error)
	requests  []request.Request

	t                *testing.T
	pcrs             map[uint][]byte
	locks            map[uint]bool
	attestationSign  *testAttestationSigner
	attestationRoots *x509.CertPool

	closed bool
}

func newStatefulNSMSession(t *testing.T, pcrs map[uint][]byte) *fakeNSMSession {
	t.Helper()
	now := time.Now()
	return &fakeNSMSession{
		t:                t,
		pcrs:             clonePCRs(pcrs),
		locks:            map[uint]bool{},
		attestationSign:  newTestAttestationSigner(t, now.Add(-time.Hour), now.Add(time.Hour)),
		attestationRoots: x509.NewCertPool(),
	}
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
		if f.t == nil {
			return response.Response{}, errors.New("stateful fake NSM session missing testing.T")
		}
		if f.attestationSign == nil {
			now := time.Now()
			f.attestationSign = newTestAttestationSigner(
				f.t, now.Add(-time.Hour), now.Add(time.Hour),
			)
		}
		att := buildSignedAttestationForRequest(f.t, f.attestationSign, clonePCRs(f.pcrs), r)
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

func attestationResult(pcrs map[uint][]byte, userData []byte) *nitrite.Result {
	return &nitrite.Result{Document: &nitrite.Document{PCRs: pcrs, UserData: userData}}
}

func buildSignedAttestationForRequest(
	t *testing.T,
	signer *testAttestationSigner,
	pcrs map[uint][]byte,
	req *request.Attestation,
) signedAttestation {
	t.Helper()
	return signer.build(
		t,
		pcrs,
		time.Now(),
		req.UserData,
		req.PublicKey,
	)
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
