package runtime

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
	"github.com/stretchr/testify/require"
)

func TestAWSNSMVerifyAttestationSig(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0xab}, 48)

	t.Run("signed trusted doc", func(t *testing.T) {
		att := newFakeNSM(t).attest(map[uint][]byte{0: pcr0}, time.Now(), nil)

		res, err := (&awsNSM{roots: att.roots}).VerifyAttestationSig(att.doc)

		require.NoError(t, err)
		require.True(t, res.SignatureOK)
		require.Equal(t, pcr0, res.Document.PCRs[0])
	})

	t.Run("forged doc", func(t *testing.T) {
		_, err := (&awsNSM{}).VerifyAttestationSig(
			newFakeNSM(t).forge(map[uint][]byte{0: pcr0}, nil),
		)

		require.Error(t, err)
	})

	t.Run("signed doc with untrusted root", func(t *testing.T) {
		att := newFakeNSM(t).attest(map[uint][]byte{0: pcr0}, time.Now(), nil)
		other := newFakeNSM(t).attest(map[uint][]byte{0: pcr0}, time.Now(), nil)

		_, err := (&awsNSM{roots: other.roots}).VerifyAttestationSig(att.doc)

		require.Error(t, err)
	})

	t.Run("cert expired now but valid at attestation timestamp", func(t *testing.T) {
		now := time.Now()
		att := newFakeNSMValid(t, now.Add(-3*time.Hour), now.Add(-time.Hour)).
			attest(map[uint][]byte{0: pcr0}, now.Add(-2*time.Hour), nil)

		_, err := (&awsNSM{roots: att.roots}).VerifyAttestationSig(att.doc)

		require.NoError(t, err)
	})

	t.Run("unsigned mode parses forged doc", func(t *testing.T) {
		res, err := (&awsNSM{unsigned: true}).VerifyAttestationSig(
			newFakeNSM(t).forge(map[uint][]byte{0: pcr0}, nil),
		)

		require.NoError(t, err)
		require.False(t, res.SignatureOK)
		require.Equal(t, pcr0, res.Document.PCRs[0])
	})
}

func TestNSMVerifyAttestationDocument(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	userData := []byte("expected user data")
	doc := []byte("attestation doc")
	docB64 := base64.StdEncoding.EncodeToString(doc)

	t.Run("bad base64", func(t *testing.T) {
		fake := &fakeNSM{}
		nsm := &nsmW{nsm: fake}

		_, err := nsm.VerifyAttestationDocument("not base64", map[uint]string{})

		require.Error(t, err)
		require.Empty(t, fake.verifyDocs)
	})

	t.Run("verifier error", func(t *testing.T) {
		fake := &fakeNSM{verifyErr: errors.New("verify failed")}
		nsm := &nsmW{nsm: fake}

		_, err := nsm.VerifyAttestationDocument(docB64, map[uint]string{})

		require.Error(t, err)
		require.Equal(t, [][]byte{doc}, fake.verifyDocs)
	})

	t.Run("PCR match and user_data match", func(t *testing.T) {
		fake := &fakeNSM{verifyResult: verifyDocResult(map[uint][]byte{0: pcr0}, userData)}
		nsm := &nsmW{nsm: fake}

		got, err := nsm.VerifyAttestationDocument(
			docB64, map[uint]string{0: hex.EncodeToString(pcr0)},
		)

		require.NoError(t, err)
		require.Equal(t, userData, got.Document.UserData)
	})

	t.Run("missing PCR", func(t *testing.T) {
		fake := &fakeNSM{verifyResult: verifyDocResult(map[uint][]byte{1: pcr0}, userData)}
		nsm := &nsmW{nsm: fake}

		_, err := nsm.VerifyAttestationDocument(
			docB64, map[uint]string{0: hex.EncodeToString(pcr0)},
		)

		require.Error(t, err)
	})

	t.Run("PCR mismatch", func(t *testing.T) {
		fake := &fakeNSM{verifyResult: verifyDocResult(map[uint][]byte{0: pcr0}, userData)}
		nsm := &nsmW{nsm: fake}

		_, err := nsm.VerifyAttestationDocument(
			docB64,
			map[uint]string{0: hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 48))},
		)

		require.Error(t, err)
	})

	t.Run("user_data mismatch", func(t *testing.T) {
		fake := &fakeNSM{verifyResult: verifyDocResult(map[uint][]byte{0: pcr0}, userData)}
		nsm := &nsmW{nsm: fake}

		err := verifyAttestationUserData(
			nsm, docB64, map[uint]string{0: hex.EncodeToString(pcr0)}, []byte("wrong"),
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
				newFakeNSM(t).forge(map[uint][]byte{0: pcr0}, nil),
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
				newFakeNSM(t).forge(map[uint][]byte{1: pcr0}, nil),
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
