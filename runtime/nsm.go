package runtime

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

type BuildAttestationOptions struct {
	publicKey bool
	nonce     []byte
	userData  []byte
}

type BuildAttestationOption func(*BuildAttestationOptions)

func WithPublicKey() BuildAttestationOption {
	return func(opts *BuildAttestationOptions) {
		opts.publicKey = true
	}
}

func WithNonce(nonce []byte) BuildAttestationOption {
	return func(opts *BuildAttestationOptions) {
		opts.nonce = nonce
	}
}

func WithUserData(userData []byte) BuildAttestationOption {
	return func(opts *BuildAttestationOptions) {
		opts.userData = userData
	}
}

type NSM interface {
	VerifyAttestation(
		attestDocB64 string,
		expectedPCRs map[uint]string,
		expectedUserData []byte,
	) error
	BuildAttestationDocument(opts ...BuildAttestationOption) ([]byte, *rsa.PrivateKey, error)
	LockPCR(index uint) error
	ExtendPCR(index uint, data []byte) error
	DescribePCR(index uint) (data []byte, locked bool, err error)
	CommitPCR(index uint, data []byte) error
	PCR0() ([]byte, error)
}

type VerifyAttestationOptions struct {
	unsigned bool
	roots    *x509.CertPool
}

type VerifyAttestationOption func(*VerifyAttestationOptions)

func WithAttestationRoots(roots *x509.CertPool) VerifyAttestationOption {
	return func(opts *VerifyAttestationOptions) {
		opts.roots = roots
	}
}

func WithAttestationUnsigned(unsigned bool) VerifyAttestationOption {
	return func(opts *VerifyAttestationOptions) {
		opts.unsigned = unsigned
	}
}

type nsmW struct {
	nsm nsmAPI
}

func NewNSM(opts ...VerifyAttestationOption) NSM {
	vao := &VerifyAttestationOptions{}

	for _, opt := range opts {
		opt(vao)
	}

	return &nsmW{nsm: &awsNSM{unsigned: vao.unsigned, roots: vao.roots}}
}

func (n *nsmW) VerifyAttestation(
	attestDocB64 string,
	expectedPCRs map[uint]string,
	expectedUserData []byte,
) error {
	attestDoc, err := base64.StdEncoding.DecodeString(attestDocB64)
	if err != nil {
		return fmt.Errorf("decode attestation base64: %w", err)
	}

	result, err := n.nsm.VerifyAttestationSig(attestDoc)
	if err != nil {
		return fmt.Errorf("verify predecessor attestation: %w", err)
	}

	for index, expected := range expectedPCRs {
		attestedPCR, ok := result.Document.PCRs[index]
		if !ok {
			return fmt.Errorf("PCR%d not found in attestation document", index)
		}
		attestedPCRHex := hex.EncodeToString(attestedPCR)
		if !strings.EqualFold(attestedPCRHex, expected) {
			return fmt.Errorf("attested PCR%d does not match expected: %s != %s",
				index, attestedPCRHex, expected)
		}
	}

	if !bytes.Equal(result.Document.UserData, expectedUserData) {
		return fmt.Errorf("attested user data does not match expected user data")
	}

	return nil
}

func (n *nsmW) BuildAttestationDocument(
	opts ...BuildAttestationOption,
) ([]byte, *rsa.PrivateKey, error) {
	session, err := n.nsm.OpenSession()
	if err != nil {
		return nil, nil, fmt.Errorf("open NSM session: %w", err)
	}

	defer func() { _ = session.Close() }()

	return buildAttestationDocument(session, opts...)
}

// LockPCR pins a PCR so further extendPCR calls are rejected by the NSM.
func (n *nsmW) LockPCR(index uint) error {
	session, err := n.nsm.OpenSession()
	if err != nil {
		return fmt.Errorf("open NSM session: %w", err)
	}
	defer func() { _ = session.Close() }()

	return lockPCR(session, index)
}

func lockPCR(session nsmSession, index uint) error {
	resp, err := session.Send(&request.LockPCR{Index: uint16(index)})
	if err != nil {
		return fmt.Errorf("LockPCR(%d): %w", index, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("LockPCR(%d): NSM error: %s", index, resp.Error)
	}
	return nil
}

// ExtendPCR appends data to PCR[index]'s rolling hash.
func (n *nsmW) ExtendPCR(index uint, value []byte) error {
	session, err := n.nsm.OpenSession()
	if err != nil {
		return fmt.Errorf("open NSM session: %w", err)
	}

	defer func() { _ = session.Close() }()

	return extendPCR(session, index, value)
}

func extendPCR(session nsmSession, index uint, value []byte) error {
	resp, err := session.Send(&request.ExtendPCR{Index: uint16(index), Data: value})
	if err != nil {
		return fmt.Errorf("ExtendPCR(%d): %w", index, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("ExtendPCR(%d): NSM error: %s", index, resp.Error)
	}
	return nil
}

// DescribePCR returns PCR[index]'s current value and its lock state.
func (n *nsmW) DescribePCR(index uint) (data []byte, locked bool, err error) {
	session, err := n.nsm.OpenSession()
	if err != nil {
		return nil, false, fmt.Errorf("open NSM session: %w", err)
	}

	defer func() { _ = session.Close() }()

	return describePCR(session, index)
}

func describePCR(session nsmSession, index uint) (data []byte, locked bool, err error) {
	resp, err := session.Send(&request.DescribePCR{Index: uint16(index)})
	if err != nil {
		return nil, false, fmt.Errorf("DescribePCR(%d): %w", index, err)
	}
	if resp.Error != "" {
		return nil, false, fmt.Errorf("DescribePCR(%d): NSM error: %s", index, resp.Error)
	}
	if resp.DescribePCR == nil {
		return nil, false, fmt.Errorf("DescribePCR(%d): empty response", index)
	}
	return resp.DescribePCR.Data, resp.DescribePCR.Lock, nil
}

func (n *nsmW) PCR0() ([]byte, error) {
	session, err := n.nsm.OpenSession()
	if err != nil {
		return nil, fmt.Errorf("open NSM session: %w", err)
	}

	defer func() { _ = session.Close() }()

	pcr, err := getPCR(session, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get PCR0: %w", err)
	}

	if len(pcr) <= 0 {
		return nil, fmt.Errorf("empty PCR0")
	}

	return pcr, nil
}

func (n *nsmW) CommitPCR(index uint, value []byte) error {
	session, err := n.nsm.OpenSession()
	if err != nil {
		return fmt.Errorf("open NSM session: %w", err)
	}

	defer func() { _ = session.Close() }()

	return commitPCR(session, index, value)
}

func commitPCR(session nsmSession, index uint, value []byte) error {
	cur, locked, err := describePCR(session, index)
	if err != nil {
		return fmt.Errorf("describePCR(%d): %w", index, err)
	}

	extendedValue := pcrExtendFromZero(value)

	switch {
	case bytes.Equal(cur, extendedValue):
		if !locked {
			if err := lockPCR(session, index); err != nil {
				return fmt.Errorf("lock PCR%d: %w", index, err)
			}
		}
		slog.Info(
			"PCR already committed to value, skipped re-extension",
			"index", index,
			"data", prefix16(hex.EncodeToString(value)),
		)
		return nil
	case !bytes.Equal(cur, make([]byte, len(cur))):
		return fmt.Errorf("PCR%d holds an unexpected value: %s", index, hex.EncodeToString(cur))
	}
	if err := extendPCR(session, index, value); err != nil {
		return fmt.Errorf("failed to extend PCR%d: %w", index, err)
	}
	if err := lockPCR(session, index); err != nil {
		return fmt.Errorf("failed to lock PCR%d: %w", index, err)
	}
	return nil
}

func getPCR(session nsmSession, index uint) ([]byte, error) {
	attestDoc, _, err := buildAttestationDocument(session)
	if err != nil {
		return nil, fmt.Errorf("build attestation document: %w", err)
	}

	var coseSign1 []cbor.RawMessage
	if err := cbor.Unmarshal(attestDoc, &coseSign1); err != nil {
		return nil, fmt.Errorf("unmarshal COSE Sign1: %w", err)
	}
	if len(coseSign1) < 3 {
		return nil, fmt.Errorf("invalid COSE Sign1 structure")
	}

	var payload []byte
	if err := cbor.Unmarshal(coseSign1[2], &payload); err != nil {
		return nil, fmt.Errorf("unmarshal COSE payload: %w", err)
	}

	var doc attestationDocument
	if err := cbor.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal attestation document: %w", err)
	}

	pcr, ok := doc.PCRs[index]
	if !ok {
		return nil, fmt.Errorf("PCR%d not found in attestation document", index)
	}

	return pcr, nil
}

// buildAttestationDocument creates an attestation document; WithPublicKey adds RSA.
func buildAttestationDocument(
	session nsmSession,
	opts ...BuildAttestationOption,
) ([]byte, *rsa.PrivateKey, error) {
	bao := &BuildAttestationOptions{}

	for _, opt := range opts {
		opt(bao)
	}

	var privateKey *rsa.PrivateKey
	var publicKeyDER []byte
	if bao.publicKey {
		pk, err := rsa.GenerateKey(session, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("generate rsa key: %w", err)
		}

		der, err := x509.MarshalPKIXPublicKey(&pk.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal public key: %w", err)
		}
		privateKey = pk
		publicKeyDER = der
	}

	if bao.nonce == nil {
		nonce := make([]byte, 32)
		if _, err := io.ReadFull(session, nonce); err != nil {
			return nil, nil, fmt.Errorf("read nonce: %w", err)
		}
		bao.nonce = nonce
	}

	res, err := session.Send(&request.Attestation{
		UserData:  bao.userData,
		Nonce:     bao.nonce,
		PublicKey: publicKeyDER,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("attestation request failed: %w", err)
	}
	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, nil, fmt.Errorf("attestation response missing document")
	}

	return res.Attestation.Document, privateKey, nil
}

func pcrExtendFromZero(data []byte) []byte {
	h := sha512.Sum384(append(make([]byte, 48), data...))
	return h[:]
}

type nsmAPI interface {
	OpenSession() (nsmSession, error)
	VerifyAttestationSig(doc []byte) (*nitrite.Result, error)
}

type nsmSession interface {
	io.Reader
	Send(req request.Request) (response.Response, error)
	Close() error
}

type awsNSM struct {
	unsigned bool
	// nil for production verification
	roots *x509.CertPool
}

func (n *awsNSM) OpenSession() (nsmSession, error) {
	return nsm.OpenDefaultSession()
}

func (n *awsNSM) VerifyAttestationSig(doc []byte) (*nitrite.Result, error) {
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
		return nil, fmt.Errorf("COSE Sign1 payload empty")
	}
	var document nitrite.Document
	if err := cbor.Unmarshal(envelope.Payload, &document); err != nil {
		return nil, fmt.Errorf("decode attestation document: %w", err)
	}

	if n.unsigned {
		slog.Warn("INSECURE: skipping COSE signature verification of attestation document",
			"deployment", getDeployment())
		return &nitrite.Result{
			Document:    &document,
			Protected:   envelope.Protected,
			Payload:     envelope.Payload,
			Signature:   envelope.Signature,
			SignatureOK: false,
		}, nil
	}

	// nitrite returns nil only when the cert chains to a trusted root and the
	// signature is valid; reject any failure (untrusted or bad signature).
	res, err := nitrite.Verify(doc, nitrite.VerifyOptions{
		Roots:       n.roots,
		CurrentTime: time.UnixMilli(int64(document.Timestamp)),
	})
	if err != nil {
		return nil, fmt.Errorf("attestation verification: %w", err)
	}
	return res, nil
}
