package client

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ArkLabsHQ/enclave/internal/signing"
)

// ProxyEvidence is a signed gRPC response relayed by a service that called
// the enclave for its caller, such as arkd's GetInfo: the attestation fetched
// with a nonce the service chose, and the call the runtime signed with that
// nonce and its time.
type ProxyEvidence struct {
	// Attestation is the base64 document from /enclave/attestation.
	Attestation string
	// Method is the full gRPC method called, such as
	// /signer.v1.SignerService/GetPubkey.
	Method string
	// Nonce is the nonce the service chose for the attestation and the call.
	Nonce []byte
	// Timestamp is the runtime's X-Enclave-Timestamp: when it passed the call
	// to the app.
	Timestamp time.Time
	// Response is the response message, without gRPC framing.
	Response []byte
	// Signature is the runtime's X-Enclave-Signature, decoded.
	Signature []byte
}

// VerifyProxyEvidence checks evidence relayed for a call to method with
// request, the request message the caller expects without gRPC framing (empty
// for GetPubkey), so the relaying service need not be trusted. The attestation
// must come from the enclave opts expects (ExpectedPCR0, ExpectedPCRs,
// InsecureSkipCOSEVerify) and answer the evidence's nonce. The attested
// signing key must have signed Response for method, request, that nonce, and
// Timestamp as a call that succeeded, grpc-status 0. The attestation and the
// call must both be timestamped no earlier than notBefore, typically when the
// caller asked, so neither is replayed from before. Only Response is
// authenticated: decode it once this returns. The result is what the enclave
// attests, including any pending migration.
func VerifyProxyEvidence(
	evidence ProxyEvidence, method string, request []byte, notBefore time.Time, opts Options,
) (*AttestationResult, error) {
	docBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(evidence.Attestation))
	if err != nil {
		return nil, fmt.Errorf("decode attestation document: %w", err)
	}
	nitResult, err := verifyAttestationDocument(
		docBytes, evidence.Nonce, opts.ExpectedPCR0, opts.InsecureSkipCOSEVerify,
	)
	if err != nil {
		return nil, err
	}
	timestamp := time.UnixMilli(int64(nitResult.Document.Timestamp))
	if timestamp.Before(notBefore) {
		return nil, fmt.Errorf("attestation from %s, before %s", timestamp, notBefore)
	}
	userData, err := parseUserData(nitResult)
	if err != nil {
		return nil, fmt.Errorf("parse user_data: %w", err)
	}
	if userData.signingKey == nil {
		return nil, fmt.Errorf("enclave attests no response signing key")
	}
	pcrs, err := verifyPCRs(nitResult.Document.PCRs, opts.ExpectedPCRs)
	if err != nil {
		return nil, err
	}

	// A gRPC call is a POST to the method's path; grpc-status 0 is OK.
	msg := signing.ResponseMessage(
		http.MethodPost, method, evidence.Nonce, evidence.Timestamp, request, 0, evidence.Response,
	)
	if !ed25519.Verify(userData.signingKey, msg, evidence.Signature) {
		return nil, fmt.Errorf("invalid enclave signature")
	}
	if evidence.Method != method {
		return nil, fmt.Errorf("evidence is for method %q, not %q", evidence.Method, method)
	}
	if evidence.Timestamp.Before(notBefore) {
		return nil, fmt.Errorf("response from %s, before %s", evidence.Timestamp, notBefore)
	}

	return &AttestationResult{
		PCR0:                opts.ExpectedPCR0,
		PCRs:                pcrs,
		TLSKeyHash:          userData.tlsKeyHash,
		SigningKey:          userData.signingKey,
		MigrationCooldown:   userData.migrationCooldown,
		MigrationTargetPCR0: userData.migrationTargetPCR0,
		Timestamp:           timestamp,
		Verified:            true,
		VerifiedAt:          time.Now(),
	}, nil
}
