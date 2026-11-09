package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/ArkLabsHQ/enclave/client"
)

// Proxy proof of concept: a proxy, such as arkd's GetInfo, returns the enclave
// signer's pubkey with evidence for it, so its caller does not have to trust
// the proxy.
//
//	caller ─ GET /v1/info ─▶ proxy ─ GET /enclave/attestation?nonce ─▶ runtime
//	                         proxy ─ gRPC GetPubkey + nonce ──────────▶ runtime ─▶ signer
//	caller ◀─ {signerPubkey, signerEvidence} ─ proxy
//
// The proxy chooses the nonce, and the runtime signs the signer's response for
// it. The caller checks the evidence with client.VerifyProxyEvidence, which
// also requires the attestation to be no older than the caller's request, then
// decodes the signed response.

const getPubkeyMethod = "/signer.v1.SignerService/GetPubkey"

// Messages.

// getPubkeyResponse is the signer's GetPubkeyResponse;
//
//	message GetPubkeyResponse {
//	  string pubkey = 1;
//	  int64 date = 2;  // Unix seconds
//	  repeated string deprecated_signer_keys = 3;
//	}
type getPubkeyResponse struct {
	Pubkey               string
	Date                 int64
	DeprecatedSignerKeys []string
}

// getInfoResponse is the part of the proxy's GetInfo response that carries
// the signer evidence. Bytes are base64 in JSON.
type getInfoResponse struct {
	SignerPubkey   string `json:"signerPubkey"`
	SignerEvidence struct {
		Attestation string `json:"attestation"`
		Payload     struct {
			Method   string `json:"method"`
			Nonce    []byte `json:"nonce"`
			Response []byte `json:"response"`
		} `json:"payload"`
		Signature []byte `json:"signature"`
	} `json:"signerEvidence"`
}

// Signer: the gRPC app inside the enclave.

// startSigner serves GetPubkey, answering resp, on a plain grpc-go server over
// h2c, and returns its address.
func startSigner(t *testing.T, resp getPubkeyResponse) string {
	t.Helper()
	signer := grpc.NewServer()
	signer.RegisterService(&grpc.ServiceDesc{
		ServiceName: "signer.v1.SignerService",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "GetPubkey",
			Handler: func(
				_ any, _ context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor,
			) (any, error) {
				if err := dec(new(emptypb.Empty)); err != nil {
					return nil, err
				}
				return resp.message(), nil
			},
		}},
	}, struct{}{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = signer.Serve(lis) }()
	t.Cleanup(signer.Stop)
	return lis.Addr().String()
}

// Runtime: the enclave runtime in front of the signer.

// startEnclave runs the runtime's external server in front of the signer at
// signerAddr. It attests pcr0, its response-signing key, and migration.
func startEnclave(
	t *testing.T, signerAddr string, pcr0 []byte, migration *MigrationStatus,
) *httptest.Server {
	t.Helper()
	rt := newRuntimeState()
	rt.NotifyReady()
	attData := &AttestationData{}
	attData.SetTLSKeyHashSource(staticKeyHash(sha256.Sum256([]byte("tls"))))
	attData.SetResponseSigningKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize)))
	attData.SetMigrationSource(staticMigrationStatus(migration, nil))
	s := SetupHttpServers(
		rt, Config{AppWebSrv: &url.URL{Scheme: "http", Host: signerAddr}},
		&nsmW{nsm: newFakeNSM(t).withPCRs(map[uint][]byte{0: pcr0})},
		NewTelemetry(testCfg, nil), attData, "token",
	).(*servers)
	enclave := httptest.NewUnstartedServer(s.ext.Handler)
	enclave.EnableHTTP2 = true
	enclave.StartTLS()
	t.Cleanup(enclave.Close)
	return enclave
}

// Proxy: what arkd does for GetInfo.

// proxy relays GetInfo to the enclave. It is not trusted: the caller checks
// everything it returns.
type proxy struct {
	enclave *httptest.Server
	conn    *grpc.ClientConn // gRPC to the signer, through the runtime
}

// startProxy serves the proxy's GET /v1/info and returns its URL.
func startProxy(t *testing.T, enclave *httptest.Server) string {
	t.Helper()
	conn, err := grpc.NewClient(
		strings.TrimPrefix(enclave.URL, "https://"),
		grpc.WithTransportCredentials(
			credentials.NewTLS(enclave.Client().Transport.(*http.Transport).TLSClientConfig),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	p := &proxy{enclave: enclave, conn: conn}
	server := httptest.NewServer(http.HandlerFunc(p.getInfo))
	t.Cleanup(server.Close)
	return server.URL
}

// getInfo answers GET /v1/info with the signer's pubkey and the evidence for
// it.
func (p *proxy) getInfo(w http.ResponseWriter, r *http.Request) {
	// 1. Choose a fresh nonce.
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	nonceHex := hex.EncodeToString(nonce)

	// 2. Fetch the attestation with that nonce.
	attestation, err := p.fetchAttestation(r.Context(), nonceHex)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// 3. Call GetPubkey with the same nonce, keeping the response bytes as
	// received: the signature covers them.
	response, signature, err := p.callGetPubkey(r.Context(), nonceHex)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	pubkey, err := decodeGetPubkeyResponse(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// 4. Return the pubkey and the evidence for it.
	var info getInfoResponse
	info.SignerPubkey = pubkey.Pubkey
	info.SignerEvidence.Attestation = attestation
	info.SignerEvidence.Payload.Method = getPubkeyMethod
	info.SignerEvidence.Payload.Nonce = nonce
	info.SignerEvidence.Payload.Response = response
	info.SignerEvidence.Signature = signature
	_ = json.NewEncoder(w).Encode(info)
}

// fetchAttestation returns the enclave's base64 attestation document for
// nonceHex.
func (p *proxy) fetchAttestation(ctx context.Context, nonceHex string) (string, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, p.enclave.URL+"/enclave/attestation?nonce="+nonceHex, nil,
	)
	if err != nil {
		return "", err
	}
	res, err := p.enclave.Client().Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("attestation: HTTP %d", res.StatusCode)
	}
	return strings.TrimSpace(string(body)), nil
}

// callGetPubkey calls the signer's GetPubkey through the runtime with
// nonceHex. It returns the response bytes and the runtime's signature over
// them, read from the response headers.
func (p *proxy) callGetPubkey(
	ctx context.Context, nonceHex string,
) (response, signature []byte, err error) {
	var header metadata.MD
	ctx = metadata.AppendToOutgoingContext(ctx, "x-enclave-sign-nonce", nonceHex)
	err = p.conn.Invoke(ctx, getPubkeyMethod, []byte{}, &response,
		grpc.ForceCodec(rawCodec{}), grpc.Header(&header))
	if err != nil {
		return nil, nil, err
	}
	signature, err = base64.StdEncoding.DecodeString(
		strings.Join(header.Get("x-enclave-signature"), ""),
	)
	if err != nil {
		return nil, nil, err
	}
	return response, signature, nil
}

// Caller: what a client of the proxy does.

// fetchInfo calls the proxy's GetInfo.
func fetchInfo(t *testing.T, proxyURL string) getInfoResponse {
	t.Helper()
	res, err := http.Get(proxyURL + "/v1/info")
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	require.Equal(t, http.StatusOK, res.StatusCode)
	var info getInfoResponse
	require.NoError(t, json.NewDecoder(res.Body).Decode(&info))
	return info
}

// verifyInfo checks GetInfo's evidence and returns the signer's response it
// authenticates. The client checks the attestation, that it is no older than
// notBefore, and the signature; then the signed response is decoded and must
// carry the pubkey GetInfo reports.
func verifyInfo(
	info getInfoResponse, notBefore time.Time, opts client.Options,
) (getPubkeyResponse, *client.AttestationResult, error) {
	evidence := info.SignerEvidence
	attested, err := client.VerifyProxyEvidence(client.ProxyEvidence{
		Attestation: evidence.Attestation,
		Method:      evidence.Payload.Method,
		Nonce:       evidence.Payload.Nonce,
		Response:    evidence.Payload.Response,
		Signature:   evidence.Signature,
	}, getPubkeyMethod, nil, notBefore, opts) // GetPubkey's request is empty
	if err != nil {
		return getPubkeyResponse{}, nil, err
	}
	response, err := decodeGetPubkeyResponse(evidence.Payload.Response)
	if err != nil {
		return getPubkeyResponse{}, nil, err
	}
	if !strings.EqualFold(response.Pubkey, info.SignerPubkey) {
		return getPubkeyResponse{}, nil, errors.New("GetInfo pubkey mismatch")
	}
	return response, attested, nil
}

// The proof of concept, end to end.

func TestProxyGetInfo(t *testing.T) {
	pubkey := getPubkeyResponse{
		Pubkey: "02" + strings.Repeat("ab", 32),
		Date:   time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Unix(),
		DeprecatedSignerKeys: []string{
			"02" + strings.Repeat("11", 32),
			"02" + strings.Repeat("22", 32),
		},
	}
	pcr0 := bytes.Repeat([]byte{0x5a}, 48)
	pendingMigration := &MigrationStatus{
		State:            migrationStateCoolingDown,
		TargetPCR0:       strings.Repeat("6b", 48),
		RemainingSeconds: 3600,
	}

	signer := startSigner(t, pubkey)
	enclave := startEnclave(t, signer, pcr0, pendingMigration)
	proxyURL := startProxy(t, enclave)
	opts := client.Options{ExpectedPCR0: hex.EncodeToString(pcr0), InsecureSkipCOSEVerify: true}

	// The caller notes when it asked: the evidence must be attested no
	// earlier. The attestation timestamp is in milliseconds.
	notBefore := time.Now().Truncate(time.Millisecond)
	info := fetchInfo(t, proxyURL)

	t.Run("caller verifies GetInfo and decodes the signer's response", func(t *testing.T) {
		response, attested, err := verifyInfo(info, notBefore, opts)
		require.NoError(t, err)
		require.Equal(t, pubkey, response)
		require.Equal(t, pubkey.Pubkey, info.SignerPubkey)
		require.False(t, attested.Timestamp.Before(notBefore), "attested after the caller asked")
	})

	t.Run("caller sees the pending migration", func(t *testing.T) {
		_, attested, err := verifyInfo(info, notBefore, opts)
		require.NoError(t, err)
		require.Equal(t, time.Hour, attested.MigrationCooldown)
		require.Equal(t, pendingMigration.TargetPCR0, attested.MigrationTargetPCR0)
	})

	t.Run("caller rejects evidence attested before it asked", func(t *testing.T) {
		_, _, err := verifyInfo(info, time.Now().Add(time.Hour), opts)
		require.ErrorContains(t, err, "before")
	})

	// The proxy is not trusted: whatever it changes, the caller rejects.
	tampered := func(change func(*getInfoResponse)) getInfoResponse {
		changed := info
		change(&changed)
		return changed
	}
	forged := pubkey
	forged.Pubkey = "03" + strings.Repeat("cd", 32)

	t.Run("caller rejects a proxy that swaps the pubkey", func(t *testing.T) {
		_, _, err := verifyInfo(tampered(func(i *getInfoResponse) {
			i.SignerPubkey = forged.Pubkey
		}), notBefore, opts)
		require.ErrorContains(t, err, "GetInfo pubkey mismatch")
	})

	t.Run("caller rejects a proxy that changes the response", func(t *testing.T) {
		response, err := proto.Marshal(forged.message())
		require.NoError(t, err)
		_, _, err = verifyInfo(tampered(func(i *getInfoResponse) {
			i.SignerEvidence.Payload.Response = response
		}), notBefore, opts)
		require.ErrorContains(t, err, "invalid enclave signature")
	})

	t.Run("caller rejects evidence for another method", func(t *testing.T) {
		_, _, err := verifyInfo(tampered(func(i *getInfoResponse) {
			i.SignerEvidence.Payload.Method = "/signer.v1.SignerService/Sign"
		}), notBefore, opts)
		require.ErrorContains(t, err, "evidence is for method")
	})

	t.Run("caller rejects evidence whose nonce was changed", func(t *testing.T) {
		_, _, err := verifyInfo(tampered(func(i *getInfoResponse) {
			i.SignerEvidence.Payload.Nonce = bytes.Repeat([]byte{1}, 20)
		}), notBefore, opts)
		require.ErrorContains(t, err, "attestation nonce mismatch")
	})

	t.Run("caller rejects an attestation from another call", func(t *testing.T) {
		other := fetchInfo(t, proxyURL)
		_, _, err := verifyInfo(tampered(func(i *getInfoResponse) {
			i.SignerEvidence.Attestation = other.SignerEvidence.Attestation
		}), notBefore, opts)
		require.ErrorContains(t, err, "attestation nonce mismatch")
	})

	t.Run("caller rejects a forged signature", func(t *testing.T) {
		_, _, err := verifyInfo(tampered(func(i *getInfoResponse) {
			i.SignerEvidence.Signature = make([]byte, ed25519.SignatureSize)
		}), notBefore, opts)
		require.ErrorContains(t, err, "invalid enclave signature")
	})
}

// Plumbing.

// getPubkeyResponseType describes GetPubkeyResponse. It, message, and
// decodeGetPubkeyResponse stand in for the code protoc would generate from the
// signer's .proto, which this repo does not have.
var getPubkeyResponseType = func() protoreflect.MessageDescriptor {
	field := func(
		name string, number int32, typ descriptorpb.FieldDescriptorProto_Type, repeated bool,
	) *descriptorpb.FieldDescriptorProto {
		label := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
		if repeated {
			label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED
		}
		return &descriptorpb.FieldDescriptorProto{
			Name:   proto.String(name),
			Number: proto.Int32(number),
			Type:   typ.Enum(),
			Label:  label.Enum(),
		}
	}
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	i64 := descriptorpb.FieldDescriptorProto_TYPE_INT64
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("signer/v1/signer.proto"),
		Package: proto.String("signer.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("GetPubkeyResponse"),
			Field: []*descriptorpb.FieldDescriptorProto{
				field("pubkey", 1, str, false),
				field("date", 2, i64, false),
				field("deprecated_signer_keys", 3, str, true),
			},
		}},
	}, nil)
	if err != nil {
		panic(err)
	}
	return file.Messages().ByName("GetPubkeyResponse")
}()

// message is r as the protobuf message the signer sends.
func (r getPubkeyResponse) message() proto.Message {
	fields := getPubkeyResponseType.Fields()
	msg := dynamicpb.NewMessage(getPubkeyResponseType)
	msg.Set(fields.ByName("pubkey"), protoreflect.ValueOfString(r.Pubkey))
	msg.Set(fields.ByName("date"), protoreflect.ValueOfInt64(r.Date))
	keys := msg.Mutable(fields.ByName("deprecated_signer_keys")).List()
	for _, key := range r.DeprecatedSignerKeys {
		keys.Append(protoreflect.ValueOfString(key))
	}
	return msg
}

// decodeGetPubkeyResponse decodes the protobuf bytes of a GetPubkeyResponse.
func decodeGetPubkeyResponse(b []byte) (getPubkeyResponse, error) {
	fields := getPubkeyResponseType.Fields()
	msg := dynamicpb.NewMessage(getPubkeyResponseType)
	if err := proto.Unmarshal(b, msg); err != nil {
		return getPubkeyResponse{}, err
	}
	r := getPubkeyResponse{
		Pubkey: msg.Get(fields.ByName("pubkey")).String(),
		Date:   msg.Get(fields.ByName("date")).Int(),
	}
	keys := msg.Get(fields.ByName("deprecated_signer_keys")).List()
	for i := range keys.Len() {
		r.DeprecatedSignerKeys = append(r.DeprecatedSignerKeys, keys.Get(i).String())
	}
	return r, nil
}

// rawCodec passes message bytes through unchanged, so the proxy relays exactly
// the response the runtime signed.
type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) { return v.([]byte), nil }

func (rawCodec) Unmarshal(data []byte, v any) error {
	*v.(*[]byte) = bytes.Clone(data)
	return nil
}

func (rawCodec) Name() string { return "proto" }
