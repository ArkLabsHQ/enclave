package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	signerv1 "github.com/ArkLabsHQ/enclave/examples/proxy/gen/signer/v1"
	"github.com/ArkLabsHQ/enclave/runtime"
)

// Proxy proof of concept: a proxy, such as arkd's GetInfo, returns the enclave
// signer's pubkey with evidence for it, so its caller does not have to trust
// the proxy. The enclave here is the runtime's own servers, with a software
// NSM, in front of a signer that answers GetPubkey over gRPC and over REST.
//
//	caller ─ GET /v1/info ─▶ proxy ─ GET /enclave/attestation?nonce ─▶ runtime
//	                         proxy ─ gRPC GetPubkey + nonce ──────────▶ runtime ─▶ signer
//	caller ◀─ {signerPubkey, signerEvidence} ─ proxy
//
// GET /v1/info-rest is the same, with the proxy calling the signer's REST
// route, GET /v1/pubkey, instead of gRPC.
//
// The proxy chooses the nonce, and the runtime signs the signer's response for
// it with the runtime's time. The caller checks that evidence, requires the
// attestation and the signed response to be no older than its request, then
// decodes the signed response. The caller is ts/verify.ts, in TypeScript with
// the buf-generated code.

func TestExample(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0x5a}, 48)
	pubkey := &signerv1.GetPubkeyResponse{
		Pubkey: "02" + strings.Repeat("ab", 32),
		DeprecatedSigners: []*signerv1.DeprecatedSigner{{
			Pubkey:     "02" + strings.Repeat("11", 32),
			CutoffDate: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Unix(),
		}},
	}

	signer := startSigner(t, pubkey)
	enclave := startEnclave(t, signer, pcr0)
	proxyURL := startProxy(t, enclave)

	// ts/main.ts runs the caller, ts/verify.ts, against the proxy's gRPC or REST
	// route, and prints the signer's response it verified, as JSON.
	want, err := protojson.Marshal(pubkey)
	require.NoError(t, err)
	for _, call := range []string{"grpc", "rest"} {
		t.Run(call, func(t *testing.T) {
			out, err := exec.Command(
				"node", "--no-warnings", "ts/main.ts", call, proxyURL, hex.EncodeToString(pcr0),
			).CombinedOutput()
			require.NoError(t, err, string(out))
			require.JSONEq(t, string(want), string(out))
		})
	}
}

// Signer: the app inside the enclave, serving gRPC and REST.

// signer answers GetPubkey with pubkey.
type signer struct {
	signerv1.UnimplementedSignerServiceServer
	pubkey *signerv1.GetPubkeyResponse
}

func (s signer) GetPubkey(
	context.Context, *signerv1.GetPubkeyRequest,
) (*signerv1.GetPubkeyResponse, error) {
	return s.pubkey, nil
}

// getPubkeyREST answers GetPubkey at its REST route, GET /v1/pubkey, with
// pubkey as JSON, as arkd's HTTP gateway does.
func (s signer) getPubkeyREST(w http.ResponseWriter, _ *http.Request) {
	body, err := protojson.Marshal(s.pubkey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// Enclave: the runtime's servers in front of the signer.

// softwareNSM stands in for the NSM device. It answers attestation requests
// with an unsigned COSE_Sign1 document that attests pcr0; callers here skip
// the COSE signature check, as QEMU's NSM cannot sign either.
type softwareNSM struct {
	pcr0 []byte
}

func (softwareNSM) Read(p []byte) (int, error) {
	return rand.Read(p)
}

func (n softwareNSM) Send(req request.Request) (response.Response, error) {
	attestation, ok := req.(*request.Attestation)
	if !ok {
		return response.Response{}, fmt.Errorf("software NSM does not answer %T", req)
	}
	document, err := cbor.Marshal(&nitrite.Document{
		ModuleID:  "software-nsm",
		Timestamp: uint64(time.Now().UnixMilli()),
		Digest:    "SHA384",
		PCRs:      map[uint][]byte{0: n.pcr0},
		PublicKey: attestation.PublicKey,
		UserData:  attestation.UserData,
		Nonce:     attestation.Nonce,
	})
	if err != nil {
		return response.Response{}, err
	}
	// COSE_Sign1: protected header, unprotected header, payload, signature.
	doc, err := cbor.Marshal([]any{[]byte{}, map[int]any{}, document, []byte{}})
	if err != nil {
		return response.Response{}, err
	}
	return response.Response{Attestation: &response.Attestation{Document: doc}}, nil
}

func (softwareNSM) Close() error {
	return nil
}

// enclave is how the proxy reaches the runtime's external server.
type enclave struct {
	url    string
	tls    *tls.Config // trusts the runtime's self-signed certificate
	client *http.Client
}

// fetchAttestation returns the enclave's base64 attestation document for
// nonceHex.
func (e enclave) fetchAttestation(ctx context.Context, nonceHex string) (string, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, e.url+"/enclave/attestation?nonce="+nonceHex, nil,
	)
	if err != nil {
		return "", err
	}
	res, err := e.client.Do(req)
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

// Proxy: what arkd does for GetInfo.

// getInfoResponse is the proxy's GET /v1/info and /v1/info-rest answer, plain
// JSON, as the caller speaks REST to the proxy. Bytes are base64 in JSON;
// timestamp is Unix milliseconds.
type getInfoResponse struct {
	SignerPubkey   string `json:"signerPubkey"`
	SignerEvidence struct {
		// The base64 document from /enclave/attestation.
		Attestation string `json:"attestation"`
		Payload     struct {
			// The call's request line as the runtime signed it:
			// "POST /signer.v1.SignerService/GetPubkey" or "GET /v1/pubkey".
			Method string `json:"method"`
			// The nonce the proxy chose for the attestation and the call.
			Nonce []byte `json:"nonce"`
			// The runtime's x-enclave-timestamp.
			Timestamp int64 `json:"timestamp"`
			// The GetPubkeyResponse as the runtime signed it: protobuf without
			// gRPC framing, or the REST route's JSON body.
			Response []byte `json:"response"`
		} `json:"payload"`
		// The runtime's x-enclave-signature, decoded.
		Signature []byte `json:"signature"`
	} `json:"signerEvidence"`
}

// proxy relays GetInfo to the enclave. It is not trusted: the caller checks
// everything it returns.
type proxy struct {
	enclave enclave
	conn    *grpc.ClientConn // gRPC to the signer, through the runtime
}

// getInfo answers with the signer's pubkey and the evidence for it. It calls
// GetPubkey with call, whose request line the runtime signs as method, and
// decodes the response with unmarshal: protobuf for gRPC, JSON for REST.
func (p *proxy) getInfo(
	method string,
	call func(ctx context.Context, nonceHex string) (
		response []byte, timestamp int64, signature []byte, err error,
	),
	unmarshal func([]byte, proto.Message) error,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Choose a fresh nonce.
		nonce := make([]byte, 20)
		if _, err := rand.Read(nonce); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		nonceHex := hex.EncodeToString(nonce)

		// 2. Fetch the attestation with that nonce.
		attestation, err := p.enclave.fetchAttestation(r.Context(), nonceHex)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		// 3. Call GetPubkey with the same nonce, keeping the response bytes as
		// received: the signature covers them.
		response, timestamp, signature, err := call(r.Context(), nonceHex)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		pubkey := &signerv1.GetPubkeyResponse{}
		if err := unmarshal(response, pubkey); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		// 4. Return the pubkey and the evidence for it.
		var info getInfoResponse
		info.SignerPubkey = pubkey.GetPubkey()
		info.SignerEvidence.Attestation = attestation
		info.SignerEvidence.Payload.Method = method
		info.SignerEvidence.Payload.Nonce = nonce
		info.SignerEvidence.Payload.Timestamp = timestamp
		info.SignerEvidence.Payload.Response = response
		info.SignerEvidence.Signature = signature
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}
}

// callGetPubkey calls the signer's GetPubkey through the runtime with
// nonceHex. It returns the response bytes and, read from the response headers,
// the runtime's timestamp and its signature over both.
func (p *proxy) callGetPubkey(
	ctx context.Context, nonceHex string,
) (response []byte, timestamp int64, signature []byte, err error) {
	var header metadata.MD
	ctx = metadata.AppendToOutgoingContext(ctx, "x-enclave-sign-nonce", nonceHex)
	err = p.conn.Invoke(ctx, signerv1.SignerService_GetPubkey_FullMethodName, []byte{}, &response,
		grpc.ForceCodec(rawCodec{}), grpc.Header(&header))
	if err != nil {
		return nil, 0, nil, err
	}
	timestamp, err = strconv.ParseInt(strings.Join(header.Get("x-enclave-timestamp"), ""), 10, 64)
	if err != nil {
		return nil, 0, nil, err
	}
	signature, err = base64.StdEncoding.DecodeString(
		strings.Join(header.Get("x-enclave-signature"), ""),
	)
	if err != nil {
		return nil, 0, nil, err
	}
	return response, timestamp, signature, nil
}

// callGetPubkeyREST calls the signer's REST route for GetPubkey,
// GET /v1/pubkey, through the runtime with nonceHex. It returns the response
// body and, read from the response headers, the runtime's timestamp and its
// signature over both.
func (p *proxy) callGetPubkeyREST(
	ctx context.Context, nonceHex string,
) (response []byte, timestamp int64, signature []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.enclave.url+"/v1/pubkey", nil)
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("X-Enclave-Sign-Nonce", nonceHex)
	res, err := p.enclave.client.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	response, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, 0, nil, fmt.Errorf("GetPubkey: HTTP %d", res.StatusCode)
	}
	timestamp, err = strconv.ParseInt(res.Header.Get("X-Enclave-Timestamp"), 10, 64)
	if err != nil {
		return nil, 0, nil, err
	}
	signature, err = base64.StdEncoding.DecodeString(res.Header.Get("X-Enclave-Signature"))
	if err != nil {
		return nil, 0, nil, err
	}
	return response, timestamp, signature, nil
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

// startSigner serves the signer, answering GetPubkey with pubkey, and returns
// its address. One port serves gRPC over h2c and the REST route over
// HTTP/1.1; the runtime forwards each request with the protocol it came in.
func startSigner(t *testing.T, pubkey *signerv1.GetPubkeyResponse) string {
	t.Helper()
	s := signer{pubkey: pubkey}
	grpcServer := grpc.NewServer()
	signerv1.RegisterSignerServiceServer(grpcServer, s)
	mux := http.NewServeMux()
	mux.Handle("POST /signer.v1.SignerService/", grpcServer)
	mux.HandleFunc("GET /v1/pubkey", s.getPubkeyREST)
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{Handler: mux, Protocols: &protocols}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(func() { _ = server.Close() })
	return lis.Addr().String()
}

// startEnclave runs the runtime's servers in front of the signer at
// signerAddr, with a software NSM that attests pcr0. They attest their
// response-signing key.
func startEnclave(t *testing.T, signerAddr string, pcr0 []byte) enclave {
	t.Helper()
	cert, roots := selfSignedCert(t)
	rt := runtime.NewRuntimeState()
	rt.SetTLSCertCallback(func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &cert, nil
	})
	rt.NotifyReady()
	attData := &runtime.AttestationData{}
	attData.SetResponseSigningKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize)),
	)
	// The runtime attests its pending migration: none here.
	attData.SetMigrationSource(func(context.Context) (*runtime.MigrationStatus, error) {
		return &runtime.MigrationStatus{}, nil
	})
	cfg := runtime.Config{
		ExtPort:   freePort(t),
		IntPort:   freePort(t),
		AppWebSrv: &url.URL{Scheme: "http", Host: signerAddr},
	}
	nsm := runtime.NewNSM(func() (runtime.NSMSession, error) {
		return softwareNSM{pcr0: pcr0}, nil
	})
	servers := runtime.SetupHttpServers(
		rt, cfg, nsm, runtime.NewTelemetry(&cfg, nil), attData, "",
	)
	require.NoError(t, servers.Start(t.Context(), cfg))

	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return enclave{
		url:    fmt.Sprintf("https://127.0.0.1:%d", cfg.ExtPort),
		tls:    tlsConfig,
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}},
	}
}

// startProxy serves the proxy's GET /v1/info, which calls the signer over
// gRPC, and GET /v1/info-rest, which calls it over REST, and returns its URL.
func startProxy(t *testing.T, enclave enclave) string {
	t.Helper()
	conn, err := grpc.NewClient(
		strings.TrimPrefix(enclave.url, "https://"),
		grpc.WithTransportCredentials(credentials.NewTLS(enclave.tls)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	p := &proxy{enclave: enclave, conn: conn}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", p.getInfo(
		"POST "+signerv1.SignerService_GetPubkey_FullMethodName, p.callGetPubkey, proto.Unmarshal,
	))
	mux.HandleFunc("GET /v1/info-rest", p.getInfo(
		"GET /v1/pubkey", p.callGetPubkeyREST, protojson.Unmarshal,
	))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

// selfSignedCert returns a certificate for 127.0.0.1 and a pool that trusts it.
func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}

// freePort returns a loopback port that was free a moment ago.
// ponytail: another process can take it before the runtime listens; use a
// listener-injecting Start if that ever flakes.
func freePort(t *testing.T) uint16 {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()
	return uint16(lis.Addr().(*net.TCPAddr).Port)
}
