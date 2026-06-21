// awsmocks bundles a KMS Decrypt/GenerateDataKey-with-Recipient proxy (:4000,
// wraps plaintext in CMS EnvelopedData for the attesting enclave's RSA key)
// and an IMDSv2 stub (:1338) into one binary.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidRSAESOAEP     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     envelopedData `asn1:"explicit,tag:0"`
}

type envelopedData struct {
	Version              int
	RecipientInfos       []keyTransRecipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type keyTransRecipientInfo struct {
	Version                int
	RecipientIdentifier    []byte `asn1:"tag:0"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0"`
}

type kmsDecryptRequest struct {
	CiphertextBlob    string          `json:"CiphertextBlob,omitempty"`
	KeyId             string          `json:"KeyId,omitempty"`
	EncryptionContext json.RawMessage `json:"EncryptionContext,omitempty"`
	Recipient         *kmsRecipient   `json:"Recipient,omitempty"`
}

type kmsRecipient struct {
	AttestationDocument    string `json:"AttestationDocument"`
	KeyEncryptionAlgorithm string `json:"KeyEncryptionAlgorithm"`
}

type kmsDecryptResponse struct {
	KeyId               string `json:"KeyId,omitempty"`
	Plaintext           string `json:"Plaintext,omitempty"`
	EncryptionAlgorithm string `json:"EncryptionAlgorithm,omitempty"`
}

type kmsDecryptResponseWithRecipient struct {
	KeyId                  string `json:"KeyId,omitempty"`
	CiphertextForRecipient string `json:"CiphertextForRecipient,omitempty"`
	EncryptionAlgorithm    string `json:"EncryptionAlgorithm,omitempty"`
}

type kmsGenerateDataKeyRequest struct {
	KeyId         string        `json:"KeyId,omitempty"`
	NumberOfBytes int           `json:"NumberOfBytes,omitempty"`
	KeySpec       string        `json:"KeySpec,omitempty"`
	Recipient     *kmsRecipient `json:"Recipient,omitempty"`
}

type kmsGenerateDataKeyResponse struct {
	KeyId          string `json:"KeyId,omitempty"`
	CiphertextBlob string `json:"CiphertextBlob,omitempty"`
	Plaintext      string `json:"Plaintext,omitempty"`
}

// kmsGenerateDataKeyResponseWithRecipient mirrors AWS: with a Recipient, KMS
// returns the wrapped key (CiphertextBlob) plus the plaintext enveloped to the
// enclave (CiphertextForRecipient) and omits Plaintext.
type kmsGenerateDataKeyResponseWithRecipient struct {
	KeyId                  string `json:"KeyId,omitempty"`
	CiphertextBlob         string `json:"CiphertextBlob,omitempty"`
	CiphertextForRecipient string `json:"CiphertextForRecipient,omitempty"`
}

type imdsCredentials struct {
	Code            string `json:"Code"`
	LastUpdated     string `json:"LastUpdated"`
	Type            string `json:"Type"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

func main() {
	kmsListen := envOrDefault("KMS_PROXY_LISTEN_ADDR", ":4000")
	upstreamKMS := envOrDefault("UPSTREAM_KMS_URL", "http://local-kms:8080")
	imdsListen := envOrDefault("IMDS_LISTEN_ADDR", ":1338")

	upstream, err := url.Parse(upstreamKMS)
	if err != nil {
		log.Fatalf("invalid UPSTREAM_KMS_URL %q: %v", upstreamKMS, err)
	}

	errCh := make(chan error, 2)

	go func() {
		errCh <- runKMSProxy(kmsListen, upstream)
	}()
	go func() {
		errCh <- runMockIMDS(imdsListen)
	}()

	// First fatal error from either listener wins.
	log.Fatal(<-errCh)
}

func runKMSProxy(listenAddr string, upstream *url.URL) error {
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			switch r.Header.Get("X-Amz-Target") {
			case "TrentService.Decrypt":
				handleDecrypt(w, r, upstream, proxy)
				return
			case "TrentService.GenerateDataKey":
				handleGenerateDataKey(w, r, upstream, proxy)
				return
			}
		}
		proxy.ServeHTTP(w, r)
	})

	log.Printf("kms-proxy listening on %s, forwarding to %s", listenAddr, upstream.String())
	return http.ListenAndServe(listenAddr, mux)
}

func runMockIMDS(listenAddr string) error {
	const roleName = "test-enclave-role"

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("PUT /latest/api/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("mock-imds-token"))
	})

	mux.HandleFunc("GET /latest/meta-data/iam/security-credentials/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(roleName))
	})

	mux.HandleFunc("GET /latest/meta-data/iam/security-credentials/{role}", func(w http.ResponseWriter, _ *http.Request) {
		creds := imdsCredentials{
			Code:            "Success",
			LastUpdated:     "2026-01-01T00:00:00Z",
			Type:            "AWS-HMAC",
			AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Token:           "mock-session-token",
			Expiration:      "2099-12-31T23:59:59Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(creds)
	})

	log.Printf("mock-imds listening on %s", listenAddr)
	return http.ListenAndServe(listenAddr, mux)
}

func handleDecrypt(w http.ResponseWriter, r *http.Request, upstream *url.URL, proxy *httputil.ReverseProxy) {
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
		return
	}

	var req kmsDecryptRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("parse request: %v", err), http.StatusBadRequest)
		return
	}

	if req.Recipient == nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		proxy.ServeHTTP(w, r)
		return
	}

	rsaPub, err := extractRSAPubKeyFromAttestationDoc(req.Recipient.AttestationDocument)
	if err != nil {
		http.Error(w, fmt.Sprintf("extract RSA key from attestation doc: %v", err), http.StatusBadRequest)
		return
	}

	req.Recipient = nil
	strippedBody, err := json.Marshal(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("marshal stripped request: %v", err), http.StatusInternalServerError)
		return
	}

	respBody, ok := forwardToUpstream(w, r, upstream, strippedBody)
	if !ok {
		return
	}

	var decryptResp kmsDecryptResponse
	if err := json.Unmarshal(respBody, &decryptResp); err != nil {
		http.Error(w, fmt.Sprintf("parse upstream response: %v", err), http.StatusBadGateway)
		return
	}

	plaintext, err := base64.StdEncoding.DecodeString(decryptResp.Plaintext)
	if err != nil {
		http.Error(w, fmt.Sprintf("decode plaintext: %v", err), http.StatusBadGateway)
		return
	}

	cmsData, err := buildCMSEnvelopedData(plaintext, rsaPub)
	if err != nil {
		http.Error(w, fmt.Sprintf("build CMS EnvelopedData: %v", err), http.StatusInternalServerError)
		return
	}

	result := kmsDecryptResponseWithRecipient{
		KeyId:                  decryptResp.KeyId,
		CiphertextForRecipient: base64.StdEncoding.EncodeToString(cmsData),
		EncryptionAlgorithm:    "SYMMETRIC_DEFAULT",
	}

	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

// handleGenerateDataKey mirrors handleDecrypt for GenerateDataKey: local-kms has
// no Recipient support, so the proxy strips the attestation, forwards, then
// CMS-envelopes the returned Plaintext into CiphertextForRecipient — keeping the
// wrapped CiphertextBlob and dropping Plaintext, as real Nitro KMS does.
func handleGenerateDataKey(w http.ResponseWriter, r *http.Request, upstream *url.URL, proxy *httputil.ReverseProxy) {
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
		return
	}

	var req kmsGenerateDataKeyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("parse request: %v", err), http.StatusBadRequest)
		return
	}

	if req.Recipient == nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		proxy.ServeHTTP(w, r)
		return
	}

	rsaPub, err := extractRSAPubKeyFromAttestationDoc(req.Recipient.AttestationDocument)
	if err != nil {
		http.Error(w, fmt.Sprintf("extract RSA key from attestation doc: %v", err), http.StatusBadRequest)
		return
	}

	req.Recipient = nil
	strippedBody, err := json.Marshal(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("marshal stripped request: %v", err), http.StatusInternalServerError)
		return
	}

	respBody, ok := forwardToUpstream(w, r, upstream, strippedBody)
	if !ok {
		return
	}

	var genResp kmsGenerateDataKeyResponse
	if err := json.Unmarshal(respBody, &genResp); err != nil {
		http.Error(w, fmt.Sprintf("parse upstream response: %v", err), http.StatusBadGateway)
		return
	}

	plaintext, err := base64.StdEncoding.DecodeString(genResp.Plaintext)
	if err != nil {
		http.Error(w, fmt.Sprintf("decode plaintext: %v", err), http.StatusBadGateway)
		return
	}

	cmsData, err := buildCMSEnvelopedData(plaintext, rsaPub)
	if err != nil {
		http.Error(w, fmt.Sprintf("build CMS EnvelopedData: %v", err), http.StatusInternalServerError)
		return
	}

	result := kmsGenerateDataKeyResponseWithRecipient{
		KeyId:                  genResp.KeyId,
		CiphertextBlob:         genResp.CiphertextBlob,
		CiphertextForRecipient: base64.StdEncoding.EncodeToString(cmsData),
	}

	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

// forwardToUpstream sends the Recipient-stripped body to the upstream KMS,
// copying the AWS signing headers. On a 200 it returns the response body; on a
// transport error or non-200 it writes the error/passthrough to w and returns
// ok=false.
func forwardToUpstream(w http.ResponseWriter, r *http.Request, upstream *url.URL, strippedBody []byte) ([]byte, bool) {
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream.String()+"/", bytes.NewReader(strippedBody))
	if err != nil {
		http.Error(w, fmt.Sprintf("create upstream request: %v", err), http.StatusInternalServerError)
		return nil, false
	}
	for _, h := range []string{"X-Amz-Target", "Content-Type", "Authorization", "X-Amz-Date", "X-Amz-Security-Token"} {
		if v := r.Header.Get(h); v != "" {
			upstreamReq.Header.Set(h, v)
		}
	}
	upstreamReq.ContentLength = int64(len(strippedBody))

	resp, err := http.DefaultClient.Do(upstreamReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream request: %v", err), http.StatusBadGateway)
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read upstream response: %v", err), http.StatusBadGateway)
		return nil, false
	}

	if resp.StatusCode != http.StatusOK {
		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return nil, false
	}

	return respBody, true
}

// buildCMSEnvelopedData mirrors AWS Nitro KMS's response shape:
// AES-256-CBC over the plaintext, RSA-OAEP-SHA256 over the CEK.
func buildCMSEnvelopedData(plaintext []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("generate CEK: %w", err)
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("generate IV: %w", err)
	}

	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	encryptedCEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, cek, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encrypt CEK: %w", err)
	}

	eci := encryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{Tag: asn1.TagOctetString, Class: asn1.ClassUniversal, Bytes: iv},
		},
		EncryptedContent: asn1.RawValue{
			Tag:   0,
			Class: asn1.ClassContextSpecific,
			Bytes: ciphertext,
		},
	}

	ed := envelopedData{
		Version: 2,
		RecipientInfos: []keyTransRecipientInfo{{
			Version:             2,
			RecipientIdentifier: []byte{},
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: oidRSAESOAEP,
			},
			EncryptedKey: encryptedCEK,
		}},
		EncryptedContentInfo: eci,
	}

	ci := contentInfo{
		ContentType: oidEnvelopedData,
		Content:     ed,
	}

	return asn1.Marshal(ci)
}

func extractRSAPubKeyFromAttestationDoc(attestB64 string) (*rsa.PublicKey, error) {
	attestRaw, err := base64.StdEncoding.DecodeString(attestB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	var tagged cbor.Tag
	if err := cbor.Unmarshal(attestRaw, &tagged); err == nil {
		if innerBytes, err := cbor.Marshal(tagged.Content); err == nil {
			attestRaw = innerBytes
		}
	}

	var coseSign1 []cbor.RawMessage
	if err := cbor.Unmarshal(attestRaw, &coseSign1); err != nil {
		return nil, fmt.Errorf("unmarshal COSE Sign1: %w", err)
	}
	if len(coseSign1) < 4 {
		return nil, fmt.Errorf("invalid COSE Sign1: expected 4 elements, got %d", len(coseSign1))
	}

	var payloadBytes []byte
	if err := cbor.Unmarshal(coseSign1[2], &payloadBytes); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	var doc struct {
		PublicKey []byte `cbor:"public_key"`
	}
	if err := cbor.Unmarshal(payloadBytes, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal attestation doc: %w", err)
	}
	if len(doc.PublicKey) == 0 {
		return nil, fmt.Errorf("no public_key in attestation document")
	}

	pub, err := x509.ParsePKIXPublicKey(doc.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA, got %T", pub)
	}
	return rsaPub, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}
