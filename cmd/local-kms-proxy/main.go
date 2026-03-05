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

// ASN.1 OIDs for CMS EnvelopedData construction.
var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidRSAESOAEP     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// ASN.1 structures for CMS EnvelopedData.

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
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

// KMS request/response types.

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

func main() {
	listenAddr := envOrDefault("LISTEN_ADDR", ":4000")
	upstreamURL := envOrDefault("UPSTREAM_KMS_URL", "http://localhost:8080")

	upstream, err := url.Parse(upstreamURL)
	if err != nil {
		log.Fatalf("invalid UPSTREAM_KMS_URL %q: %v", upstreamURL, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Check if this is a Decrypt call with Recipient.
		target := r.Header.Get("X-Amz-Target")
		if target == "TrentService.Decrypt" && r.Method == http.MethodPost {
			handleDecrypt(w, r, upstream, proxy)
			return
		}
		// All other requests: pass through.
		proxy.ServeHTTP(w, r)
	})

	log.Printf("local-kms-proxy listening on %s, forwarding to %s", listenAddr, upstreamURL)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func handleDecrypt(w http.ResponseWriter, r *http.Request, upstream *url.URL, proxy *httputil.ReverseProxy) {
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
		return
	}

	var req kmsDecryptRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("parse request: %v", err), http.StatusBadRequest)
		return
	}

	// If no Recipient, pass through as-is.
	if req.Recipient == nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		proxy.ServeHTTP(w, r)
		return
	}

	// Extract the RSA public key from the attestation document.
	rsaPub, err := extractRSAPubKeyFromAttestationDoc(req.Recipient.AttestationDocument)
	if err != nil {
		http.Error(w, fmt.Sprintf("extract RSA key from attestation doc: %v", err), http.StatusBadRequest)
		return
	}

	// Strip Recipient and forward to upstream local-kms.
	req.Recipient = nil
	strippedBody, err := json.Marshal(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("marshal stripped request: %v", err), http.StatusInternalServerError)
		return
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream.String()+"/", bytes.NewReader(strippedBody))
	if err != nil {
		http.Error(w, fmt.Sprintf("create upstream request: %v", err), http.StatusInternalServerError)
		return
	}
	// Copy relevant headers.
	for _, h := range []string{"X-Amz-Target", "Content-Type", "Authorization", "X-Amz-Date", "X-Amz-Security-Token"} {
		if v := r.Header.Get(h); v != "" {
			upstreamReq.Header.Set(h, v)
		}
	}
	upstreamReq.ContentLength = int64(len(strippedBody))

	resp, err := http.DefaultClient.Do(upstreamReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream request: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read upstream response: %v", err), http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusOK {
		// Forward error response as-is.
		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
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

	// Wrap plaintext in CMS EnvelopedData.
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
	json.NewEncoder(w).Encode(result)
}

// buildCMSEnvelopedData constructs a CMS EnvelopedData (ContentInfo) wrapping
// the plaintext with AES-256-CBC content encryption and RSA-OAEP-SHA256 key transport.
func buildCMSEnvelopedData(plaintext []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	// 1. Generate random AES-256 key (CEK) and IV.
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("generate CEK: %w", err)
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("generate IV: %w", err)
	}

	// 2. PKCS#7 pad the plaintext.
	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	// 3. Encrypt with AES-256-CBC.
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	// 4. Encrypt CEK with RSA-OAEP-SHA256.
	encryptedCEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, cek, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encrypt CEK: %w", err)
	}

	// 5. Build ASN.1 structure.
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

	edBytes, err := asn1.Marshal(ed)
	if err != nil {
		return nil, fmt.Errorf("marshal enveloped data: %w", err)
	}

	ci := contentInfo{
		ContentType: oidEnvelopedData,
		Content:     asn1.RawValue{FullBytes: edBytes},
	}

	return asn1.Marshal(ci)
}

// extractRSAPubKeyFromAttestationDoc parses a base64-encoded COSE Sign1
// attestation document and extracts the RSA public key from the public_key field.
func extractRSAPubKeyFromAttestationDoc(attestB64 string) (*rsa.PublicKey, error) {
	attestRaw, err := base64.StdEncoding.DecodeString(attestB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	// COSE Sign1 may be CBOR-tagged (tag 18). Try to unwrap tag first.
	var tagged cbor.Tag
	if err := cbor.Unmarshal(attestRaw, &tagged); err == nil {
		// Successfully unwrapped tag, use inner content.
		innerBytes, err := cbor.Marshal(tagged.Content)
		if err == nil {
			attestRaw = innerBytes
		}
	}

	// COSE Sign1 is a CBOR array: [protected, unprotected, payload, signature].
	var coseSign1 []cbor.RawMessage
	if err := cbor.Unmarshal(attestRaw, &coseSign1); err != nil {
		return nil, fmt.Errorf("unmarshal COSE Sign1: %w", err)
	}
	if len(coseSign1) < 4 {
		return nil, fmt.Errorf("invalid COSE Sign1: expected 4 elements, got %d", len(coseSign1))
	}

	// Payload is element [2], CBOR bstr.
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
