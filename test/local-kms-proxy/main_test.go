package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// buildTestAttestationDoc constructs a minimal COSE Sign1 attestation document
// with the given RSA public key in the payload's public_key field.
// If withTag is true, wraps the array with CBOR tag 18.
func buildTestAttestationDoc(t *testing.T, pubKey *rsa.PublicKey, withTag bool) string {
	t.Helper()

	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	type attestPayload struct {
		PublicKey []byte `cbor:"public_key"`
	}
	payloadBytes, err := cbor.Marshal(attestPayload{PublicKey: pubDER})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	protectedHeader, err := cbor.Marshal(map[int]int{1: -7})
	if err != nil {
		t.Fatalf("marshal protected header: %v", err)
	}

	coseArray := []interface{}{
		protectedHeader,
		map[int]int{},
		payloadBytes,
		[]byte{0, 0},
	}

	var docBytes []byte
	if withTag {
		tagged := cbor.Tag{
			Number:  18,
			Content: coseArray,
		}
		docBytes, err = cbor.Marshal(tagged)
	} else {
		docBytes, err = cbor.Marshal(coseArray)
	}
	if err != nil {
		t.Fatalf("marshal COSE Sign1: %v", err)
	}

	return base64.StdEncoding.EncodeToString(docBytes)
}

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return privKey
}

// parseEnvelopedDataRaw manually walks the ASN.1 structure of an EnvelopedData
// to extract the encrypted CEK, IV, and encrypted content bytes.
func parseEnvelopedDataRaw(t *testing.T, edBytes []byte) (encryptedCEK, iv, encryptedContent []byte) {
	t.Helper()

	var edSeq asn1.RawValue
	if _, err := asn1.Unmarshal(edBytes, &edSeq); err != nil {
		t.Fatalf("parse EnvelopedData SEQUENCE: %v", err)
	}

	remaining := edSeq.Bytes

	var version int
	remaining, err := asn1.Unmarshal(remaining, &version)
	if err != nil {
		t.Fatalf("parse EnvelopedData version: %v", err)
	}

	var recipientInfosSet asn1.RawValue
	remaining, err = asn1.Unmarshal(remaining, &recipientInfosSet)
	if err != nil {
		t.Fatalf("parse recipientInfos SET: %v", err)
	}

	var ktriSeq asn1.RawValue
	if _, err := asn1.Unmarshal(recipientInfosSet.Bytes, &ktriSeq); err != nil {
		t.Fatalf("parse KeyTransRecipientInfo SEQUENCE: %v", err)
	}

	ktriRemaining := ktriSeq.Bytes

	var ktriVersion int
	ktriRemaining, err = asn1.Unmarshal(ktriRemaining, &ktriVersion)
	if err != nil {
		t.Fatalf("parse ktri version: %v", err)
	}

	var ridRaw asn1.RawValue
	ktriRemaining, err = asn1.Unmarshal(ktriRemaining, &ridRaw)
	if err != nil {
		t.Fatalf("parse recipientIdentifier: %v", err)
	}

	var keaSeq asn1.RawValue
	ktriRemaining, err = asn1.Unmarshal(ktriRemaining, &keaSeq)
	if err != nil {
		t.Fatalf("parse keyEncryptionAlgorithm: %v", err)
	}

	var encKey asn1.RawValue
	_, err = asn1.Unmarshal(ktriRemaining, &encKey)
	if err != nil {
		t.Fatalf("parse encryptedKey: %v", err)
	}
	encryptedCEK = encKey.Bytes

	var eciSeq asn1.RawValue
	_, err = asn1.Unmarshal(remaining, &eciSeq)
	if err != nil {
		t.Fatalf("parse encryptedContentInfo SEQUENCE: %v", err)
	}

	eciRemaining := eciSeq.Bytes

	var contentTypeOID asn1.ObjectIdentifier
	eciRemaining, err = asn1.Unmarshal(eciRemaining, &contentTypeOID)
	if err != nil {
		t.Fatalf("parse eci contentType: %v", err)
	}

	var ceaSeq asn1.RawValue
	eciRemaining, err = asn1.Unmarshal(eciRemaining, &ceaSeq)
	if err != nil {
		t.Fatalf("parse contentEncryptionAlgorithm: %v", err)
	}

	ceaInner := ceaSeq.Bytes
	var ceaOID asn1.ObjectIdentifier
	ceaInner, err = asn1.Unmarshal(ceaInner, &ceaOID)
	if err != nil {
		t.Fatalf("parse cea OID: %v", err)
	}
	var ivRaw asn1.RawValue
	_, err = asn1.Unmarshal(ceaInner, &ivRaw)
	if err != nil {
		t.Fatalf("parse IV from cea parameters: %v", err)
	}
	iv = ivRaw.Bytes

	var encContentRaw asn1.RawValue
	_, err = asn1.Unmarshal(eciRemaining, &encContentRaw)
	if err != nil {
		t.Fatalf("parse encryptedContent: %v", err)
	}
	encryptedContent = encContentRaw.Bytes

	return encryptedCEK, iv, encryptedContent
}

// decryptCMSEnvelopedData is a test helper that takes raw CMS EnvelopedData bytes (the
// outer ContentInfo) and an RSA private key, then returns the decrypted plaintext.
func decryptCMSEnvelopedData(t *testing.T, cmsBytes []byte, privKey *rsa.PrivateKey) []byte {
	t.Helper()

	if len(cmsBytes) == 0 {
		t.Fatal("CMS envelope is empty")
	}
	if cmsBytes[0] != 0x30 {
		t.Fatalf("expected DER SEQUENCE tag 0x30, got 0x%02x", cmsBytes[0])
	}

	var outerSeq asn1.RawValue
	rest, err := asn1.Unmarshal(cmsBytes, &outerSeq)
	if err != nil {
		t.Fatalf("unmarshal outer SEQUENCE: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after ContentInfo: %d", len(rest))
	}

	var oid asn1.ObjectIdentifier
	innerRest, err := asn1.Unmarshal(outerSeq.Bytes, &oid)
	if err != nil {
		t.Fatalf("unmarshal ContentType OID: %v", err)
	}
	if !oid.Equal(oidEnvelopedData) {
		t.Fatalf("expected EnvelopedData OID %v, got %v", oidEnvelopedData, oid)
	}

	var wrappedContent asn1.RawValue
	if _, err := asn1.Unmarshal(innerRest, &wrappedContent); err != nil {
		t.Fatalf("unmarshal wrapped content: %v", err)
	}

	edInput := wrappedContent.FullBytes
	if len(edInput) == 0 {
		edInput = wrappedContent.Bytes
	}
	encryptedCEK, iv, encryptedContent := parseEnvelopedDataRaw(t, edInput)

	cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encryptedCEK, nil)
	if err != nil {
		t.Fatalf("RSA-OAEP decrypt CEK: %v", err)
	}
	if len(cek) != 32 {
		t.Fatalf("expected 32-byte CEK, got %d", len(cek))
	}
	if len(iv) != 16 {
		t.Fatalf("expected 16-byte IV, got %d", len(iv))
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatalf("create AES cipher: %v", err)
	}
	decrypted := make([]byte, len(encryptedContent))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decrypted, encryptedContent)

	if len(decrypted) == 0 {
		t.Fatal("decrypted content is empty")
	}
	padLen := int(decrypted[len(decrypted)-1])
	if padLen < 1 || padLen > aes.BlockSize || padLen > len(decrypted) {
		t.Fatalf("invalid PKCS#7 padding: %d", padLen)
	}
	for i := len(decrypted) - padLen; i < len(decrypted); i++ {
		if decrypted[i] != byte(padLen) {
			t.Fatalf("invalid PKCS#7 padding byte at position %d: expected %d, got %d", i, padLen, decrypted[i])
		}
	}
	return decrypted[:len(decrypted)-padLen]
}

func TestExtractRSAPubKeyFromAttestationDoc(t *testing.T) {
	privKey := generateTestRSAKey(t)
	doc := buildTestAttestationDoc(t, &privKey.PublicKey, true)

	extracted, err := extractRSAPubKeyFromAttestationDoc(doc)
	if err != nil {
		t.Fatalf("extractRSAPubKeyFromAttestationDoc: %v", err)
	}

	if extracted.N.Cmp(privKey.PublicKey.N) != 0 {
		t.Error("extracted key N does not match original")
	}
	if extracted.E != privKey.PublicKey.E {
		t.Error("extracted key E does not match original")
	}
}

func TestExtractRSAPubKeyWithoutTag(t *testing.T) {
	privKey := generateTestRSAKey(t)
	doc := buildTestAttestationDoc(t, &privKey.PublicKey, false)

	extracted, err := extractRSAPubKeyFromAttestationDoc(doc)
	if err != nil {
		t.Fatalf("extractRSAPubKeyFromAttestationDoc (no tag): %v", err)
	}

	if extracted.N.Cmp(privKey.PublicKey.N) != 0 {
		t.Error("extracted key N does not match original")
	}
	if extracted.E != privKey.PublicKey.E {
		t.Error("extracted key E does not match original")
	}
}

func TestExtractRSAPubKeyErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "invalid base64",
			input: "!!!not-valid-base64!!!",
		},
		{
			name:  "valid base64 but malformed CBOR",
			input: base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0xfd}),
		},
		{
			name: "COSE Sign1 with fewer than 4 elements",
			input: func() string {
				twoElem := []interface{}{[]byte{0x01}, []byte{0x02}}
				b, _ := cbor.Marshal(twoElem)
				return base64.StdEncoding.EncodeToString(b)
			}(),
		},
		{
			name: "attestation doc with empty public_key",
			input: func() string {
				type emptyPubKey struct {
					PublicKey []byte `cbor:"public_key"`
				}
				payload, _ := cbor.Marshal(emptyPubKey{PublicKey: nil})
				protHdr, _ := cbor.Marshal(map[int]int{1: -7})
				arr := []interface{}{protHdr, map[int]int{}, payload, []byte{0x00}}
				b, _ := cbor.Marshal(arr)
				return base64.StdEncoding.EncodeToString(b)
			}(),
		},
		{
			name: "public key with invalid DER bytes",
			input: func() string {
				type badPubKey struct {
					PublicKey []byte `cbor:"public_key"`
				}
				payload, _ := cbor.Marshal(badPubKey{PublicKey: []byte{0xDE, 0xAD, 0xBE, 0xEF}})
				protHdr, _ := cbor.Marshal(map[int]int{1: -7})
				arr := []interface{}{protHdr, map[int]int{}, payload, []byte{0x00}}
				b, _ := cbor.Marshal(arr)
				return base64.StdEncoding.EncodeToString(b)
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := extractRSAPubKeyFromAttestationDoc(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestBuildCMSEnvelopedDataRoundTrip(t *testing.T) {
	privKey := generateTestRSAKey(t)
	plaintext := []byte("hello, this is a test plaintext for CMS envelope!")

	cmsBytes, err := buildCMSEnvelopedData(plaintext, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("buildCMSEnvelopedData: %v", err)
	}

	decrypted := decryptCMSEnvelopedData(t, cmsBytes, privKey)
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted plaintext mismatch:\n  got:  %q\n  want: %q", decrypted, plaintext)
	}
}

func TestBuildCMSEnvelopedDataDifferentPlaintextSizes(t *testing.T) {
	privKey := generateTestRSAKey(t)

	sizes := []int{0, 1, 15, 16, 17, 31, 32, 100}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			plaintext := make([]byte, size)
			for i := range plaintext {
				plaintext[i] = byte(i % 256)
			}

			cmsBytes, err := buildCMSEnvelopedData(plaintext, &privKey.PublicKey)
			if err != nil {
				t.Fatalf("buildCMSEnvelopedData(size=%d): %v", size, err)
			}

			decrypted := decryptCMSEnvelopedData(t, cmsBytes, privKey)
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("round-trip failed for size %d:\n  got:  %x\n  want: %x", size, decrypted, plaintext)
			}
		})
	}
}

func TestHandleDecrypt(t *testing.T) {
	testPlaintext := []byte("secret-key-material-for-testing")
	testKeyId := "arn:aws:kms:us-east-1:123456789012:key/test-key-id"

	// Mock upstream KMS that returns a simple Decrypt response with base64-encoded plaintext.
	mockKMS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		var req kmsDecryptRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.Recipient != nil {
			t.Error("upstream received request with Recipient still set")
		}
		resp := kmsDecryptResponse{
			KeyId:               testKeyId,
			Plaintext:           base64.StdEncoding.EncodeToString(testPlaintext),
			EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockKMS.Close()

	// Build a proxy server using the same handler logic as main().
	upstreamURL, _ := url.Parse(mockKMS.URL)
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		if target == "TrentService.Decrypt" && r.Method == http.MethodPost {
			handleDecrypt(w, r, upstreamURL, proxy)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer proxyServer.Close()

	t.Run("no Recipient", func(t *testing.T) {
		reqBody := kmsDecryptRequest{
			CiphertextBlob: base64.StdEncoding.EncodeToString([]byte("fake-ciphertext")),
			KeyId:          testKeyId,
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/", bytes.NewReader(body))
		req.Header.Set("X-Amz-Target", "TrentService.Decrypt")
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var result kmsDecryptResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if result.KeyId != testKeyId {
			t.Errorf("KeyId mismatch: got %q, want %q", result.KeyId, testKeyId)
		}
		if result.Plaintext != base64.StdEncoding.EncodeToString(testPlaintext) {
			t.Errorf("Plaintext mismatch")
		}
	})

	t.Run("with valid Recipient", func(t *testing.T) {
		privKey := generateTestRSAKey(t)
		attestDoc := buildTestAttestationDoc(t, &privKey.PublicKey, true)

		reqBody := kmsDecryptRequest{
			CiphertextBlob: base64.StdEncoding.EncodeToString([]byte("fake-ciphertext")),
			KeyId:          testKeyId,
			Recipient: &kmsRecipient{
				AttestationDocument:    attestDoc,
				KeyEncryptionAlgorithm: "RSAES_OAEP_SHA_256",
			},
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/", bytes.NewReader(body))
		req.Header.Set("X-Amz-Target", "TrentService.Decrypt")
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var result kmsDecryptResponseWithRecipient
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if result.KeyId != testKeyId {
			t.Errorf("KeyId mismatch: got %q, want %q", result.KeyId, testKeyId)
		}
		if result.CiphertextForRecipient == "" {
			t.Fatal("CiphertextForRecipient is empty")
		}

		cmsBytes, err := base64.StdEncoding.DecodeString(result.CiphertextForRecipient)
		if err != nil {
			t.Fatalf("decode CiphertextForRecipient: %v", err)
		}

		decrypted := decryptCMSEnvelopedData(t, cmsBytes, privKey)
		if !bytes.Equal(decrypted, testPlaintext) {
			t.Fatalf("decrypted plaintext mismatch:\n  got:  %x\n  want: %x", decrypted, testPlaintext)
		}
	})

	t.Run("invalid attestation document", func(t *testing.T) {
		reqBody := kmsDecryptRequest{
			CiphertextBlob: base64.StdEncoding.EncodeToString([]byte("fake-ciphertext")),
			KeyId:          testKeyId,
			Recipient: &kmsRecipient{
				AttestationDocument:    base64.StdEncoding.EncodeToString([]byte("not-valid-cbor")),
				KeyEncryptionAlgorithm: "RSAES_OAEP_SHA_256",
			},
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/", bytes.NewReader(body))
		req.Header.Set("X-Amz-Target", "TrentService.Decrypt")
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected error status code, got 200")
		}
	})
}
