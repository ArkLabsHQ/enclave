package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"testing"
)

func TestSignature_VerifierRoundTrip(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "dev")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}

	var pcr0 [sha512.Size384]byte
	for i := range pcr0 {
		pcr0[i] = byte(i)
	}
	pcr0Hex := hex.EncodeToString(pcr0[:])

	sigDER, err := ecdsa.SignASN1(rand.Reader, priv, pcr0[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigDER)

	pubkeyPEM := marshalPubKeyPEM(t, &priv.PublicKey)

	fake := &fakeSSM{params: map[string]string{
		"/dev/myapp/Signing/PubkeyPEM": pubkeyPEM,
		"/dev/myapp/Signing/PCR0":      pcr0Hex,
		"/dev/myapp/Signing/Signature": sigB64,
	}}

	sig := NewSignature()
	sig.Load(context.Background(), fake)
	if !sig.Ready() {
		t.Fatalf("Signature.Ready() = false after Load with all params present")
	}

	snap := sig.Snapshot()
	if snap == nil {
		t.Fatal("Snapshot() = nil after Ready() = true")
	}
	if snap.PubkeyPEM != pubkeyPEM {
		t.Errorf("pubkey round-trip drift")
	}
	if snap.PCR0Hex != pcr0Hex {
		t.Errorf("pcr0_hex = %q, want %q", snap.PCR0Hex, pcr0Hex)
	}

	verifierPub := parsePubKeyPEM(t, snap.PubkeyPEM)
	pcr0Bytes, err := hex.DecodeString(snap.PCR0Hex)
	if err != nil {
		t.Fatalf("decode pcr0_hex: %v", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(snap.SignatureB64)
	if err != nil {
		t.Fatalf("decode signature_b64: %v", err)
	}
	if !ecdsa.VerifyASN1(verifierPub, pcr0Bytes, sigBytes) {
		t.Fatal("ecdsa.VerifyASN1 returned false")
	}
}

func TestSignature_NotProvisioned(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "dev")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")

	fake := &fakeSSM{params: map[string]string{}}

	sig := NewSignature()
	sig.Load(context.Background(), fake)
	if sig.Ready() {
		t.Fatal("Signature.Ready() = true with no SSM params; want false")
	}
	if sig.Snapshot() != nil {
		t.Fatal("Snapshot() != nil when not ready")
	}
}

func TestSignature_PartialParams(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "dev")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")

	fake := &fakeSSM{params: map[string]string{
		"/dev/myapp/Signing/PubkeyPEM": "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----",
	}}

	sig := NewSignature()
	sig.Load(context.Background(), fake)
	if sig.Ready() {
		t.Fatal("Signature.Ready() = true with partial params; want false")
	}
}

func TestSignature_SSMError(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "dev")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")

	fake := &fakeSSM{err: errors.New("AccessDenied")}

	sig := NewSignature()
	sig.Load(context.Background(), fake)
	if sig.Ready() {
		t.Fatal("Signature.Ready() = true after SSM error; want false")
	}
}

func marshalPubKeyPEM(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func parsePubKeyPEM(t *testing.T, pemStr string) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatalf("pem.Decode returned nil for: %q", pemStr)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse pubkey: %v", err)
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("pubkey is %T, want *ecdsa.PublicKey", pub)
	}
	return ecdsaPub
}
