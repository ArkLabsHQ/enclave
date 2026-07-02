package runtime

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// testDEK is a fixed 32-byte AES-256 key; the helpers never touch S3/KMS/NSM
// (secureRandom falls back to crypto/rand off-enclave), so they unit-test cleanly.
var testDEK = bytes.Repeat([]byte{0x42}, 32)

func TestSealOpenRoundTrip(t *testing.T) {
	aad := storageAAD("user/key")
	pt := []byte("hello enclave")

	blob, err := sealStorage(testDEK, pt, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if blob[0] != storageFormatV1 {
		t.Fatalf("version byte = %#x, want %#x", blob[0], storageFormatV1)
	}
	if want := storageHeaderLen + len(pt) + gcmTagSize; len(blob) != want {
		t.Fatalf("blob len = %d, want %d", len(blob), want)
	}

	got, err := openStorage(testDEK, blob, aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip = %q, want %q", got, pt)
	}
}

// TestRelabelRejected is the core Tier-0 guarantee: a blob sealed for one key
// must not open under another key's AAD.
func TestRelabelRejected(t *testing.T) {
	blob, err := sealStorage(testDEK, []byte("secret"), storageAAD("foo"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := openStorage(testDEK, blob, storageAAD("bar")); err == nil {
		t.Fatal("open under a different key's AAD must fail (relabel)")
	}
}

// TestCrossDeploymentRejected: a blob sealed under one deployment must not open
// with an AAD built for another deployment (cross-deployment replay).
func TestCrossDeploymentRejected(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	prodAAD := storageAAD("k")
	blob, err := sealStorage(testDEK, []byte("v"), prodAAD)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	t.Setenv("ENCLAVE_DEPLOYMENT", "staging")
	if _, err := openStorage(testDEK, blob, storageAAD("k")); err == nil {
		t.Fatal("open across deployments must fail (replay)")
	}
}

// TestCrossAppRejected: same key, different app name → reject.
func TestCrossAppRejected(t *testing.T) {
	t.Setenv("ENCLAVE_APP_NAME", "app-a")
	blob, err := sealStorage(testDEK, []byte("v"), storageAAD("k"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	t.Setenv("ENCLAVE_APP_NAME", "app-b")
	if _, err := openStorage(testDEK, blob, storageAAD("k")); err == nil {
		t.Fatal("open across app names must fail")
	}
}

func TestTamperRejected(t *testing.T) {
	aad := storageAAD("k")
	blob, err := sealStorage(testDEK, []byte("plaintext"), aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Flip a byte in the ciphertext/tag region.
	ctTamper := append([]byte(nil), blob...)
	ctTamper[len(ctTamper)-1] ^= 0xff
	if _, err := openStorage(testDEK, ctTamper, aad); err == nil {
		t.Fatal("tampered ciphertext must fail")
	}

	// Flip the version byte → unversioned, must be rejected outright.
	verTamper := append([]byte(nil), blob...)
	verTamper[0] = 0x02
	if _, err := openStorage(testDEK, verTamper, aad); err == nil {
		t.Fatal("wrong version byte must be rejected")
	}
}

func TestShortBlobRejected(t *testing.T) {
	aad := storageAAD("k")
	for _, blob := range [][]byte{
		nil,
		{storageFormatV1},
		make([]byte, minStorageBlobLen-1), // one byte under the v1 minimum
	} {
		if _, err := openStorage(testDEK, blob, aad); err == nil {
			t.Fatalf("short blob (len %d) must be rejected", len(blob))
		}
	}
}

// TestLegacyFormatRejected: an old nil-AAD, unversioned blob (nonce || ct) must
// not decrypt under the clean-cutover reader.
func TestLegacyFormatRejected(t *testing.T) {
	block, _ := aes.NewCipher(testDEK)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, nonceSize)
	legacy := append(nonce, gcm.Seal(nil, nonce, []byte("old"), nil)...)

	if _, err := openStorage(testDEK, legacy, storageAAD("k")); err == nil {
		t.Fatal("legacy unversioned blob must be rejected (clean cutover)")
	}
}

func TestWrongDEKRejected(t *testing.T) {
	aad := storageAAD("k")
	blob, err := sealStorage(testDEK, []byte("v"), aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	otherDEK := bytes.Repeat([]byte{0x99}, 32)
	if _, err := openStorage(otherDEK, blob, aad); err == nil {
		t.Fatal("open with a different DEK must fail")
	}
}
