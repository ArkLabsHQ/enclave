package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/hf/nitrite"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
	"github.com/stretchr/testify/require"
)

func TestFetchOrCreatePrimaryKMS(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "kms")
	t.Setenv("ENCLAVE_KMS_KEY_LOCKED", "true")

	ctx := context.Background()
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	pcr0Hex := hex.EncodeToString(pcr0)
	policy := mustBuildKMSPolicy(t, testRoleARN, []string{pcr0Hex}, "")
	attestation := base64.StdEncoding.EncodeToString([]byte("migration attestation"))

	t.Run("existing key accepted", func(t *testing.T) {
		kmsf := newFakeKMS()
		kmsf.putKey("key-existing", policy)
		ssmf := &fakeSSM{params: map[string]string{kmsKeyIDParam(): "key-existing"}}

		got, err := FetchOrCreatePrimaryKMS(
			ctx,
			kmsTestNSMWithPCR0(t, pcr0),
			kmsf,
			&fakeSTS{},
			NewSSM(ssmf),
		)

		require.NoError(t, err)
		if got.KeyID() != "key-existing" {
			t.Fatalf("key ID = %q", got.KeyID())
		}
		if got.Genesis() {
			t.Fatalf("existing key reported genesis")
		}
	})

	t.Run("stale policy rejected", func(t *testing.T) {
		kmsf := newFakeKMS()
		stalePCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 48))
		kmsf.putKey("key-stale", mustBuildKMSPolicy(t, testRoleARN, []string{stalePCR0}, ""))
		ssmf := &fakeSSM{params: map[string]string{kmsKeyIDParam(): "key-stale"}}

		_, err := FetchOrCreatePrimaryKMS(
			ctx,
			kmsTestNSMWithPCR0(t, pcr0),
			kmsf,
			&fakeSTS{},
			NewSSM(ssmf),
		)

		require.Error(t, err)
	})

	t.Run("rollback-to-self accepts committed target policy", func(t *testing.T) {
		targetPCR0 := bytes.Repeat([]byte{0xcd}, 48)
		targetPCR0Hex := hex.EncodeToString(targetPCR0)
		kmsf := newFakeKMS()
		kmsf.putKey("key-rollback", mustBuildKMSPolicy(
			t,
			testRoleARN,
			[]string{pcr0Hex, targetPCR0Hex},
			"",
		))
		ssmf := &fakeSSM{params: map[string]string{
			kmsKeyIDParam():                         "key-rollback",
			migrationPreviousPCR0Param():            pcr0Hex,
			migrationPreviousPCR0AttestationParam(): attestation,
		}}

		got, err := FetchOrCreatePrimaryKMS(
			ctx,
			kmsTestNSMWithVerifiedDoc(t, pcr0, verifyDocResult(map[uint][]byte{
				0:                 pcr0,
				migrationPCRIndex: pcrExtendFromZero(targetPCR0),
			}, nil)),
			kmsf,
			&fakeSTS{},
			NewSSM(ssmf),
		)

		require.NoError(t, err)
		require.Equal(t, "key-rollback", got.KeyID())
	})

	t.Run("rollback-to-self rejects uncommitted target policy", func(t *testing.T) {
		targetPCR0 := bytes.Repeat([]byte{0xcd}, 48)
		targetPCR0Hex := hex.EncodeToString(targetPCR0)
		evilPCR0 := bytes.Repeat([]byte{0xef}, 48)
		kmsf := newFakeKMS()
		kmsf.putKey("key-rollback", mustBuildKMSPolicy(
			t,
			testRoleARN,
			[]string{pcr0Hex, targetPCR0Hex},
			"",
		))
		ssmf := &fakeSSM{params: map[string]string{
			kmsKeyIDParam():                         "key-rollback",
			migrationPreviousPCR0Param():            pcr0Hex,
			migrationPreviousPCR0AttestationParam(): attestation,
		}}

		_, err := FetchOrCreatePrimaryKMS(
			ctx,
			kmsTestNSMWithVerifiedDoc(t, pcr0, verifyDocResult(map[uint][]byte{
				0:                 pcr0,
				migrationPCRIndex: pcrExtendFromZero(evilPCR0),
			}, nil)),
			kmsf,
			&fakeSTS{},
			NewSSM(ssmf),
		)

		require.Error(t, err)
	})

	t.Run("rollback-to-self rejects policy without target PCR0", func(t *testing.T) {
		targetPCR0 := bytes.Repeat([]byte{0xcd}, 48)
		kmsf := newFakeKMS()
		kmsf.putKey("key-rollback", mustBuildKMSPolicy(t, testRoleARN, []string{pcr0Hex}, ""))
		ssmf := &fakeSSM{params: map[string]string{
			kmsKeyIDParam():                         "key-rollback",
			migrationPreviousPCR0Param():            pcr0Hex,
			migrationPreviousPCR0AttestationParam(): attestation,
		}}

		_, err := FetchOrCreatePrimaryKMS(
			ctx,
			kmsTestNSMWithVerifiedDoc(t, pcr0, verifyDocResult(map[uint][]byte{
				0:                 pcr0,
				migrationPCRIndex: pcrExtendFromZero(targetPCR0),
			}, nil)),
			kmsf,
			&fakeSTS{},
			NewSSM(ssmf),
		)

		require.Error(t, err)
	})

	t.Run("rollback-to-self rejects policy with extra target PCR0", func(t *testing.T) {
		targetPCR0 := bytes.Repeat([]byte{0xcd}, 48)
		targetPCR0Hex := hex.EncodeToString(targetPCR0)
		evilPCR0Hex := hex.EncodeToString(bytes.Repeat([]byte{0xef}, 48))
		kmsf := newFakeKMS()
		kmsf.putKey("key-rollback", mustBuildKMSPolicy(
			t,
			testRoleARN,
			[]string{pcr0Hex, targetPCR0Hex, evilPCR0Hex},
			"",
		))
		ssmf := &fakeSSM{params: map[string]string{
			kmsKeyIDParam():                         "key-rollback",
			migrationPreviousPCR0Param():            pcr0Hex,
			migrationPreviousPCR0AttestationParam(): attestation,
		}}

		_, err := FetchOrCreatePrimaryKMS(
			ctx,
			kmsTestNSMWithVerifiedDoc(t, pcr0, verifyDocResult(map[uint][]byte{
				0:                 pcr0,
				migrationPCRIndex: pcrExtendFromZero(targetPCR0),
			}, nil)),
			kmsf,
			&fakeSTS{},
			NewSSM(ssmf),
		)

		require.Error(t, err)
	})

	t.Run("rollback-to-self rejects policy missing current PCR0", func(t *testing.T) {
		targetPCR0 := bytes.Repeat([]byte{0xcd}, 48)
		targetPCR0Hex := hex.EncodeToString(targetPCR0)
		evilPCR0Hex := hex.EncodeToString(bytes.Repeat([]byte{0xef}, 48))
		kmsf := newFakeKMS()
		kmsf.putKey("key-rollback", mustBuildKMSPolicy(
			t,
			testRoleARN,
			[]string{targetPCR0Hex, evilPCR0Hex},
			"",
		))
		ssmf := &fakeSSM{params: map[string]string{
			kmsKeyIDParam():                         "key-rollback",
			migrationPreviousPCR0Param():            pcr0Hex,
			migrationPreviousPCR0AttestationParam(): attestation,
		}}

		_, err := FetchOrCreatePrimaryKMS(
			ctx,
			kmsTestNSMWithVerifiedDoc(t, pcr0, verifyDocResult(map[uint][]byte{
				0:                 pcr0,
				migrationPCRIndex: pcrExtendFromZero(targetPCR0),
			}, nil)),
			kmsf,
			&fakeSTS{},
			NewSSM(ssmf),
		)

		require.Error(t, err)
	})

	t.Run("missing key creates genesis key", func(t *testing.T) {
		kmsf := newFakeKMS()
		ssmf := &fakeSSM{params: map[string]string{}}

		got, err := FetchOrCreatePrimaryKMS(
			ctx,
			kmsTestNSMWithPCR0(t, pcr0),
			kmsf,
			&fakeSTS{arn: testRoleARN},
			NewSSM(ssmf),
		)

		require.NoError(t, err)
		if !got.Genesis() {
			t.Fatalf("created key did not report genesis")
		}
		if got.KeyID() == "" {
			t.Fatalf("created key ID is empty")
		}
		if ssmf.params[kmsKeyIDParam()] != got.KeyID() {
			t.Fatalf("created key ID was not stored")
		}
		require.NoError(
			t,
			VerifyKeyPolicyPosture(kmsf.keyPolicy(got.KeyID()), []string{pcr0Hex}, true),
		)
	})
}

func TestKMSRecipientOperations(t *testing.T) {
	ctx := context.Background()
	newKMS := func(t *testing.T) *kmsW {
		return &kmsW{nsm: kmsTestNSMWithRecipient(t), kms: newFakeKMS(), keyID: "key-crypto"}
	}

	t.Run("encrypt decrypt round trip", func(t *testing.T) {
		k := newKMS(t)

		ciphertext, err := k.Encrypt(ctx, []byte("secret"))
		require.NoError(t, err)
		got, err := k.Decrypt(ctx, ciphertext)

		require.NoError(t, err)
		if string(got) != "secret" {
			t.Fatalf("plaintext = %q", string(got))
		}
	})

	t.Run("generate data key unwraps recipient ciphertext", func(t *testing.T) {
		k := newKMS(t)

		dk, err := k.GenerateDataKey(ctx)
		require.NoError(t, err)
		if len(dk.Plaintext) != 32 {
			t.Fatalf("plaintext len = %d", len(dk.Plaintext))
		}
		if len(dk.Ciphertext) == 0 {
			t.Fatalf("ciphertext is empty")
		}

		got, err := k.Decrypt(ctx, base64.StdEncoding.EncodeToString(dk.Ciphertext))

		require.NoError(t, err)
		if !bytes.Equal(got, dk.Plaintext) {
			t.Fatalf("data key ciphertext did not decrypt to generated plaintext")
		}
	})

	t.Run("bad ciphertext rejected", func(t *testing.T) {
		_, err := newKMS(t).Decrypt(ctx, "not base64")

		require.Error(t, err)
	})
}

func TestCreateMigrationKMS(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "kms")
	t.Setenv("ENCLAVE_KMS_KEY_LOCKED", "true")

	ctx := context.Background()
	curPCR0 := bytes.Repeat([]byte{0xab}, 48)
	newPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 48))
	kmsf := newFakeKMS()
	primary := &kmsW{
		nsm:   kmsTestNSMWithPCR0(t, curPCR0),
		kms:   kmsf,
		sts:   &fakeSTS{arn: testRoleARN},
		keyID: "primary",
	}

	got, err := primary.CreateMigrationKMS(ctx, newPCR0)

	require.NoError(t, err)
	if got.KeyID() == "" || got.KeyID() == "primary" {
		t.Fatalf("migration key ID = %q", got.KeyID())
	}
	require.NoError(
		t,
		VerifyKeyPolicyPosture(
			kmsf.keyPolicy(got.KeyID()),
			[]string{hex.EncodeToString(curPCR0), newPCR0},
			true,
		),
	)
}

func kmsTestNSMWithPCR0(t *testing.T, pcr0 []byte) NSM {
	t.Helper()
	return &nsmW{nsm: &fakeNSM{session: &fakeNSMSession{
		responses: []response.Response{
			attestationDocumentResponse(buildForgedAttestation(t, map[uint][]byte{0: pcr0})),
		},
	}}}
}

func kmsTestNSMWithVerifiedDoc(t *testing.T, currentPCR0 []byte, verifyResult *nitrite.Result) NSM {
	t.Helper()
	return &nsmW{nsm: &fakeNSM{
		session: &fakeNSMSession{responses: []response.Response{
			attestationDocumentResponse(buildForgedAttestation(t, map[uint][]byte{0: currentPCR0})),
		}},
		verifyResult: verifyResult,
	}}
}

func kmsTestNSMWithRecipient(t *testing.T) NSM {
	t.Helper()
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	return &nsmW{nsm: &fakeNSM{session: &fakeNSMSession{
		sendFunc: func(req request.Request) (response.Response, error) {
			att := req.(*request.Attestation)
			return attestationDocumentResponse(
				buildForgedAttestationWithPublicKey(t, map[uint][]byte{0: pcr0}, att.PublicKey),
			), nil
		},
	}}}
}
