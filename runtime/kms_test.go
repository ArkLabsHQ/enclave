package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
	"github.com/stretchr/testify/require"
)

func TestFetchOrCreatePrimaryKMS(t *testing.T) {
	ctx := context.Background()
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	pcr0Hex := hex.EncodeToString(pcr0)
	policy := mustBuildKMSPolicy(t, testRoleARN, []string{pcr0Hex}, "")

	t.Run("existing key accepted", func(t *testing.T) {
		kmsf := newFakeKMS()
		kmsf.putKey("key-existing", policy)

		got, err := FetchOrCreatePrimaryKMS(
			ctx,
			testCfg,
			kmsTestNSMWithPCR0(t, pcr0),
			kmsf,
			&fakeSTS{},
			"key-existing",
		)

		require.NoError(t, err)
		if got.KeyID() != "key-existing" {
			t.Fatalf("key ID = %q", got.KeyID())
		}
	})

	t.Run("stale policy rejected", func(t *testing.T) {
		kmsf := newFakeKMS()
		stalePCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 48))
		kmsf.putKey("key-stale", mustBuildKMSPolicy(t, testRoleARN, []string{stalePCR0}, ""))

		_, err := FetchOrCreatePrimaryKMS(
			ctx,
			testCfg,
			kmsTestNSMWithPCR0(t, pcr0),
			kmsf,
			&fakeSTS{},
			"key-stale",
		)

		require.Error(t, err)
	})

	t.Run("multi-PCR0 policy rejected", func(t *testing.T) {
		otherPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 48))
		kmsf := newFakeKMS()
		kmsf.putKey("key-dual", mustBuildKMSPolicy(
			t,
			testRoleARN,
			[]string{pcr0Hex, otherPCR0},
			"",
		))

		_, err := FetchOrCreatePrimaryKMS(
			ctx,
			testCfg,
			kmsTestNSMWithPCR0(t, pcr0),
			kmsf,
			&fakeSTS{},
			"key-dual",
		)

		require.Error(t, err)
	})

	t.Run("missing key creates genesis key", func(t *testing.T) {
		kmsf := newFakeKMS()

		got, err := FetchOrCreatePrimaryKMS(
			ctx,
			testCfg,
			kmsTestNSMWithPCR0(t, pcr0),
			kmsf,
			&fakeSTS{arn: testRoleARN},
			"",
		)

		require.NoError(t, err)
		if got.KeyID() == "" {
			t.Fatalf("created key ID is empty")
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
		return &kmsW{
			cfg:   testCfg,
			nsm:   kmsTestNSMWithRecipient(t),
			kms:   newFakeKMS(),
			keyID: "key-crypto",
		}
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
	ctx := context.Background()
	curPCR0 := bytes.Repeat([]byte{0xab}, 48)
	newPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 48))
	kmsf := newFakeKMS()
	primary := &kmsW{
		cfg:   testCfg,
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
		VerifyKeyPolicyPosture(kmsf.keyPolicy(got.KeyID()), []string{newPCR0}, true),
	)
	require.Error(
		t,
		VerifyKeyPolicyPosture(
			kmsf.keyPolicy(got.KeyID()),
			[]string{hex.EncodeToString(curPCR0)},
			true,
		),
		"migration key must not admit the predecessor",
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

func TestKeyStatus(t *testing.T) {
	deletionDate := time.Now().Add(30 * 24 * time.Hour).UTC()
	tests := []struct {
		name         string
		state        kmstypes.KeyState
		wantState    string
		wantDeletion bool
	}{
		{"enabled", kmstypes.KeyStateEnabled, keyStateExists, false},
		{"disabled", kmstypes.KeyStateDisabled, keyStateExists, false},
		{"creating", kmstypes.KeyStateCreating, keyStateExists, false},
		{"updating", kmstypes.KeyStateUpdating, keyStateExists, false},
		{"unavailable", kmstypes.KeyStateUnavailable, keyStateExists, false},
		{"pending import", kmstypes.KeyStatePendingImport, keyStateExists, false},
		{"pending deletion", kmstypes.KeyStatePendingDeletion, keyStatePendingDeletion, true},
		{
			"pending replica deletion", kmstypes.KeyStatePendingReplicaDeletion,
			keyStatePendingDeletion, true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeKMS()
			fake.keyStates = map[string]*kmstypes.KeyMetadata{
				"key-1": {
					KeyId: aws.String("key-1"), KeyState: tc.state,
					DeletionDate: aws.Time(deletionDate),
				},
			}

			got := (&kmsW{cfg: testCfg, kms: fake}).KeyStatus(context.Background(), "key-1")

			require.Equal(t, tc.wantState, got.State)
			require.Equal(t, 1, fake.describeCalls)
			if tc.wantDeletion {
				require.Equal(t, deletionDate, got.DeletionDate.UTC())
			} else {
				require.Nil(t, got.DeletionDate)
			}
		})
	}
}

func TestKeyStatusDeleted(t *testing.T) {
	fake := newFakeKMS()

	got := (&kmsW{cfg: testCfg, kms: fake}).KeyStatus(context.Background(), "gone")

	require.Equal(t, keyStateDeleted, got.State)
	require.Equal(t, 1, fake.describeCalls)
}

func TestKeyStatusUnknown(t *testing.T) {
	t.Run("missing metadata", func(t *testing.T) {
		fake := newFakeKMS()
		fake.putKey("key-1", "{}")
		fake.describeNilMetadata = true

		got := (&kmsW{cfg: testCfg, kms: fake}).KeyStatus(context.Background(), "key-1")

		require.Equal(t, keyStateUnknown, got.State)
		require.Contains(t, got.Reason, "no key metadata")
	})

	t.Run("describe error", func(t *testing.T) {
		fake := newFakeKMS()
		fake.describeErr = &kmstypes.KMSInvalidStateException{Message: aws.String("bad state")}

		got := (&kmsW{cfg: testCfg, kms: fake}).KeyStatus(context.Background(), "key-1")

		require.Equal(t, keyStateUnknown, got.State)
		require.Contains(t, got.Reason, "describe_key:")
	})

	t.Run("empty key ID", func(t *testing.T) {
		fake := newFakeKMS()

		got := (&kmsW{cfg: testCfg, kms: fake}).KeyStatus(context.Background(), "")

		require.Equal(t, keyStateUnknown, got.State)
		require.Zero(t, fake.describeCalls)
	})
}
