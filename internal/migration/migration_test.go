package migration

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestResolveGeneration(t *testing.T) {
	targetA, targetB := strings.Repeat("bb", 48), strings.Repeat("cc", 48)
	base := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	intent := func(sequence uint64, action, target string, minute int, root ...byte) Intent {
		return Intent{
			Sequence:     sequence,
			Action:       action,
			TargetPCR0:   target,
			PublishedAt:  base.Add(time.Duration(minute) * time.Minute),
			SnapshotRoot: root,
		}
	}

	for _, tc := range []struct {
		name    string
		intents []Intent
		want    GenerationState
	}{
		{
			name:    "a request is in force",
			intents: []Intent{intent(1, Requested, targetA, 0)},
			want:    GenerationState{Current: 0, HighestSequence: 1},
		},
		{
			name: "a finalised intent stands on the pending request",
			intents: []Intent{
				intent(1, Requested, targetA, 0),
				intent(2, Finalised, targetA, 1, 1),
			},
			want: GenerationState{
				Current:         1,
				Handoffs:        []Handoff{{Request: 0, Finalised: 1}},
				HighestSequence: 2,
			},
		},
		{
			name: "a handoff at an abort's sequence is listed but never in force",
			intents: []Intent{
				intent(1, Requested, targetA, 0),
				intent(2, Finalised, targetA, 1, 1),
				intent(2, Aborted, targetA, 1),
			},
			want: GenerationState{
				Current:         2,
				Handoffs:        []Handoff{{Request: 0, Finalised: 1}},
				HighestSequence: 2,
			},
		},
		{
			name: "a finalised intent for another target does not stand",
			intents: []Intent{
				intent(1, Requested, targetA, 0),
				intent(2, Finalised, targetB, 1, 1),
			},
			want: GenerationState{Current: 0, HighestSequence: 2},
		},
		{
			name: "an abort ends the pending request",
			intents: []Intent{
				intent(1, Requested, targetA, 0),
				intent(2, Aborted, targetA, 1),
			},
			want: GenerationState{Current: 1, HighestSequence: 2},
		},
		{
			name: "an abort after a handoff withdraws it",
			intents: []Intent{
				intent(1, Requested, targetA, 0),
				intent(2, Finalised, targetA, 1, 1),
				intent(3, Aborted, targetA, 2),
			},
			want: GenerationState{
				Current:         2,
				Handoffs:        []Handoff{{Request: 0, Finalised: 1}},
				HighestSequence: 3,
			},
		},
		{
			name: "a request while one is pending is ignored but occupies its sequence",
			intents: []Intent{
				intent(1, Requested, targetA, 0),
				intent(2, Requested, targetB, 1),
			},
			want: GenerationState{Current: 0, HighestSequence: 2},
		},
		{
			name: "the version published first counts, listed second",
			intents: []Intent{
				intent(1, Requested, targetB, 1),
				intent(1, Requested, targetA, 0),
			},
			want: GenerationState{Current: 1, HighestSequence: 1},
		},
		{
			name: "the version published first counts, listed first",
			intents: []Intent{
				intent(1, Requested, targetA, 0),
				intent(1, Requested, targetB, 1),
			},
			want: GenerationState{Current: 0, HighestSequence: 1},
		},
		{
			name: "equivalent versions are one intent",
			intents: []Intent{
				intent(1, Requested, targetA, 0),
				intent(1, Requested, targetA, 0),
			},
			want: GenerationState{Current: 0, HighestSequence: 1},
		},
		{
			name: "tied requests are a conflict",
			intents: []Intent{
				intent(1, Requested, targetA, 0),
				intent(1, Requested, targetB, 0),
			},
			want: GenerationState{Current: -1, Ambiguous: []int{0, 1}, HighestSequence: 1},
		},
		{
			name: "tied aborts resolve to the smallest target, listed second",
			intents: []Intent{
				intent(1, Requested, targetA, 0),
				intent(2, Aborted, targetB, 1),
				intent(2, Aborted, targetA, 1),
			},
			want: GenerationState{Current: 2, HighestSequence: 2},
		},
		{
			name: "tied aborts resolve to the smallest target, listed first",
			intents: []Intent{
				intent(1, Requested, targetA, 0),
				intent(2, Aborted, targetA, 1),
				intent(2, Aborted, targetB, 1),
			},
			want: GenerationState{Current: 1, HighestSequence: 2},
		},
		{
			name: "tied finalised intents are all handoffs, the smaller root in force, listed second",
			intents: []Intent{
				intent(1, Requested, targetA, 0),
				intent(2, Finalised, targetA, 1, 9),
				intent(2, Finalised, targetA, 1, 3),
			},
			want: GenerationState{
				Current: 2,
				Handoffs: []Handoff{
					{Request: 0, Finalised: 2},
					{Request: 0, Finalised: 1},
				},
				HighestSequence: 2,
			},
		},
		{
			name: "tied finalised intents are all handoffs, the smaller root in force, listed first",
			intents: []Intent{
				intent(1, Requested, targetA, 0),
				intent(2, Finalised, targetA, 1, 3),
				intent(2, Finalised, targetA, 1, 9),
			},
			want: GenerationState{
				Current: 1,
				Handoffs: []Handoff{
					{Request: 0, Finalised: 1},
					{Request: 0, Finalised: 2},
				},
				HighestSequence: 2,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ResolveGeneration(tc.intents))
		})
	}
}

func TestVerifyIntentObject(t *testing.T) {
	source, target := strings.Repeat("aa", 48), strings.Repeat("bb", 48)
	other := strings.Repeat("cc", 48)
	const bucket = "intent-bucket"
	attestedAt := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	publishedAt := attestedAt.Add(time.Second)
	snapshot := testSnapshot(t, target, source, "key-1")
	// genuine returns an intent and the attestation its source would make for it.
	genuine := func(t *testing.T, action string, snapshot []byte) (ObjectV1, Attestation) {
		t.Helper()
		userData := UserDataV1{
			Schema: IntentSchemaV1, BucketName: bucket, Sequence: 1,
			Action: action, TargetPCR0: target,
		}
		pcrs := map[uint][]byte{0: mustDecodeHex(t, source)}
		if snapshot != nil {
			userData.FinalisedSnapshotRoot = SnapshotRoot(snapshot)
			pcrs[TargetPCRIndex] = TargetCommitment(mustDecodeHex(t, target))
		}
		payload, err := EncodeUserData(userData)
		require.NoError(t, err)
		return ObjectV1{
				Schema: IntentSchemaV1, Sequence: 1, Action: action, TargetPCR0: target,
				Attestation: "attestation", FinalisedSnapshot: snapshot,
			}, Attestation{
				PCRs: pcrs, UserData: payload, Timestamp: attestedAt,
			}
	}
	attesting := func(attestation Attestation) VerifyAttestationFunc {
		return func(string) (Attestation, error) { return attestation, nil }
	}

	t.Run("a request", func(t *testing.T) {
		object, attestation := genuine(t, Requested, nil)
		intent, at, err := VerifyIntentObject(
			object, source, bucket, publishedAt, attesting(attestation),
		)
		require.NoError(t, err)
		require.Equal(t, Intent{
			Sequence: 1, Action: Requested, TargetPCR0: target, PublishedAt: publishedAt,
		}, intent)
		require.Equal(t, attestedAt, at)
	})

	t.Run("a handoff", func(t *testing.T) {
		object, attestation := genuine(t, Finalised, snapshot)
		intent, _, err := VerifyIntentObject(
			object, source, bucket, publishedAt, attesting(attestation),
		)
		require.NoError(t, err)
		require.Equal(t, SnapshotRoot(snapshot), intent.SnapshotRoot)
	})

	t.Run("an attestation that does not verify", func(t *testing.T) {
		object, _ := genuine(t, Requested, nil)
		rejected := errors.New("certificate chain does not reach the AWS root")
		_, _, err := VerifyIntentObject(object, source, bucket, publishedAt,
			func(string) (Attestation, error) { return Attestation{}, rejected })
		require.ErrorIs(t, err, rejected)
	})

	for _, tc := range []struct {
		name    string
		handoff bool
		forge   func(t *testing.T, object *ObjectV1, attestation *Attestation)
		err     string
	}{
		{
			name: "another schema",
			forge: func(_ *testing.T, object *ObjectV1, _ *Attestation) {
				object.Schema = "enclave.migration_intent.v2"
			},
			err: "unexpected schema",
		},
		{
			name: "an unknown action",
			forge: func(_ *testing.T, object *ObjectV1, _ *Attestation) {
				object.Action = "migrated"
			},
			err: "unexpected action",
		},
		{
			name:    "a request carrying a snapshot",
			handoff: true,
			forge: func(_ *testing.T, object *ObjectV1, _ *Attestation) {
				object.Action = Requested
			},
			err: "only a finalised intent carries a snapshot",
		},
		{
			name: "an uppercase target",
			forge: func(_ *testing.T, object *ObjectV1, _ *Attestation) {
				object.TargetPCR0 = strings.ToUpper(target)
			},
			err: "target PCR0 is not lowercase hex",
		},
		{
			name: "attested by another enclave",
			forge: func(t *testing.T, _ *ObjectV1, attestation *Attestation) {
				attestation.PCRs[0] = mustDecodeHex(t, other)
			},
			err: "attested by PCR0",
		},
		{
			name: "a target changed after attestation",
			forge: func(_ *testing.T, object *ObjectV1, _ *Attestation) {
				object.TargetPCR0 = other
			},
			err: "attested user_data does not match the intent",
		},
		{
			name:    "a snapshot changed after attestation",
			handoff: true,
			forge: func(t *testing.T, object *ObjectV1, _ *Attestation) {
				object.FinalisedSnapshot = testSnapshot(t, target, source, "key-2")
			},
			err: "attested user_data does not match the intent",
		},
		{
			name:    "a snapshot owned by another enclave",
			handoff: true,
			forge: func(t *testing.T, object *ObjectV1, _ *Attestation) {
				object.FinalisedSnapshot = testSnapshot(t, other, source, "key-1")
			},
			err: "snapshot is owned by",
		},
		{
			name:    "a snapshot naming another predecessor",
			handoff: true,
			forge: func(t *testing.T, object *ObjectV1, _ *Attestation) {
				object.FinalisedSnapshot = testSnapshot(t, target, other, "key-1")
			},
			err: "snapshot names predecessor",
		},
		{
			name:    "a handoff without the target commitment",
			handoff: true,
			forge: func(_ *testing.T, _ *ObjectV1, attestation *Attestation) {
				delete(attestation.PCRs, TargetPCRIndex)
			},
			err: "PCR31 does not commit to the target",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			object, attestation := genuine(t, Requested, nil)
			if tc.handoff {
				object, attestation = genuine(t, Finalised, snapshot)
			}
			tc.forge(t, &object, &attestation)

			_, _, err := VerifyIntentObject(
				object, source, bucket, publishedAt, attesting(attestation),
			)
			require.ErrorContains(t, err, tc.err)
		})
	}
}

// testSnapshot encodes the snapshot fields a handoff is checked against, with
// a key ID so two snapshots of one handoff can differ.
func testSnapshot(t *testing.T, owner, predecessor, keyID string) []byte {
	t.Helper()
	encoder, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	raw, err := encoder.Marshal(struct {
		OwnerPCR0       string `cbor:"owner_pcr0"`
		KMSKeyID        string `cbor:"kms_key_id"`
		PredecessorPCR0 string `cbor:"predecessor_pcr0"`
	}{owner, keyID, predecessor})
	require.NoError(t, err)
	return raw
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
