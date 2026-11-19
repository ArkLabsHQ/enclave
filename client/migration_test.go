package client

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArkLabsHQ/enclave/internal/migration"
	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
	"github.com/stretchr/testify/require"
)

const migrationTestBucket = "enclave-000000000000-0011223344556677-migration-intents"

// A stored record outlives its short-lived certificates, so it is verified at
// the time it was attested.
func TestVerifyStoredAttestationUsesItsOwnTimestamp(t *testing.T) {
	doc := loadTestAttestation(t)
	_, err := nitrite.Verify(doc, nitrite.VerifyOptions{CurrentTime: time.Now()})
	require.Error(t, err, "the fixture's certificate chain has expired")

	result, err := verifyStoredAttestation(base64.StdEncoding.EncodeToString(doc), false)
	require.NoError(t, err)
	require.True(t, result.SignatureOK)
}

func TestWalkHandoffs(t *testing.T) {
	genesis, successor := strings.Repeat("aa", 48), strings.Repeat("bb", 48)
	base := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	// day spaces records further apart than the cooldown.
	day := func(n int) time.Time { return base.Add(time.Duration(n) * 25 * time.Hour) }
	request := func(source, target string, sequence uint64, at time.Time) migrationTestIntent {
		return migrationTestIntent{
			source: source, target: target, sequence: sequence,
			action: migration.Requested, at: at,
		}
	}
	abort := func(source, target string, sequence uint64, at time.Time) migrationTestIntent {
		return migrationTestIntent{
			source: source, target: target, sequence: sequence,
			action: migration.Aborted, at: at,
		}
	}
	handoff := func(source, target string, sequence uint64, at time.Time) migrationTestIntent {
		return migrationTestIntent{
			source: source, target: target, sequence: sequence,
			action: migration.Finalised, at: at,
			snapshot: migrationTestSnapshot(t, target, source, "key-1"),
		}
	}
	// logsOf files each intent's record under the log of the enclave that wrote it.
	logsOf := func(t *testing.T, intents ...migrationTestIntent) map[string][]migration.Record {
		t.Helper()
		logs := map[string][]migration.Record{}
		for _, intent := range intents {
			logs[intent.source] = append(logs[intent.source], intent.record(t))
		}
		return logs
	}
	opts := MigrationVerifyOptions{MinCooldown: 24 * time.Hour, InsecureSkipCOSEVerify: true}
	walk := func(current string, logs map[string][]migration.Record) HandoffWalk {
		fetch := func(_ context.Context, pcr0 string) (MigrationGeneration, error) {
			return MigrationGeneration{PCR0: pcr0, Records: logs[pcr0]}, nil
		}
		return WalkHandoffs(
			context.Background(),
			fetch,
			migrationTestBucket,
			genesis,
			current,
			opts,
		)
	}

	t.Run("walks from genesis to the current enclave", func(t *testing.T) {
		walked := walk(successor, logsOf(
			t,
			request(genesis, successor, 1, day(0)),
			handoff(genesis, successor, 2, day(1)),
		))

		require.Empty(t, walked.Failures)
		require.Len(t, walked.Generations, 2)
		require.Equal(t, genesis, walked.Generations[0].PCR0)
		require.Len(t, walked.Generations[0].Handoffs, 1)
		require.Equal(t, successor, walked.Generations[0].Handoffs[0].Finalised.TargetPCR0)
		require.Equal(t, day(0), walked.Generations[0].Handoffs[0].Request.AttestedAt)
		require.Equal(t, day(1), walked.Generations[0].Handoffs[0].Finalised.AttestedAt)
		require.Equal(t, successor, walked.Generations[1].PCR0)
		require.Empty(t, walked.Generations[1].Handoffs)
		require.Nil(t, walked.Generations[1].Pending)
	})

	// Genesis hands off to offPathTarget, aborts, then hands off to current;
	// offPathTarget had already adopted and hands off to offPathSuccessor.
	t.Run("follows every handoff, off the current enclave's path too", func(t *testing.T) {
		offPathTarget, current := strings.Repeat("bb", 48), strings.Repeat("cc", 48)
		offPathSuccessor := strings.Repeat("dd", 48)
		walked := walk(current, logsOf(
			t,
			request(genesis, offPathTarget, 1, day(0)),
			handoff(genesis, offPathTarget, 2, day(1)),
			abort(genesis, offPathTarget, 3, day(2)),
			request(genesis, current, 4, day(3)),
			handoff(genesis, current, 5, day(4)),
			request(offPathTarget, offPathSuccessor, 1, day(2)),
			handoff(offPathTarget, offPathSuccessor, 2, day(3)),
		))

		require.Empty(t, walked.Failures)
		require.Len(t, walked.Generations, 4)
		require.Equal(t,
			[]string{genesis, offPathTarget, current, offPathSuccessor},
			[]string{
				walked.Generations[0].PCR0, walked.Generations[1].PCR0,
				walked.Generations[2].PCR0, walked.Generations[3].PCR0,
			})
		require.Len(t, walked.Generations[0].Handoffs, 2)
		require.Len(t, walked.Generations[1].Handoffs, 1)
	})

	t.Run("records a current enclave not reached from genesis", func(t *testing.T) {
		current := strings.Repeat("cc", 48)
		walked := walk(current, logsOf(
			t,
			request(genesis, successor, 1, day(0)),
			handoff(genesis, successor, 2, day(1)),
		))

		require.Len(t, walked.Generations, 2)
		require.Len(t, walked.Failures, 1)
		require.EqualError(t, walked.Failures[0],
			"no handoff from genesis "+genesis+" reaches "+current)
	})

	t.Run("records a handoff left unreached by a forged request", func(t *testing.T) {
		forged := request(genesis, successor, 1, day(0))
		forged.attestedBy = successor
		walked := walk(successor, logsOf(t, forged, handoff(genesis, successor, 2, day(1))))

		require.Len(t, walked.Generations, 1)
		require.Len(t, walked.Generations[0].Ignored, 1)
		require.Len(t, walked.Failures, 1)
		require.EqualError(t, walked.Failures[0],
			"no handoff from genesis "+genesis+" reaches "+successor)
	})

	t.Run("records a handoff before the cooldown and follows it", func(t *testing.T) {
		walked := walk(successor, logsOf(
			t,
			request(genesis, successor, 1, day(0)),
			handoff(genesis, successor, 2, day(0).Add(time.Hour)),
		))

		require.Len(t, walked.Generations, 2)
		require.Len(t, walked.Failures, 1)
		require.EqualError(t, walked.Failures[0], "generation "+genesis+" finalised "+
			successor+" 1h0m0s after its request, before the 24h0m0s cooldown")
	})

	t.Run("records a log served for another PCR0", func(t *testing.T) {
		fetch := func(context.Context, string) (MigrationGeneration, error) {
			return MigrationGeneration{PCR0: successor}, nil
		}
		walked := WalkHandoffs(
			context.Background(), fetch, migrationTestBucket, genesis, genesis, opts,
		)

		require.Empty(t, walked.Generations)
		require.Len(t, walked.Failures, 1)
		require.EqualError(t, walked.Failures[0],
			"asked for generation "+genesis+", got "+successor)
	})

	// The successor's own log says whether it is migrating on.
	next := strings.Repeat("cc", 48)
	onward := request(successor, next, 1, day(2))
	successorLog := func(t *testing.T, records ...migration.Record) VerifiedGeneration {
		t.Helper()
		logs := logsOf(
			t,
			request(genesis, successor, 1, day(0)),
			handoff(genesis, successor, 2, day(1)),
		)
		logs[successor] = records
		walked := walk(successor, logs)
		require.Empty(t, walked.Failures)
		require.Len(t, walked.Generations, 2)
		return walked.Generations[1]
	}

	t.Run("pending", func(t *testing.T) {
		generation := successorLog(t, onward.record(t))

		require.NotNil(t, generation.Pending)
		require.Equal(t, next, generation.Pending.TargetPCR0)
		require.Equal(t, onward.at, generation.Pending.AttestedAt)
		require.Empty(t, generation.Handoffs)
	})

	t.Run("aborted is not pending", func(t *testing.T) {
		generation := successorLog(t,
			onward.record(t), abort(successor, next, 2, day(2).Add(time.Minute)).record(t))

		require.Nil(t, generation.Pending)
		require.Empty(t, generation.Handoffs)
	})

	t.Run("tied requests block any handoff", func(t *testing.T) {
		rival := request(successor, strings.Repeat("dd", 48), 1, day(2))
		generation := successorLog(t, onward.record(t), rival.record(t))

		require.Nil(t, generation.Pending)
		require.Len(t, generation.Ambiguous, 2)
	})

	// As in the runtime, S3's publication orders a sequence, not attestation.
	t.Run("the version published first counts", func(t *testing.T) {
		rival := request(successor, strings.Repeat("dd", 48), 1, onward.at.Add(-time.Minute))
		rival.published = onward.at.Add(time.Minute)
		generation := successorLog(t, onward.record(t), rival.record(t))

		require.NotNil(t, generation.Pending)
		require.Equal(t, next, generation.Pending.TargetPCR0)
	})

	// A record that does not verify is ignored, as the runtime ignores it.
	onwardHandoff := handoff(successor, next, 2, day(3))
	for _, tc := range []struct {
		name   string
		record func(t *testing.T) migration.Record
		err    string
	}{
		{
			name: "attested by another generation",
			record: func(t *testing.T) migration.Record {
				forged := onward
				forged.attestedBy = genesis
				return forged.record(t)
			},
			err: "attested by PCR0",
		},
		{
			name: "attested for another bucket",
			record: func(t *testing.T) migration.Record {
				forged := onward
				forged.bucket = "another-bucket"
				return forged.record(t)
			},
			err: "attested user_data does not match the intent",
		},
		{
			name: "target changed after attestation",
			record: func(t *testing.T) migration.Record {
				record := onward.record(t)
				editMigrationRecord(t, &record, func(o *migration.ObjectV1) {
					o.TargetPCR0 = strings.Repeat("dd", 48)
				})
				return record
			},
			err: "attested user_data does not match the intent",
		},
		{
			name: "snapshot changed after attestation",
			record: func(t *testing.T) migration.Record {
				record := onwardHandoff.record(t)
				editMigrationRecord(t, &record, func(o *migration.ObjectV1) {
					o.FinalisedSnapshot = migrationTestSnapshot(t, next, successor, "key-2")
				})
				return record
			},
			err: "attested user_data does not match the intent",
		},
		{
			name: "handoff without the PCR31 commitment",
			record: func(t *testing.T) migration.Record {
				forged := onwardHandoff
				forged.noPCR31 = true
				return forged.record(t)
			},
			err: "PCR31 does not commit to the target",
		},
	} {
		t.Run("ignores a record "+tc.name, func(t *testing.T) {
			generation := successorLog(t, tc.record(t))

			require.Empty(t, generation.Records)
			require.Len(t, generation.Ignored, 1)
			require.ErrorContains(t, generation.Ignored[0], tc.err)
		})
	}
}

// migrationTestIntent describes a record the way the runtime writes one, by
// default published when attested; attestedBy, bucket and noPCR31 forge it.
type migrationTestIntent struct {
	source, target, action string
	sequence               uint64
	at                     time.Time
	published              time.Time
	snapshot               []byte
	attestedBy             string
	bucket                 string
	noPCR31                bool
}

func (i migrationTestIntent) record(t *testing.T) migration.Record {
	t.Helper()
	userData := migration.UserDataV1{
		Schema:     migration.IntentSchemaV1,
		BucketName: cmp.Or(i.bucket, migrationTestBucket),
		Sequence:   i.sequence,
		Action:     i.action,
		TargetPCR0: i.target,
	}
	pcrs := map[uint][]byte{0: mustDecodeHex(t, cmp.Or(i.attestedBy, i.source))}
	if i.snapshot != nil {
		userData.FinalisedSnapshotRoot = migration.SnapshotRoot(i.snapshot)
		if !i.noPCR31 {
			pcrs[migration.TargetPCRIndex] = migration.TargetCommitment(mustDecodeHex(t, i.target))
		}
	}
	payload, err := migration.EncodeUserData(userData)
	require.NoError(t, err)
	object, err := json.Marshal(migration.ObjectV1{
		Schema:     migration.IntentSchemaV1,
		Sequence:   i.sequence,
		Action:     i.action,
		TargetPCR0: i.target,
		Attestation: buildInsecureCOSEDoc(nitrite.Document{
			Timestamp: uint64(i.at.UnixMilli()), PCRs: pcrs, UserData: payload,
		}),
		FinalisedSnapshot: i.snapshot,
	})
	require.NoError(t, err)
	published := i.published
	if published.IsZero() {
		published = i.at
	}
	return migration.Record{PublishedAt: published, Object: object}
}

// editMigrationRecord changes a stored object after its attestation was made.
func editMigrationRecord(t *testing.T, record *migration.Record, edit func(*migration.ObjectV1)) {
	t.Helper()
	var object migration.ObjectV1
	require.NoError(t, json.Unmarshal(record.Object, &object))
	edit(&object)
	var err error
	record.Object, err = json.Marshal(object)
	require.NoError(t, err)
}

// migrationTestSnapshot encodes the snapshot fields the verifier reads, with a
// key ID so two snapshots of one handoff can differ.
func migrationTestSnapshot(t *testing.T, owner, predecessor, keyID string) []byte {
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
