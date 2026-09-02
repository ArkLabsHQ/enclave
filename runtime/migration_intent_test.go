package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

const migrationIntentTestBucket = "migration-intent-test"

type migrationIntentFixture struct {
	log     *migrationIntentLog
	genesis *genesisLog
	s3      *fakeS3
	nsm     *nsmW
	pcr0    []byte
	source  string
	signer  *testAttestationSigner
}

func newMigrationIntentFixture(t *testing.T) *migrationIntentFixture {
	return newMigrationIntentFixtureWithRetention(t, "87600h")
}

func newMigrationIntentFixtureWithRetention(
	t *testing.T,
	retention string,
) *migrationIntentFixture {
	t.Helper()
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "intent")
	t.Setenv("ENCLAVE_MIGRATION_INTENT_RETENTION", retention)
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	session := newStatefulNSMSession(t, map[uint][]byte{0: pcr0})
	nsm := &nsmW{nsm: &fakeNSM{
		session:     session,
		verifyRoots: session.attestationSign.roots,
	}}
	s3f := newFakeS3()
	log, err := newMigrationIntentLog(s3f, nsm, migrationIntentTestBucket)
	require.NoError(t, err)
	genesis, err := newGenesisLog(s3f, nsm, migrationIntentTestBucket)
	require.NoError(t, err)
	return &migrationIntentFixture{
		log:     log,
		genesis: genesis,
		s3:      s3f,
		nsm:     nsm,
		pcr0:    pcr0,
		source:  strings.Repeat("ab", 48),
		signer:  session.attestationSign,
	}
}

func (f *migrationIntentFixture) object(
	t *testing.T,
	sequence uint64,
	action, targetPCR0, bucket string,
	pcr0 []byte,
) []byte {
	t.Helper()
	payload, err := f.log.enc.Marshal(migrationIntentV1{
		Schema:     migrationIntentSchemaV1,
		BucketName: bucket,
		Sequence:   sequence,
		Action:     action,
		TargetPCR0: targetPCR0,
	})
	require.NoError(t, err)
	attestation := f.signer.build(t, map[uint][]byte{0: pcr0}, time.Now(), payload)
	body, err := json.Marshal(migrationIntentObjectV1{
		Schema:      migrationIntentSchemaV1,
		Sequence:    sequence,
		Action:      action,
		TargetPCR0:  targetPCR0,
		Attestation: attestation.docB64,
	})
	require.NoError(t, err)
	return body
}

func TestMigrationIntentJSON(t *testing.T) {
	target := strings.Repeat("cd", 48)
	entry, err := decodeMigrationIntentObject([]byte(`{
		"attestation":"doc",
		"target_pcr0":"` + target + `",
		"action":"requested",
		"sequence":1,
		"schema":"enclave.migration_intent.v1"
	}`))
	require.NoError(t, err)
	require.Equal(t, uint64(1), entry.Sequence)
	require.Equal(t, target, entry.TargetPCR0)

	for name, body := range map[string]string{
		"missing":   `{"schema":"x"}`,
		"duplicate": `{"schema":"x","schema":"x","sequence":1,"action":"requested","target_pcr0":"x","attestation":"x"}`,
		"unknown":   `{"schema":"x","sequence":1,"action":"requested","target_pcr0":"x","attestation":"x","extra":true}`,
		"trailing":  `{"schema":"x","sequence":1,"action":"requested","target_pcr0":"x","attestation":"x"} true`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeMigrationIntentObject([]byte(body))
			require.Error(t, err)
		})
	}
}

func TestMigrationIntentObjectKey(t *testing.T) {
	source := strings.Repeat("ab", 48)
	key := migrationIntentObjectKey(source, 42)
	require.Equal(t, migrationIntentPrefix+source+"/00000000000000000042", key)
	gotSource, sequence, ok := parseMigrationIntentObjectKey(key)
	require.True(t, ok)
	require.Equal(t, source, gotSource)
	require.Equal(t, uint64(42), sequence)

	for _, invalid := range []string{
		"other/" + source + "/00000000000000000042",
		migrationIntentPrefix + strings.ToUpper(source) + "/00000000000000000042",
		migrationIntentPrefix + source + "/42",
		migrationIntentPrefix + source + "/00000000000000000000",
		migrationIntentPrefix + source + "/00000000000000000042/extra",
	} {
		_, _, ok := parseMigrationIntentObjectKey(invalid)
		require.False(t, ok, invalid)
	}
}

func TestMigrationIntentAppend(t *testing.T) {
	fx := newMigrationIntentFixtureWithRetention(t, "24h")
	targetA := strings.Repeat("cd", 48)
	targetB := strings.Repeat("ef", 48)
	empty := newMigrationIntentFixtureWithRetention(t, "24h")
	_, err := empty.log.Abort(context.Background(), empty.source)
	require.ErrorIs(t, err, errMigrationIntentAbsent)

	head, err := fx.log.Request(context.Background(), fx.source, strings.ToUpper(targetA))
	require.NoError(t, err)
	require.Equal(t, uint64(1), head.Sequence)
	require.Equal(t, migrationIntentRequested, head.Action)
	require.Equal(t, targetA, head.TargetPCR0)
	require.Equal(t, fx.source, head.SourcePCR0)
	require.False(t, head.PublishedAt.IsZero())

	key := migrationIntentObjectKey(fx.source, 1)
	fx.s3.mu.Lock()
	stored := fx.s3.objects[key][0]
	fx.s3.mu.Unlock()
	require.Equal(t, s3types.ObjectLockModeCompliance, stored.lockMode)
	require.WithinDuration(t, time.Now().Add(24*time.Hour), stored.retainUntil, time.Second)
	entry, err := decodeMigrationIntentObject(stored.body)
	require.NoError(t, err)
	require.NoError(t, fx.nsm.VerifyAttestation(entry.Attestation, map[uint]string{0: fx.source},
		mustMigrationIntentPayload(t, fx.log, entry, migrationIntentTestBucket)))

	_, err = fx.log.Request(context.Background(), fx.source, targetB)
	require.ErrorIs(t, err, errMigrationIntentAlreadyRequested)

	head, err = fx.log.Abort(context.Background(), fx.source)
	require.NoError(t, err)
	require.Equal(t, uint64(2), head.Sequence)
	require.Equal(t, migrationIntentAborted, head.Action)
	require.Equal(t, targetA, head.TargetPCR0)

	_, err = fx.log.Abort(context.Background(), fx.source)
	require.ErrorIs(t, err, errMigrationIntentAborted)

	head, err = fx.log.Request(context.Background(), fx.source, targetB)
	require.NoError(t, err)
	require.Equal(t, uint64(3), head.Sequence)
	require.Equal(t, targetB, head.TargetPCR0)
}

func TestMigrationIntentRejectsSelfTarget(t *testing.T) {
	fx := newMigrationIntentFixtureWithRetention(t, "24h")

	// A self-targeted handoff would overwrite this enclave's own commit pointer
	// and satisfy the PCR31 check trivially.
	_, err := fx.log.Request(context.Background(), fx.source, strings.ToUpper(fx.source))

	require.ErrorIs(t, err, errMigrationIntentSelfTarget)
	head, err := fx.log.Head(context.Background(), fx.source)
	require.NoError(t, err)
	require.Nil(t, head, "a refused request must publish no intent")
}

func TestMigrationIntentRetentionConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   string
		wantErr string
	}{
		{name: "missing", wantErr: "ENCLAVE_MIGRATION_INTENT_RETENTION must not be empty"},
		{name: "invalid", value: "later", wantErr: `invalid ENCLAVE_MIGRATION_INTENT_RETENTION "later"`},
		{name: "zero", value: "0s", wantErr: "ENCLAVE_MIGRATION_INTENT_RETENTION must be positive"},
		{name: "negative", value: "-1h", wantErr: "ENCLAVE_MIGRATION_INTENT_RETENTION must be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ENCLAVE_MIGRATION_INTENT_RETENTION", tc.value)
			_, err := newMigrationIntentLog(newFakeS3(), nil, migrationIntentTestBucket)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestMigrationIntentCanonicalHead(t *testing.T) {
	targetA := strings.Repeat("cd", 48)
	targetB := strings.Repeat("ef", 48)

	t.Run("highest sequence and earliest version win", func(t *testing.T) {
		fx := newMigrationIntentFixture(t)
		base := time.Now().Add(-time.Hour)
		key1 := migrationIntentObjectKey(fx.source, 1)
		late := fx.object(
			t,
			1,
			migrationIntentRequested,
			targetA,
			migrationIntentTestBucket,
			fx.pcr0,
		)
		early := fx.object(
			t,
			1,
			migrationIntentAborted,
			targetA,
			migrationIntentTestBucket,
			fx.pcr0,
		)
		fx.s3.putRawObjectAt(key1, late, base.Add(time.Minute))
		fx.s3.putRawObjectAt(key1, early, base)
		fx.s3.putRawObjectAt(
			migrationIntentObjectKey(fx.source, 2),
			fx.object(t, 2, migrationIntentRequested, targetB, migrationIntentTestBucket, fx.pcr0),
			base.Add(2*time.Minute),
		)

		head, err := fx.log.Head(context.Background(), fx.source)
		require.NoError(t, err)
		require.Equal(t, uint64(2), head.Sequence)
		require.Equal(t, targetB, head.TargetPCR0)

		fx.s3.mu.Lock()
		delete(fx.s3.objects, migrationIntentObjectKey(fx.source, 2))
		fx.s3.mu.Unlock()
		head, err = fx.log.Head(context.Background(), fx.source)
		require.NoError(t, err)
		require.Equal(t, migrationIntentAborted, head.Action)
		require.Equal(t, base.UTC(), head.PublishedAt)
	})

	t.Run("newer replay does not replace original", func(t *testing.T) {
		fx := newMigrationIntentFixture(t)
		key := migrationIntentObjectKey(fx.source, 1)
		body := fx.object(
			t,
			1,
			migrationIntentRequested,
			targetA,
			migrationIntentTestBucket,
			fx.pcr0,
		)
		base := time.Now().Add(-time.Hour).UTC()
		fx.s3.putRawObjectAt(key, body, base)
		fx.s3.putRawObjectAt(key, body, base.Add(time.Minute))

		head, err := fx.log.Head(context.Background(), fx.source)
		require.NoError(t, err)
		require.Equal(t, base, head.PublishedAt)
	})

	t.Run("timestamp tie fails closed but abort advances", func(t *testing.T) {
		fx := newMigrationIntentFixture(t)
		key := migrationIntentObjectKey(fx.source, 1)
		publishedAt := time.Now().Add(-time.Hour).UTC()
		fx.s3.putRawObjectAt(key,
			fx.object(t, 1, migrationIntentRequested, targetA, migrationIntentTestBucket, fx.pcr0),
			publishedAt)
		fx.s3.putRawObjectAt(key,
			fx.object(t, 1, migrationIntentRequested, targetB, migrationIntentTestBucket, fx.pcr0),
			publishedAt)

		_, err := fx.log.Head(context.Background(), fx.source)
		require.ErrorIs(t, err, errMigrationIntentAmbiguous)

		_, err = fx.log.Request(context.Background(), fx.source, targetB)
		require.ErrorIs(t, err, errMigrationIntentAlreadyRequested)

		head, err := fx.log.Abort(context.Background(), fx.source)
		require.NoError(t, err)
		require.Equal(t, uint64(2), head.Sequence)

		head, err = fx.log.Request(context.Background(), fx.source, targetB)
		require.NoError(t, err)
		require.Equal(t, uint64(3), head.Sequence)
	})
}

func TestMigrationIntentInvalidVersionsAreIgnored(t *testing.T) {
	target := strings.Repeat("cd", 48)
	foreignPCR0 := bytes.Repeat([]byte{0xee}, 48)

	tests := map[string]func(*testing.T, *migrationIntentFixture) []byte{
		"malformed JSON": func(_ *testing.T, _ *migrationIntentFixture) []byte {
			return []byte("not-json")
		},
		"wrong bucket": func(t *testing.T, fx *migrationIntentFixture) []byte {
			return fx.object(t, 2, migrationIntentRequested, target, "other-bucket", fx.pcr0)
		},
		"wrong schema": func(t *testing.T, fx *migrationIntentFixture) []byte {
			body := fx.object(
				t,
				2,
				migrationIntentRequested,
				target,
				migrationIntentTestBucket,
				fx.pcr0,
			)
			var entry migrationIntentObjectV1
			require.NoError(t, json.Unmarshal(body, &entry))
			entry.Schema = "enclave.migration_intent.v2"
			body, err := json.Marshal(entry)
			require.NoError(t, err)
			return body
		},
		"foreign PCR0": func(t *testing.T, fx *migrationIntentFixture) []byte {
			return fx.object(
				t,
				2,
				migrationIntentRequested,
				target,
				migrationIntentTestBucket,
				foreignPCR0,
			)
		},
		"untrusted root": func(t *testing.T, fx *migrationIntentFixture) []byte {
			payload, err := fx.log.enc.Marshal(migrationIntentV1{
				Schema:     migrationIntentSchemaV1,
				BucketName: migrationIntentTestBucket,
				Sequence:   2,
				Action:     migrationIntentRequested,
				TargetPCR0: target,
			})
			require.NoError(t, err)
			now := time.Now()
			other := newTestAttestationSigner(t, now.Add(-time.Hour), now.Add(time.Hour)).
				build(t, map[uint][]byte{0: fx.pcr0}, now, payload)
			body, err := json.Marshal(migrationIntentObjectV1{
				Schema:      migrationIntentSchemaV1,
				Sequence:    2,
				Action:      migrationIntentRequested,
				TargetPCR0:  target,
				Attestation: other.docB64,
			})
			require.NoError(t, err)
			return body
		},
		"sequence mismatch": func(t *testing.T, fx *migrationIntentFixture) []byte {
			return fx.object(
				t,
				3,
				migrationIntentRequested,
				target,
				migrationIntentTestBucket,
				fx.pcr0,
			)
		},
		"unknown action": func(t *testing.T, fx *migrationIntentFixture) []byte {
			return fx.object(t, 2, "unknown", target, migrationIntentTestBucket, fx.pcr0)
		},
		"noncanonical target": func(t *testing.T, fx *migrationIntentFixture) []byte {
			return fx.object(
				t,
				2,
				migrationIntentRequested,
				strings.ToUpper(target),
				migrationIntentTestBucket,
				fx.pcr0,
			)
		},
		"noncanonical CBOR": func(t *testing.T, fx *migrationIntentFixture) []byte {
			payload, err := cbor.Marshal(migrationIntentV1{
				Schema:     migrationIntentSchemaV1,
				BucketName: migrationIntentTestBucket,
				Sequence:   2,
				Action:     migrationIntentRequested,
				TargetPCR0: target,
			})
			require.NoError(t, err)
			canonical, err := fx.log.enc.Marshal(migrationIntentV1{
				Schema:     migrationIntentSchemaV1,
				BucketName: migrationIntentTestBucket,
				Sequence:   2,
				Action:     migrationIntentRequested,
				TargetPCR0: target,
			})
			require.NoError(t, err)
			require.NotEqual(t, canonical, payload)
			attestation := fx.signer.build(t, map[uint][]byte{0: fx.pcr0}, time.Now(), payload)
			body, err := json.Marshal(migrationIntentObjectV1{
				Schema:      migrationIntentSchemaV1,
				Sequence:    2,
				Action:      migrationIntentRequested,
				TargetPCR0:  target,
				Attestation: attestation.docB64,
			})
			require.NoError(t, err)
			return body
		},
		"forged signature": func(t *testing.T, fx *migrationIntentFixture) []byte {
			body := fx.object(
				t,
				2,
				migrationIntentRequested,
				target,
				migrationIntentTestBucket,
				fx.pcr0,
			)
			var entry migrationIntentObjectV1
			require.NoError(t, json.Unmarshal(body, &entry))
			doc, err := base64.StdEncoding.DecodeString(entry.Attestation)
			require.NoError(t, err)
			doc[len(doc)-1] ^= 1
			entry.Attestation = base64.StdEncoding.EncodeToString(doc)
			body, err = json.Marshal(entry)
			require.NoError(t, err)
			return body
		},
	}

	for name, invalidBody := range tests {
		t.Run(name, func(t *testing.T) {
			fx := newMigrationIntentFixture(t)
			base := time.Now().Add(-time.Hour)
			fx.s3.putRawObjectAt(
				migrationIntentObjectKey(fx.source, 1),
				fx.object(
					t,
					1,
					migrationIntentRequested,
					target,
					migrationIntentTestBucket,
					fx.pcr0,
				),
				base,
			)
			fx.s3.putRawObjectAt(
				migrationIntentObjectKey(fx.source, 2), invalidBody(t, fx), base.Add(time.Minute),
			)

			head, err := fx.log.Head(context.Background(), fx.source)
			require.NoError(t, err)
			require.Equal(t, uint64(1), head.Sequence)
		})
	}
}

func TestMigrationIntentS3Failures(t *testing.T) {
	target := strings.Repeat("cd", 48)
	ctx := context.Background()

	for name, configure := range map[string]func(*fakeS3){
		"list": func(s *fakeS3) { s.listErr = errors.New("list failed") },
		"get":  func(s *fakeS3) { s.getErr = errors.New("get failed") },
		"read": func(s *fakeS3) { s.readErr = errors.New("read failed") },
	} {
		t.Run(name, func(t *testing.T) {
			fx := newMigrationIntentFixture(t)
			fx.s3.putRawObjectAt(
				migrationIntentObjectKey(fx.source, 1),
				fx.object(
					t,
					1,
					migrationIntentRequested,
					target,
					migrationIntentTestBucket,
					fx.pcr0,
				),
				time.Now(),
			)
			configure(fx.s3)
			_, err := fx.log.Head(ctx, fx.source)
			require.ErrorIs(t, err, errMigrationIntentStoreUnavailable)
		})
	}

	t.Run("put", func(t *testing.T) {
		fx := newMigrationIntentFixture(t)
		fx.s3.putErr = errors.New("put failed")
		_, err := fx.log.Request(ctx, fx.source, target)
		require.ErrorIs(t, err, errMigrationIntentStoreUnavailable)
	})

	t.Run("missing put version ID", func(t *testing.T) {
		fx := newMigrationIntentFixture(t)
		fx.s3.missingVersionID = true
		_, err := fx.log.Request(ctx, fx.source, target)
		require.ErrorContains(t, err, "no version ID")
		require.ErrorIs(t, err, errMigrationIntentStoreUnavailable)
	})
}

func TestMigrationIntentSequenceOverflow(t *testing.T) {
	fx := newMigrationIntentFixture(t)
	target := strings.Repeat("cd", 48)
	fx.s3.putRawObjectAt(
		migrationIntentObjectKey(fx.source, math.MaxUint64),
		fx.object(
			t,
			math.MaxUint64,
			migrationIntentAborted,
			target,
			migrationIntentTestBucket,
			fx.pcr0,
		),
		time.Now(),
	)

	_, err := fx.log.Request(context.Background(), fx.source, target)
	require.ErrorContains(t, err, "overflow")
}

type migrationIntentPagedS3 struct {
	*fakeS3
	versions []s3types.ObjectVersion
	page     int
}

func (p *migrationIntentPagedS3) ListObjectVersions(
	ctx context.Context,
	in *s3.ListObjectVersionsInput,
	opts ...func(*s3.Options),
) (*s3.ListObjectVersionsOutput, error) {
	if p.versions == nil {
		out, err := p.fakeS3.ListObjectVersions(ctx, in, opts...)
		if err != nil {
			return nil, err
		}
		p.versions = out.Versions
	}
	if p.page == 0 {
		p.page++
		return &s3.ListObjectVersionsOutput{
			Versions:            p.versions[:1],
			IsTruncated:         aws.Bool(true),
			NextKeyMarker:       aws.String("next"),
			NextVersionIdMarker: aws.String("next-version"),
		}, nil
	}
	if in.KeyMarker == nil || in.VersionIdMarker == nil {
		return nil, errors.New("pagination markers missing")
	}
	return &s3.ListObjectVersionsOutput{
		Versions:    p.versions[1:],
		IsTruncated: aws.Bool(false),
	}, nil
}

func TestMigrationIntentPagination(t *testing.T) {
	fx := newMigrationIntentFixture(t)
	target := strings.Repeat("cd", 48)
	for sequence := uint64(1); sequence <= 2; sequence++ {
		fx.s3.putRawObjectAt(
			migrationIntentObjectKey(fx.source, sequence),
			fx.object(
				t,
				sequence,
				migrationIntentRequested,
				target,
				migrationIntentTestBucket,
				fx.pcr0,
			),
			time.Now().Add(time.Duration(sequence)*time.Minute),
		)
	}
	paged := &migrationIntentPagedS3{fakeS3: fx.s3}
	fx.log.s3 = paged

	head, err := fx.log.Head(context.Background(), fx.source)
	require.NoError(t, err)
	require.Equal(t, uint64(2), head.Sequence)
	require.Equal(t, 1, paged.page)
}

func mustMigrationIntentPayload(
	t *testing.T,
	log *migrationIntentLog,
	entry migrationIntentObjectV1,
	bucket string,
) []byte {
	t.Helper()
	payload, err := log.enc.Marshal(migrationIntentV1{
		Schema:     entry.Schema,
		BucketName: bucket,
		Sequence:   entry.Sequence,
		Action:     entry.Action,
		TargetPCR0: entry.TargetPCR0,
	})
	require.NoError(t, err)
	return payload
}

var _ S3API = (*migrationIntentPagedS3)(nil)

func TestMigrationIntentBucketNameDerivation(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "wallet")
	name := migrationIntentBucketName("123456789012")

	require.Regexp(t, `^enclave-123456789012-[0-9a-f]{16}-migration-intents$`, name)
	require.LessOrEqual(t, len(name), 63, "S3 bucket names cap at 63 characters")
	require.Equal(t, name, migrationIntentBucketName("123456789012"), "must be stable")

	// The account is what keeps two accounts off the same globally unique name.
	require.NotEqual(t, name, migrationIntentBucketName("210987654321"))

	t.Run("distinct per application", func(t *testing.T) {
		t.Setenv("ENCLAVE_APP_NAME", "vault")
		require.NotEqual(t, name, migrationIntentBucketName("123456789012"))
	})

	t.Run("distinct per deployment", func(t *testing.T) {
		t.Setenv("ENCLAVE_DEPLOYMENT", "staging")
		require.NotEqual(t, name, migrationIntentBucketName("123456789012"))
	})

	t.Run("survives names S3 would reject", func(t *testing.T) {
		t.Setenv("ENCLAVE_DEPLOYMENT", "Prod_EU_West")
		t.Setenv("ENCLAVE_APP_NAME", strings.Repeat("long", 40))
		long := migrationIntentBucketName("123456789012")
		require.Regexp(t, `^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`, long)
		require.LessOrEqual(t, len(long), 63)
	})

	t.Run("separator prevents identity collisions", func(t *testing.T) {
		t.Setenv("ENCLAVE_DEPLOYMENT", "prodwal")
		t.Setenv("ENCLAVE_APP_NAME", "let")
		require.NotEqual(t, name, migrationIntentBucketName("123456789012"))
	})
}
