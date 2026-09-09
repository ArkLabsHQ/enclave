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
	return newMigrationIntentFixtureWithConfig(t, testCfg)
}

func newMigrationIntentFixtureWithConfig(
	t *testing.T, cfg *Config,
) *migrationIntentFixture {
	t.Helper()
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	session := newStatefulNSMSession(t, map[uint][]byte{0: pcr0})
	nsm := &nsmW{nsm: &fakeNSM{
		session:     session,
		verifyRoots: session.attestationSign.roots,
	}}
	s3f := newFakeS3()
	log, err := newMigrationIntentLog(cfg, s3f, nsm, migrationIntentTestBucket)
	require.NoError(t, err)
	genesis, err := newGenesisLog(cfg, s3f, nsm, migrationIntentTestBucket)
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
	fx := newMigrationIntentFixture(t)
	targetA := strings.Repeat("cd", 48)
	targetB := strings.Repeat("ef", 48)
	empty := newMigrationIntentFixture(t)
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
	require.WithinDuration(
		t,
		time.Now().Add(testCfg.IntentRetention),
		stored.retainUntil,
		time.Second,
	)
	entry, err := decodeMigrationIntentObject(stored.body)
	require.NoError(t, err)
	require.NoError(t, verifyAttestationUserData(
		fx.nsm, entry.Attestation, map[uint]string{0: fx.source},
		mustMigrationIntentPayload(t, fx.log, entry, migrationIntentTestBucket),
	))

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
	fx := newMigrationIntentFixture(t)

	// A self-targeted handoff would overwrite this enclave's own commit pointer
	// and satisfy the PCR31 check trivially.
	_, err := fx.log.Request(context.Background(), fx.source, strings.ToUpper(fx.source))

	require.ErrorIs(t, err, errMigrationIntentSelfTarget)
	head, err := fx.log.Head(context.Background(), fx.source)
	require.NoError(t, err)
	require.Nil(t, head, "a refused request must publish no intent")
}

func TestMigrationIntentRetentionComesFromTheEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		isDev bool
	}{
		{name: "production", isDev: false},
		{name: "dev", isDev: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newTestConfig("prod", "app", tc.isDev)
			fx := newMigrationIntentFixtureWithConfig(t, cfg)

			_, err := fx.log.Request(
				context.Background(), fx.source, strings.Repeat("cd", 48),
			)
			require.NoError(t, err)

			fx.s3.mu.Lock()
			stored := fx.s3.objects[migrationIntentObjectKey(fx.source, 1)][0]
			fx.s3.mu.Unlock()
			require.Equal(t, s3types.ObjectLockModeCompliance, stored.lockMode)
			require.WithinDuration(
				t,
				time.Now().Add(cfg.IntentRetention),
				stored.retainUntil,
				10*time.Second,
			)
		})
	}
}

// The log is append-only only because published intents cannot be deleted or
// rewritten. A version whose Object Lock does not prove that must not count.
func TestMigrationIntentIgnoresVersionsWithoutComplianceRetention(t *testing.T) {
	target := strings.Repeat("cd", 48)
	published := time.Now().Add(-time.Hour)

	for _, tc := range []struct {
		name        string
		lockMode    s3types.ObjectLockMode
		retainUntil time.Time
	}{
		{
			name:        "governance mode can be bypassed",
			lockMode:    s3types.ObjectLockModeGovernance,
			retainUntil: published.Add(prodRetention),
		},
		{
			name:        "no lock at all",
			lockMode:    "",
			retainUntil: published.Add(prodRetention),
		},
		{
			name:     "no retain-until date",
			lockMode: s3types.ObjectLockModeCompliance,
		},
		{
			name:        "expires far sooner than the configured retention",
			lockMode:    s3types.ObjectLockModeCompliance,
			retainUntil: published.Add(time.Minute),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newMigrationIntentFixture(t)
			fx.s3.putRawObjectLockedAt(
				migrationIntentObjectKey(fx.source, 1),
				fx.object(t, 1, migrationIntentRequested, target,
					migrationIntentTestBucket, fx.pcr0),
				published, tc.lockMode, tc.retainUntil,
			)

			head, err := fx.log.Head(context.Background(), fx.source)

			require.NoError(t, err, "one unlocked object must not break the log")
			require.Nil(t, head, "an intent that is not immutably retained must not count")
		})
	}
}

// A hostile writer publishing an unlocked version alongside the genuine one must
// not be able to displace it, nor to hide it.
func TestMigrationIntentPrefersTheRetainedVersion(t *testing.T) {
	genuineTarget := strings.Repeat("cd", 48)
	forgedTarget := strings.Repeat("ef", 48)
	published := time.Now().Add(-time.Hour)
	key := migrationIntentObjectKey(strings.Repeat("ab", 48), 1)

	fx := newMigrationIntentFixture(t)
	// The forged version is written first, so "earliest wins" alone would take it.
	fx.s3.putRawObjectLockedAt(
		key,
		fx.object(t, 1, migrationIntentRequested, forgedTarget,
			migrationIntentTestBucket, fx.pcr0),
		published.Add(-time.Minute), s3types.ObjectLockModeGovernance, published.Add(prodRetention),
	)
	fx.s3.putRawObjectAt(
		key,
		fx.object(t, 1, migrationIntentRequested, genuineTarget,
			migrationIntentTestBucket, fx.pcr0),
		published,
	)

	head, err := fx.log.Head(context.Background(), fx.source)

	require.NoError(t, err)
	require.NotNil(t, head)
	require.Equal(t, genuineTarget, head.TargetPCR0,
		"the earliest version must be picked from those actually retained")
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
	require.Equal(t, uint64(1), head.Sequence)
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
	const account = "123456789012"
	nameFor := func(deployment, app string) string {
		return migrationIntentBucketName(newTestConfig(deployment, app, false), account)
	}
	name := nameFor("prod", "wallet")

	require.Regexp(t, `^enclave-123456789012-[0-9a-f]{16}-migration-intents$`, name)
	require.LessOrEqual(t, len(name), 63, "S3 bucket names cap at 63 characters")
	require.Equal(t, name, nameFor("prod", "wallet"), "must be stable")

	// The account is what keeps two accounts off the same globally unique name.
	require.NotEqual(t, name, migrationIntentBucketName(
		newTestConfig("prod", "wallet", false), "210987654321",
	))

	require.NotEqual(t, name, nameFor("prod", "vault"), "distinct per application")
	require.NotEqual(t, name, nameFor("staging", "wallet"), "distinct per deployment")

	// The NUL separator is what stops "prodwal"+"let" colliding with
	// "prod"+"wallet".
	require.NotEqual(t, name, nameFor("prodwal", "let"))

	t.Run("survives names S3 would reject", func(t *testing.T) {
		long := nameFor("Prod_EU_West", strings.Repeat("long", 40))
		require.Regexp(t, `^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`, long)
		require.LessOrEqual(t, len(long), 63)
	})
}

func TestMigrationIntentRetentionBoundary(t *testing.T) {
	published := time.Now().UTC()
	for _, retention := range []time.Duration{devIntentRetention, prodRetention} {
		t.Run(retention.String(), func(t *testing.T) {
			cfg := newTestConfig("prod", "app", retention == devIntentRetention)
			log := &migrationIntentLog{retention: retention, cfg: cfg}
			for _, tc := range []struct {
				name     string
				deadline *time.Time
				want     bool
			}{
				{"missing", nil, false},
				{"below tolerated minimum", aws.Time(published.Add(retention - log.writeTimeout() - time.Nanosecond)), false},
				{"tolerated minimum", aws.Time(published.Add(retention - log.writeTimeout())), true},
				{"within tolerance", aws.Time(published.Add(retention - time.Nanosecond)), true},
				{"exact minimum", aws.Time(published.Add(retention)), true},
				{"longer", aws.Time(published.Add(retention + time.Second)), true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					out := &s3.GetObjectOutput{
						ObjectLockMode:            s3types.ObjectLockModeCompliance,
						ObjectLockRetainUntilDate: tc.deadline,
					}
					require.Equal(t, tc.want, log.compliesWithObjectLock("key", "version", published, out))
				})
			}
		})
	}
}

func TestMigrationIntentWriteTimeout(t *testing.T) {
	require.Equal(t, 10*time.Minute,
		(&migrationIntentLog{cfg: newTestConfig("prod", "app", false)}).writeTimeout())
	require.Equal(t, 2*time.Minute,
		(&migrationIntentLog{cfg: newTestConfig("dev", "app", true)}).writeTimeout())
}

func TestEarliestUnabortedIntentRemainsAuthoritative(t *testing.T) {
	fx := newMigrationIntentFixture(t)
	ctx := context.Background()
	base := time.Now().Add(-prodRetention - time.Hour)
	target := strings.Repeat("cd", 48)
	put := func(sequence uint64, action string, published time.Time) {
		fx.s3.putRawObjectLockedAt(migrationIntentObjectKey(fx.source, sequence),
			fx.object(t, sequence, action, target, migrationIntentTestBucket, fx.pcr0),
			published, s3types.ObjectLockModeCompliance, published.Add(prodRetention))
	}
	put(1, migrationIntentRequested, base)
	put(2, migrationIntentRequested, time.Now())
	head, err := fx.log.Head(ctx, fx.source)
	require.NoError(t, err)
	require.Equal(t, uint64(1), head.Sequence,
		"a later request must not hide the earliest unaborted authorization")
	m := &migrator{intent: fx.log}
	require.NoError(t, m.verifyIntent(ctx, fx.source, target, 1))
	put(3, migrationIntentAborted, base.Add(time.Minute))
	head, err = fx.log.Head(ctx, fx.source)
	require.NoError(t, err)
	require.Equal(t, migrationIntentAborted, head.Action, "expired aborts must remain visible")
	put(4, migrationIntentRequested, time.Now())
	head, err = fx.log.Head(ctx, fx.source)
	require.NoError(t, err)
	require.Equal(t, uint64(4), head.Sequence)
	require.NoError(t, m.verifyIntent(ctx, fx.source, target, 4))
}

// Every append must land above every sequence already published. Writing at the
// active head's sequence instead would add a second version to a key that
// already exists, where the earliest-version rule would then bury it.
func TestAppendAlwaysAdvancesBeyondEverySequence(t *testing.T) {
	target := strings.Repeat("cd", 48)

	highestSequence := func(t *testing.T, fx *migrationIntentFixture) uint64 {
		t.Helper()
		fx.s3.mu.Lock()
		defer fx.s3.mu.Unlock()
		var highest uint64
		for key := range fx.s3.objects {
			if _, sequence, ok := parseMigrationIntentObjectKey(key); ok {
				highest = max(highest, sequence)
			}
		}
		return highest
	}

	for _, action := range []string{migrationIntentRequested, migrationIntentAborted} {
		t.Run("after "+action, func(t *testing.T) {
			fx := newMigrationIntentFixture(t)
			ctx := context.Background()
			// Three open requests: the head stays at 1 while the log reaches 3.
			for sequence := uint64(1); sequence <= 3; sequence++ {
				fx.s3.putRawObjectAt(
					migrationIntentObjectKey(fx.source, sequence),
					fx.object(t, sequence, action, target,
						migrationIntentTestBucket, fx.pcr0),
					time.Now().Add(-time.Hour+time.Duration(sequence)*time.Second),
				)
			}
			before := highestSequence(t, fx)
			require.Equal(t, uint64(3), before)

			var head *migrationIntent
			var err error
			if action == migrationIntentRequested {
				head, err = fx.log.Abort(ctx, fx.source)
			} else {
				head, err = fx.log.Request(ctx, fx.source, target)
			}

			require.NoError(t, err)
			require.Greater(t, head.Sequence, before,
				"an append must not reuse a sequence that already has an object")
			require.Len(t, fx.s3.objects[migrationIntentObjectKey(fx.source, head.Sequence)], 1,
				"the new sequence must be a fresh key, not another version of an old one")
		})
	}
}

func TestAbortAdvancesPastIgnoredRequests(t *testing.T) {
	fx := newMigrationIntentFixture(t)
	ctx := context.Background()
	target := strings.Repeat("cd", 48)
	for sequence := uint64(1); sequence <= 3; sequence++ {
		fx.s3.putRawObjectAt(migrationIntentObjectKey(fx.source, sequence),
			fx.object(t, sequence, migrationIntentRequested, target, migrationIntentTestBucket, fx.pcr0),
			time.Now().Add(-time.Hour+time.Duration(sequence)*time.Second))
	}
	head, err := fx.log.Head(ctx, fx.source)
	require.NoError(t, err)
	require.Equal(t, uint64(1), head.Sequence)
	head, err = fx.log.Abort(ctx, fx.source)
	require.NoError(t, err)
	require.Equal(t, uint64(4), head.Sequence)
	require.Equal(t, migrationIntentAborted, head.Action)
	head, err = fx.log.Request(ctx, fx.source, target)
	require.NoError(t, err)
	require.Equal(t, uint64(5), head.Sequence)
}
