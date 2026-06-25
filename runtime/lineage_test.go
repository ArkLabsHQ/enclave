package runtime

import (
	"context"
	"testing"
	"time"

	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func latestVersion(f *fakeS3, key string) s3Version {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.objects[key]
	return v[len(v)-1]
}

func decodeLineage(t *testing.T, f *fakeS3, selfPCR0 string) lineageEntryV1 {
	t.Helper()
	var e lineageEntryV1
	require.NoError(t, cbor.Unmarshal(latestVersion(f, lineageObjectKey(selfPCR0)).body, &e))
	return e
}

// record writes a compliance-locked, plaintext entry at lineage/<selfPCR0>.
func TestLineage_RecordCompliesAndRoundTrips(t *testing.T) {
	f := newFakeS3()
	l := &PCR0Lineage{s3: f, bucket: "lineage-bkt", window: 1000 * time.Hour}

	pcr0 := "aabbcc"
	require.NoError(t, l.record(context.Background(), lineageEntryV1{
		Schema: lineageSchemaV1, Purpose: lineagePurposeGenesis, SelfPCR0: pcr0, SelfAttestation: "DOC",
	}))

	v := latestVersion(f, lineageObjectKey(pcr0))
	require.Equal(t, s3types.ObjectLockModeCompliance, v.lockMode)
	require.NotNil(t, v.retainUntil)
	require.WithinDuration(t, time.Now().Add(1000*time.Hour), *v.retainUntil, time.Hour)

	got := decodeLineage(t, f, pcr0)
	require.Equal(t, lineageSchemaV1, got.Schema)
	require.Equal(t, lineagePurposeGenesis, got.Purpose)
	require.Equal(t, pcr0, got.SelfPCR0)
	require.Equal(t, "DOC", got.SelfAttestation)
	require.Positive(t, got.Timestamp)
}

// Init resolves the provisioned bucket; a missing bucket is fatal (lineage is
// mandatory, not optional).
func TestLineage_Init(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")

	ssm := &fakeSSM{params: map[string]string{lineageBucketParam(): "the-bucket"}}
	l := &PCR0Lineage{s3: newFakeS3(), ssm: ssm}
	require.NoError(t, l.Init(context.Background()))
	require.Equal(t, "the-bucket", l.bucket)

	missing := &PCR0Lineage{s3: newFakeS3(), ssm: newFakeSSM()}
	require.Error(t, missing.Init(context.Background()))
}

// Genesis records a self-attestation only; migration bundles the predecessor's
// attestation; rollback-onto-self records self-only (no predecessor binding).
func TestLineage_RecordLineageBranches(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")

	ownPCR0 := "1111"
	prevPCR0 := "2222"

	t.Run("genesis", func(t *testing.T) {
		f := newFakeS3()
		s := &StateOrigin{ssm: newFakeSSM(), lineage: &PCR0Lineage{s3: f, bucket: "b", window: time.Hour}}
		require.NoError(t, s.recordLineage(context.Background(), ownPCR0, modeGenesis, "SELF_DOC", []byte("DESC")))
		e := decodeLineage(t, f, ownPCR0)
		require.Equal(t, lineagePurposeGenesis, e.Purpose)
		require.Equal(t, "SELF_DOC", e.SelfAttestation)
		require.Equal(t, []byte("DESC"), e.Descriptor)
		require.Empty(t, e.PrevPCR0)
		require.Empty(t, e.PrevAttestation)
	})

	t.Run("migration bundles predecessor", func(t *testing.T) {
		f := newFakeS3()
		ssm := &fakeSSM{params: map[string]string{
			migrationPreviousPCR0Param():            prevPCR0,
			migrationPreviousPCR0AttestationParam(): "PREV_DOC",
		}}
		s := &StateOrigin{ssm: ssm, lineage: &PCR0Lineage{s3: f, bucket: "b", window: time.Hour}}
		require.NoError(t, s.recordLineage(context.Background(), ownPCR0, modeMigration, "SELF_DOC", nil))
		e := decodeLineage(t, f, ownPCR0)
		require.Equal(t, lineagePurposeMigration, e.Purpose)
		require.Equal(t, "SELF_DOC", e.SelfAttestation)
		require.Equal(t, prevPCR0, e.PrevPCR0)
		require.Equal(t, "PREV_DOC", e.PrevAttestation)
	})

	t.Run("rollback-onto-self records self only", func(t *testing.T) {
		f := newFakeS3()
		ssm := &fakeSSM{params: map[string]string{
			migrationPreviousPCR0Param():            ownPCR0, // predecessor == self
			migrationPreviousPCR0AttestationParam(): "PREV_DOC",
		}}
		s := &StateOrigin{ssm: ssm, lineage: &PCR0Lineage{s3: f, bucket: "b", window: time.Hour}}
		require.NoError(t, s.recordLineage(context.Background(), ownPCR0, modeMigration, "SELF_DOC", nil))
		e := decodeLineage(t, f, ownPCR0)
		require.Equal(t, lineagePurposeGenesis, e.Purpose)
		require.Empty(t, e.PrevPCR0)
		require.Empty(t, e.PrevAttestation)
	})
}
