package runtime

// Append-only, Object-Lock-immutable PCR0 lineage log: at adoption the migrating-in
// enclave records its own Nitro self-attestation plus the predecessor's. Audit-only —
// the chain is walked by `enclave verify-lineage`, never gates boot.

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	lineagePrefix           = "lineage/"
	lineageSchemaV1         = "enclave.pcr0_lineage.v1"
	lineagePurposeGenesis   = "genesis"
	lineagePurposeMigration = "migration"
)

// lineageEntryV1 is one immutable link. A migration entry carries both the successor's
// self-attestation (it ran) and the predecessor's (PCR31-commits to self: authorized).
type lineageEntryV1 struct {
	Schema          string `cbor:"schema"`
	Purpose         string `cbor:"purpose"`
	PrevPCR0        string `cbor:"prev_pcr0"`
	SelfPCR0        string `cbor:"self_pcr0"`
	SelfAttestation string `cbor:"self_attest"`
	PrevAttestation string `cbor:"prev_attest"`
	Descriptor      []byte `cbor:"descriptor,omitempty"` // canonical-CBOR deploymentDescriptorV1; genesis only
	Timestamp       int64  `cbor:"ts"`
}

// PCR0Lineage appends Nitro-attested version-history entries; nil receiver or empty bucket disables it.
type PCR0Lineage struct {
	s3     S3API
	ssm    SSMAPI
	bucket string
	window time.Duration
}

// Init resolves the lineage bucket from SSM. It is always provisioned, so an empty
// value is a misconfiguration (not an opt-out) — fail closed.
func (l *PCR0Lineage) Init(ctx context.Context) error {
	bucket, err := readSSMParamOptional(ctx, l.ssm, lineageBucketParam())
	if err != nil {
		return fmt.Errorf("read lineage bucket name: %w", err)
	}
	if bucket == "" {
		return fmt.Errorf("lineage bucket not provisioned (%s unset)", lineageBucketParam())
	}
	l.bucket = bucket
	return nil
}

// record writes one compliance-locked, plaintext entry at lineage/<selfPCR0>. Entries
// are Nitro-signed (self-authenticating), so not sealed; re-runs add a new S3 version.
func (l *PCR0Lineage) record(ctx context.Context, entry lineageEntryV1) error {
	entry.Timestamp = time.Now().Unix()
	body, err := canonicalCBOR.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := l.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:                    aws.String(l.bucket),
		Key:                       aws.String(lineageObjectKey(entry.SelfPCR0)),
		Body:                      bytes.NewReader(body),
		ObjectLockMode:            s3types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: aws.Time(time.Now().Add(l.window)),
	}); err != nil {
		return fmt.Errorf("lineage put %q: %w", entry.SelfPCR0, err)
	}
	return nil
}

func lineageObjectKey(selfPCR0 string) string {
	return lineagePrefix + selfPCR0
}

func lineageBucketParam() string {
	return fmt.Sprintf("/%s/%s/LineageBucketName", getDeployment(), getAppName())
}
