package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/fxamacker/cbor/v2"
)

const (
	deploymentGenesisKey      = "deployment-genesis"
	deploymentGenesisSchemaV1 = "enclave.deployment_genesis.v1"
)

var (
	errGenesisAlreadyCommitted = errors.New("deployment genesis: already committed")
	errGenesisStoreUnavailable = errors.New("deployment genesis store: unavailable")
)

type genesisLog struct {
	cfg    *Config
	s3     S3API
	nsm    NSM
	bucket string
	enc    cbor.EncMode
}

type GenesisArtifact struct {
	PCR0        string
	PublishedAt time.Time
	VersionID   string
	Attestation string
}

type deploymentGenesisV1 struct {
	Schema      string `json:"schema"`
	PCR0        string `json:"pcr0"`
	Attestation string `json:"attestation"`
}

type deploymentGenesisPayloadV1 struct {
	Schema     string `cbor:"schema"`
	BucketName string `cbor:"bucket_name"`
	PCR0       string `cbor:"pcr0"`
}

func newGenesisLog(
	cfg *Config, s3Client S3API, nsm NSM, bucket string,
) (*genesisLog, error) {
	if strings.TrimSpace(bucket) == "" {
		return nil, fmt.Errorf("genesis bucket is required")
	}
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("build genesis CBOR encoder: %w", err)
	}
	return &genesisLog{
		cfg: cfg, s3: s3Client, nsm: nsm, bucket: bucket, enc: enc,
	}, nil
}

func (l *genesisLog) Genesis(ctx context.Context) (*GenesisArtifact, error) {
	var genesis *GenesisArtifact
	err := forEachObjectVersion(ctx, l.s3, l.bucket, deploymentGenesisKey,
		errGenesisStoreUnavailable, "list deployment genesis",
		func(key, versionID string, lastModified *time.Time) (bool, error) {
			if key != deploymentGenesisKey || versionID == "" || lastModified == nil {
				return false, nil
			}
			entry, err := l.readGenesis(ctx, versionID)
			if err != nil || entry == nil {
				return false, err
			}
			genesis = &GenesisArtifact{
				PCR0:        entry.PCR0,
				PublishedAt: lastModified.UTC(),
				VersionID:   versionID,
				Attestation: entry.Attestation,
			}
			return true, nil
		})
	if err != nil {
		return nil, err
	}
	return genesis, nil
}

// CommitGenesis records that pcr0 opened this deployment. The write is
// create-only: the fact is established once and never revised.
func (l *genesisLog) CommitGenesis(
	ctx context.Context,
	pcr0 string,
) (*GenesisArtifact, error) {
	if !isCanonicalPCR0(pcr0) {
		return nil, fmt.Errorf("genesis PCR0 must be 96 lowercase hex characters")
	}
	payload, err := l.preImage(pcr0)
	if err != nil {
		return nil, err
	}
	doc, _, err := l.nsm.BuildAttestationDocument(WithUserData(payload))
	if err != nil {
		return nil, fmt.Errorf("attest deployment genesis: %w", err)
	}
	body, err := json.Marshal(deploymentGenesisV1{
		Schema:      deploymentGenesisSchemaV1,
		PCR0:        pcr0,
		Attestation: base64.StdEncoding.EncodeToString(doc),
	})
	if err != nil {
		return nil, fmt.Errorf("encode deployment genesis object: %w", err)
	}
	out, err := l.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:                    aws.String(l.bucket),
		Key:                       aws.String(deploymentGenesisKey),
		Body:                      bytes.NewReader(body),
		ContentType:               aws.String("application/json"),
		IfNoneMatch:               aws.String("*"),
		ObjectLockMode:            s3types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: aws.Time(time.Now().Add(l.cfg.GenesisRetention)),
	})
	if err != nil {
		if isPreconditionFailed(err) {
			return nil, errGenesisAlreadyCommitted
		}
		return nil, fmt.Errorf(
			"%w: put deployment genesis: %w", errGenesisStoreUnavailable, err,
		)
	}
	if out == nil || aws.ToString(out.VersionId) == "" {
		return nil, fmt.Errorf(
			"%w: put deployment genesis: S3 returned no version ID",
			errGenesisStoreUnavailable,
		)
	}
	genesis, err := l.Genesis(ctx)
	if err != nil {
		return nil, err
	}
	if genesis == nil {
		return nil, fmt.Errorf(
			"%w: deployment genesis missing after write", errGenesisStoreUnavailable,
		)
	}
	return genesis, nil
}

// preImage is the user_data a genesis record is signed over: canonical CBOR
// binding the schema, this bucket and the PCR0. The bucket is inside the
// signature, so a record cannot be moved between deployments — which is what a
// verifier relies on when it derives the bucket name itself.
func (l *genesisLog) preImage(pcr0 string) ([]byte, error) {
	payload, err := l.enc.Marshal(deploymentGenesisPayloadV1{
		Schema:     deploymentGenesisSchemaV1,
		BucketName: l.bucket,
		PCR0:       pcr0,
	})
	if err != nil {
		return nil, fmt.Errorf("encode deployment genesis: %w", err)
	}
	return payload, nil
}

// readGenesis returns one version if it is a well-formed genesis object. It does
// not verify the attestation.
func (l *genesisLog) readGenesis(
	ctx context.Context,
	versionID string,
) (*deploymentGenesisV1, error) {
	out, err := l.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket:    aws.String(l.bucket),
		Key:       aws.String(deploymentGenesisKey),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		return nil, fmt.Errorf(
			"%w: get deployment genesis version %q: %w",
			errGenesisStoreUnavailable,
			versionID,
			err,
		)
	}
	defer func() { _ = out.Body.Close() }()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: read deployment genesis version %q: %w",
			errGenesisStoreUnavailable,
			versionID,
			err,
		)
	}
	entry, err := decodeDeploymentGenesis(body)
	if err != nil || entry.Schema != deploymentGenesisSchemaV1 ||
		entry.Attestation == "" || !isCanonicalPCR0(entry.PCR0) {
		return nil, nil
	}
	return &entry, nil
}

func decodeDeploymentGenesis(body []byte) (deploymentGenesisV1, error) {
	var entry deploymentGenesisV1
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return entry, fmt.Errorf("deployment genesis must be a JSON object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return entry, err
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return entry, fmt.Errorf("invalid or duplicate deployment genesis field")
		}
		seen[name] = true
		switch name {
		case "schema":
			err = decoder.Decode(&entry.Schema)
		case "pcr0":
			err = decoder.Decode(&entry.PCR0)
		case "attestation":
			err = decoder.Decode(&entry.Attestation)
		default:
			return entry, fmt.Errorf("unknown deployment genesis field %q", name)
		}
		if err != nil {
			return entry, err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return entry, err
	}
	if len(seen) != 3 {
		return entry, fmt.Errorf("deployment genesis fields are missing")
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return entry, err
		}
		return entry, fmt.Errorf("unexpected trailing JSON token %v", token)
	}
	return entry, nil
}
