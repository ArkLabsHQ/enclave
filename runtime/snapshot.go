package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	snapshotObjectPrefix   = "snapshot/"
	snapshotObjectSchemaV1 = "enclave.snapshot_object.v1"
	snapshotSchemaV1       = "enclave.snapshot.v1"
	snapshotRootDomainV1   = "enclave.snapshot_root.v1\x00" // SHA256 domain separator

	purposeStateOrigin         = "enclave.state_origin"
	purposeMigrationTransition = "enclave.state_origin.migration_transition"
)

var (
	errSnapshotStoreUnavailable = errors.New("snapshot store: unavailable")
	errSnapshotConflict         = errors.New("snapshot: another snapshot is published")
	errSnapshotAmbiguous        = errors.New("snapshot: ambiguous")
	errSnapshotUnverifiable     = errors.New("snapshot: no version verifies")
)

// Snapshot holds a generation's state and its predecessor's transition receipt.
// Its owner publishes it at snapshot/<pcr0> with an attested root and Object Lock.
type Snapshot struct {
	kmsKeyID                  string
	ownerPCR0                 string
	predecessorPCR0           string
	predecessorKMSKeyID       string
	masterSeedCiphertext      string
	tlsKeyCiphertext          string
	migrationIntentBucketName string

	// Empty at genesis; excluded from the root it attests.
	transitionReceipt string
}

type snapshotRootPayloadV1 struct {
	Purpose             string `cbor:"purpose"`
	SnapshotRoot        []byte `cbor:"snapshot_root"`
	KMSKeyID            string `cbor:"kms_key_id,omitempty"`
	PredecessorPCR0     string `cbor:"predecessor_pcr0,omitempty"`
	PredecessorKMSKeyID string `cbor:"predecessor_kms_key_id,omitempty"`
}

func (s Snapshot) attestOrigin(cfg *Config, nsm NSM) (string, error) {
	root, err := s.root(cfg)
	if err != nil {
		return "", err
	}
	payload, err := cbor.Marshal(s.originPayload(root))
	if err != nil {
		return "", fmt.Errorf("serialize state-origin receipt payload: %w", err)
	}
	doc, _, err := nsm.BuildAttestationDocument(WithUserData(payload))
	if err != nil {
		return "", fmt.Errorf("failed to attest state origin: %w", err)
	}
	return base64.StdEncoding.EncodeToString(doc), nil
}

func (s Snapshot) originPayload(root []byte) snapshotRootPayloadV1 {
	return snapshotRootPayloadV1{
		Purpose: purposeStateOrigin, SnapshotRoot: root,
		KMSKeyID: s.kmsKeyID, PredecessorPCR0: s.predecessorPCR0,
		PredecessorKMSKeyID: s.predecessorKMSKeyID,
	}
}

func (s Snapshot) verifyOriginReceipt(nsm NSM, receipt string, root []byte) error {
	payload, err := cbor.Marshal(s.originPayload(root))
	if err != nil {
		return fmt.Errorf("failed to encode state origin payload: %w", err)
	}
	return verifyAttestationUserData(
		nsm, receipt, map[uint]string{0: s.ownerPCR0}, payload,
	)
}

// PCR31 must commit to the owner even if predecessor and owner are equal;
// otherwise an attestation with no handoff commitment could pass.
func transitionPCRs(predecessorPCR0 string, owner []byte) map[uint]string {
	return map[uint]string{
		0:                 predecessorPCR0,
		migrationPCRIndex: hex.EncodeToString(pcrExtendFromZero(owner)),
	}
}

// verifyStateReceipt checks receipt PCRs and user_data {purpose,snapshot_root}.
func verifyStateReceipt(
	nsm NSM,
	receiptB64 string,
	purpose string,
	expectedSnapshotRoot []byte,
	expectedPCRs map[uint]string,
) error {
	expectedUserData, err := cbor.Marshal(snapshotRootPayloadV1{
		Purpose:      purpose,
		SnapshotRoot: expectedSnapshotRoot,
	})
	if err != nil {
		return fmt.Errorf("failed to encode state origin payload: %w", err)
	}

	return verifyAttestationUserData(nsm, receiptB64, expectedPCRs, expectedUserData)
}

// WriteTransitionReceipt is called by the predecessor during a handoff; PCR31
// must already commit to the successor PCR0.
func WriteTransitionReceipt(
	ctx context.Context,
	cfg *Config,
	nsm NSM,
	ssm SSM,
	snapshot Snapshot,
) error {
	root, err := snapshot.root(cfg)
	if err != nil {
		return fmt.Errorf("compute successor snapshot root: %w", err)
	}
	return writeReceipt(
		ctx,
		nsm,
		ssm,
		snapshotRootPayloadV1{
			Purpose: purposeMigrationTransition, SnapshotRoot: root,
		},
		cfg.migrationStateOriginReceiptParam(snapshot.kmsKeyID, snapshot.ownerPCR0),
		WithoutOverwrite(),
	)
}

// writeReceipt attests over receipt and stores it at param. Advanced tier: an
// attestation doc exceeds the 4 KB Standard-tier limit.
func writeReceipt(
	ctx context.Context,
	nsm NSM,
	ssm SSM,
	receipt snapshotRootPayloadV1,
	param string,
	opts ...SSMSetOption,
) error {
	payload, err := cbor.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("serialize receipt payload: %w", err)
	}

	doc, _, err := nsm.BuildAttestationDocument(WithUserData(payload))
	if err != nil {
		return fmt.Errorf("failed to build attestation: %w", err)
	}

	b64 := base64.StdEncoding.EncodeToString(doc)
	return ssm.Set(ctx, param, b64, append([]SSMSetOption{WithAdvancedTier()}, opts...)...)
}

// Both receipts attest the root of this canonical snapshot encoding.
type snapshotV1 struct {
	Schema               string `cbor:"schema"`
	Namespace            string `cbor:"namespace"`
	AppName              string `cbor:"app_name"`
	Lock                 string `cbor:"lock"`
	Bucket               string `cbor:"bucket"`
	OwnerPCR0            string `cbor:"owner_pcr0"`
	KMSKeyID             string `cbor:"kms_key_id"`
	MasterSeedCiphertext []byte `cbor:"master_seed_ciphertext"`
	TLSKeyCiphertext     []byte `cbor:"tls_key_ciphertext"`
	PredecessorPCR0      string `cbor:"predecessor_pcr0"`
	PredecessorKMSKeyID  string `cbor:"predecessor_kms_key_id"`
}

// Receipts wrap the snapshot so adding them does not change its root.
type snapshotObjectV1 struct {
	Schema                string `json:"schema"`
	Snapshot              []byte `json:"snapshot"`
	TransitionAttestation string `json:"transition_attestation"`
	OriginAttestation     string `json:"origin_attestation"`
}

func (s Snapshot) marshalObject(cfg *Config, originReceipt string) ([]byte, error) {
	raw, err := s.encode(cfg)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(snapshotObjectV1{
		Schema:                snapshotObjectSchemaV1,
		Snapshot:              raw,
		TransitionAttestation: s.transitionReceipt,
		OriginAttestation:     originReceipt,
	})
	if err != nil {
		return nil, fmt.Errorf("encode snapshot object: %w", err)
	}
	return body, nil
}

// readSnapshot returns the earliest verified version, or nil only for an absent
// key. Object Lock protects versions; newer writes and delete markers can hide
// them. Invalid or unreadable state must not be mistaken for a fresh genesis.
func readSnapshot(
	ctx context.Context, cfg *Config, s3api S3API, nsm NSM, bucket, pcr0 string,
) (*Snapshot, error) {
	key := snapshotObjectKey(pcr0)
	var earliest *Snapshot
	var earliestAt time.Time
	ambiguous := false
	versions := 0
	err := forEachObjectVersion(ctx, s3api, bucket, key, errSnapshotStoreUnavailable,
		"list snapshots",
		func(versionKey, versionID string, lastModified *time.Time) (bool, error) {
			if versionKey != key || versionID == "" || lastModified == nil {
				return false, nil
			}
			versions++
			publishedAt := lastModified.UTC()
			body, ok, err := readLockedVersion(
				ctx, s3api, bucket, key, versionID, publishedAt,
				cfg.SnapshotRetention, cfg.IntentWriteTimeout,
				errSnapshotStoreUnavailable, "snapshot",
			)
			if err != nil || !ok {
				return false, err
			}
			snapshot, err := openSnapshot(cfg, nsm, bucket, strings.ToLower(pcr0), body)
			if err != nil {
				slog.Warn("ignoring invalid snapshot",
					"key", key, "version", versionID, "error", err)
				return false, nil
			}
			switch {
			case earliest == nil || publishedAt.Before(earliestAt):
				earliest, earliestAt, ambiguous = &snapshot, publishedAt, false
			case publishedAt.Equal(earliestAt) && !snapshot.sameState(*earliest):
				ambiguous = true
			}
			return false, nil
		})
	if err != nil {
		return nil, err
	}
	if earliest == nil && versions > 0 {
		return nil, fmt.Errorf("%w: %s has %d versions", errSnapshotUnverifiable, key, versions)
	}
	if ambiguous {
		return nil, fmt.Errorf(
			"%w: %s has different states published at %s", errSnapshotAmbiguous, key, earliestAt,
		)
	}
	return earliest, nil
}

func openSnapshot(cfg *Config, nsm NSM, bucket, pcr0 string, body []byte) (Snapshot, error) {
	snapshot, err := parseSnapshotObject(cfg, nsm, body)
	if err != nil {
		return Snapshot{}, err
	}
	if snapshot.ownerPCR0 != pcr0 {
		return Snapshot{}, fmt.Errorf("snapshot belongs to %s", prefix16(snapshot.ownerPCR0))
	}
	if snapshot.migrationIntentBucketName != bucket {
		return Snapshot{}, fmt.Errorf(
			"snapshot names bucket %q", snapshot.migrationIntentBucketName,
		)
	}
	return snapshot, nil
}

// parseSnapshotObject validates canonical encoding and the required receipts:
// origin for every snapshot, plus transition for a migrated generation.
func parseSnapshotObject(cfg *Config, nsm NSM, body []byte) (Snapshot, error) {
	var obj snapshotObjectV1
	if err := json.Unmarshal(body, &obj); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot object: %w", err)
	}
	if canonical, err := json.Marshal(obj); err != nil || !bytes.Equal(canonical, body) {
		return Snapshot{}, errors.New("snapshot object is not canonical")
	}
	if obj.Schema != snapshotObjectSchemaV1 {
		return Snapshot{}, fmt.Errorf("unexpected snapshot object schema %q", obj.Schema)
	}
	snapshot, err := decodeSnapshot(cfg, obj.Snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.transitionReceipt = obj.TransitionAttestation

	root, err := snapshot.root(cfg)
	if err != nil {
		return Snapshot{}, err
	}
	if err := snapshot.verifyOriginReceipt(nsm, obj.OriginAttestation, root); err != nil {
		return Snapshot{}, fmt.Errorf("invalid state-origin receipt: %w", err)
	}
	if snapshot.predecessorPCR0 == "" {
		if snapshot.transitionReceipt != "" {
			return Snapshot{}, errors.New("genesis snapshot carries a transition receipt")
		}
		return snapshot, nil
	}
	_, owner, err := normalizePCR0(snapshot.ownerPCR0)
	if err != nil {
		return Snapshot{}, err
	}
	if err := verifyStateReceipt(
		nsm, snapshot.transitionReceipt, purposeMigrationTransition, root,
		transitionPCRs(snapshot.predecessorPCR0, owner),
	); err != nil {
		return Snapshot{}, fmt.Errorf("invalid transition receipt: %w", err)
	}
	return snapshot, nil
}

// Receipt bytes may differ for the same state root.
func (s Snapshot) sameState(other Snapshot) bool {
	s.transitionReceipt, other.transitionReceipt = "", ""
	return s == other
}

func snapshotObjectKey(pcr0 string) string {
	return snapshotObjectPrefix + strings.ToLower(pcr0)
}

func (s Snapshot) root(cfg *Config) ([]byte, error) {
	raw, err := s.encode(cfg)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(snapshotRootDomainV1))
	h.Write(raw)
	return h.Sum(nil), nil
}

func (s Snapshot) encode(cfg *Config) ([]byte, error) {
	if s.ownerPCR0 == "" {
		return nil, fmt.Errorf("snapshot has no owner PCR0")
	}
	seed, err := base64.StdEncoding.DecodeString(s.masterSeedCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decode master seed ciphertext: %w", err)
	}
	tlsKey, err := base64.StdEncoding.DecodeString(s.tlsKeyCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decode TLS key ciphertext: %w", err)
	}
	return encodeSnapshotDoc(snapshotV1{
		Schema:               snapshotSchemaV1,
		Namespace:            cfg.Namespace,
		AppName:              cfg.AppName,
		Lock:                 cfg.lockSegment(),
		Bucket:               s.migrationIntentBucketName,
		OwnerPCR0:            s.ownerPCR0,
		KMSKeyID:             s.kmsKeyID,
		MasterSeedCiphertext: seed,
		TLSKeyCiphertext:     tlsKey,
		PredecessorPCR0:      s.predecessorPCR0,
		PredecessorKMSKeyID:  s.predecessorKMSKeyID,
	})
}

func encodeSnapshotDoc(doc snapshotV1) ([]byte, error) {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("build canonical CBOR encoder: %w", err)
	}
	raw, err := enc.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("encode snapshot: %w", err)
	}
	return raw, nil
}

// decodeSnapshot accepts only the one canonical encoding of a complete snapshot
// for this deployment. Re-encoding catches unknown and duplicate fields.
func decodeSnapshot(cfg *Config, raw []byte) (Snapshot, error) {
	var doc snapshotV1
	if err := cbor.Unmarshal(raw, &doc); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	if canonical, err := encodeSnapshotDoc(doc); err != nil || !bytes.Equal(canonical, raw) {
		return Snapshot{}, errors.New("snapshot is not canonical CBOR")
	}
	switch {
	case doc.Schema != snapshotSchemaV1:
		return Snapshot{}, fmt.Errorf("unexpected snapshot schema %q", doc.Schema)
	case doc.Namespace != cfg.Namespace || doc.AppName != cfg.AppName ||
		doc.Lock != cfg.lockSegment():
		return Snapshot{}, errors.New("snapshot belongs to another deployment")
	case !isCanonicalPCR0(doc.OwnerPCR0):
		return Snapshot{}, errors.New("snapshot owner is not a canonical PCR0")
	case doc.KMSKeyID == "" || len(doc.MasterSeedCiphertext) == 0 || len(doc.TLSKeyCiphertext) == 0:
		return Snapshot{}, errors.New("snapshot is incomplete")
	case (doc.PredecessorPCR0 == "") != (doc.PredecessorKMSKeyID == ""):
		return Snapshot{}, errors.New("snapshot predecessor identity is incomplete")
	case doc.PredecessorPCR0 != "" &&
		(!isCanonicalPCR0(doc.PredecessorPCR0) || doc.PredecessorPCR0 == doc.OwnerPCR0):
		return Snapshot{}, errors.New("snapshot predecessor is invalid")
	}
	return Snapshot{
		kmsKeyID:                  doc.KMSKeyID,
		ownerPCR0:                 doc.OwnerPCR0,
		predecessorPCR0:           doc.PredecessorPCR0,
		predecessorKMSKeyID:       doc.PredecessorKMSKeyID,
		masterSeedCiphertext:      base64.StdEncoding.EncodeToString(doc.MasterSeedCiphertext),
		tlsKeyCiphertext:          base64.StdEncoding.EncodeToString(doc.TLSKeyCiphertext),
		migrationIntentBucketName: doc.Bucket,
	}, nil
}
