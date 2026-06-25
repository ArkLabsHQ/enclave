package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ArkLabsHQ/introspector-enclave/runtime/nitriding"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/fxamacker/cbor/v2"
)

// State-origin receipts (issue #131): bind the SSM state the runtime owns
// (KMSKeyID, secret + storage-DEK ciphertexts) to this enclave's identity via an
// NSM-signed receipt whose user_data commits to a state_root. Boot recomputes
// the state_root and fails closed without a valid receipt, so a host can't
// pre-seed or swap that state.

const (
	stateRootSchemaV1 = "enclave.state_root.v1"
	stateRootDomainV1 = "enclave.state_root.v1\x00" // SHA256 domain separator

	purposeStateOrigin         = "enclave.state_origin"
	purposeMigrationTransition = "enclave.state_origin.migration_transition"
)

// canonicalCBOR gives RFC 8949 §4.2.1 deterministic encoding, so state_root is a
// stable commitment across the writer and the verifier.
var canonicalCBOR cbor.EncMode

func init() {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("state_origin: build canonical CBOR encoder: %v", err))
	}
	canonicalCBOR = em
}

// ssmArtifactV1 is one state_root entry: a full param path plus exactly one of
// Value (small ids) or ValueSHA256 (ciphertext/attestation blobs).
type ssmArtifactV1 struct {
	Name        string `cbor:"name"`
	Value       string `cbor:"value,omitempty"`
	ValueSHA256 []byte `cbor:"value_sha256,omitempty"`
}

// stateRootInputV1 is the state_root pre-image. Migration provenance is
// deliberately excluded: the predecessor params are overwritten on every
// migration attempt, so committing to them would brick an enclave's own receipt
// on reboot — the handoff is authenticated by the transition receipt instead.
type stateRootInputV1 struct {
	Schema       string          `cbor:"schema"`
	SSMArtifacts []ssmArtifactV1 `cbor:"ssm_artifacts"`
}

type stateRootV1Doc struct {
	Version int    `cbor:"version"`
	Hash    []byte `cbor:"hash"`
}

// stateOriginPayloadV1 is the receipt's user_data.
type stateOriginPayloadV1 struct {
	Purpose   string `cbor:"purpose"`
	StateRoot []byte `cbor:"state_root"`
}

func sha256OfB64(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	h := sha256.Sum256(raw)
	return h[:], nil
}

// StateOrigin owns startup-state provenance: state_root computation, boot
// classification, and receipt write/verify. Shared by Runtime and Migrator.
type StateOrigin struct {
	ssm          SSMAPI
	secrets      []StaticSecret
	lineage      *PCR0Lineage // immutable PCR0 version-history log; nil only in tests
	anchorBucket string       // canonical freshness-anchor bucket name, for the genesis descriptor
}

func NewStateOrigin(ssm SSMAPI, secrets []StaticSecret) *StateOrigin {
	return &StateOrigin{ssm: ssm, secrets: secrets}
}

// Establish runs the startup-state protocol in the one safe order: classify →
// ensureKey → verify (resume/migration, before decrypt) → loadState → write
// receipt (genesis/migration). ensureKey and loadState are injected so
// StateOrigin owns the ordering without depending on KMS/secrets/storage.
func (s *StateOrigin) Establish(ctx context.Context, rawKeyID, ownPCR0 string, ensureKey func() (string, error), loadState func(keyID string) error) error {
	mode, err := s.classify(ctx, rawKeyID)
	if err != nil {
		return fmt.Errorf("classify startup state: %w", err)
	}
	slog.Info("startup state classified", "mode", mode.String())

	keyID, err := ensureKey()
	if err != nil {
		return err
	}

	switch mode {
	case modeResume:
		if err := s.verifyResume(ctx, keyID, ownPCR0); err != nil {
			return fmt.Errorf("verify state-origin receipt: %w", err)
		}
	case modeMigration:
		if err := s.verifyMigrationAdoption(ctx, keyID, ownPCR0); err != nil {
			return fmt.Errorf("verify migration-transition receipt: %w", err)
		}
	}

	if err := loadState(keyID); err != nil {
		return err
	}

	if mode == modeGenesis || mode == modeMigration {
		if err := s.writeReceipt(ctx, keyID); err != nil {
			return fmt.Errorf("write state-origin receipt: %w", err)
		}
		slog.Info("wrote state-origin receipt", "mode", mode.String(), "key_id", prefix16(keyID))
		// Append to the immutable PCR0 lineage log (audit-only; failures are logged).
		// On genesis, also build the deployment descriptor, write it to SSM, and bind
		// sha256(descriptor) into the self-attestation's user_data.
		if s.lineage != nil {
			var userData, descriptor []byte
			if mode == modeGenesis {
				desc := s.genesisDescriptor(ownPCR0)
				if d, err := canonicalCBOR.Marshal(desc); err == nil {
					descriptor = d
					if h, err := descriptorHash(desc); err == nil {
						userData = h
					}
					if err := s.writeGenesisDescriptor(ctx, desc); err != nil {
						slog.Warn("write genesis descriptor", "error", err)
					}
				}
			}
			if selfAttest, err := getAttestationDocumentB64WithUserData(userData); err != nil {
				slog.Warn("self-attest for PCR0 lineage", "mode", mode.String(), "error", err)
			} else if err := s.recordLineage(ctx, ownPCR0, mode, selfAttest, descriptor); err != nil {
				slog.Warn("record PCR0 lineage", "mode", mode.String(), "error", err)
			}
		}
	}
	return nil
}

// genesisDescriptor builds the deployment descriptor — the out-of-band-pinnable root
// of trust: genesis PCR0 + canonical bucket names + region.
func (s *StateOrigin) genesisDescriptor(ownPCR0 string) deploymentDescriptorV1 {
	lineageBucket := ""
	if s.lineage != nil {
		lineageBucket = s.lineage.bucket
	}
	return deploymentDescriptorV1{
		Schema:        descriptorSchemaV1,
		Deployment:    getDeployment(),
		App:           getAppName(),
		Region:        getRegion(),
		GenesisPCR0:   ownPCR0,
		AnchorBucket:  s.anchorBucket,
		LineageBucket: lineageBucket,
	}
}

// writeGenesisDescriptor stores the descriptor as JSON in SSM so /v1/enclave-info can
// surface it (discovery only; trust comes from the out-of-band pin + attestation).
func (s *StateOrigin) writeGenesisDescriptor(ctx context.Context, desc deploymentDescriptorV1) error {
	j, err := json.Marshal(desc)
	if err != nil {
		return err
	}
	_, err = s.ssm.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(genesisDescriptorParam()),
		Value:     aws.String(string(j)),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	return err
}

// recordLineage appends this enclave's lineage entry: its own self-attestation (plus,
// for genesis, the descriptor), and on a genuine migration the predecessor's, which
// PCR31-commits to this enclave.
func (s *StateOrigin) recordLineage(ctx context.Context, ownPCR0 string, mode startupMode, selfAttest string, descriptor []byte) error {
	entry := lineageEntryV1{
		Schema:          lineageSchemaV1,
		Purpose:         lineagePurposeGenesis,
		SelfPCR0:        ownPCR0,
		SelfAttestation: selfAttest,
		Descriptor:      descriptor,
	}
	if mode == modeMigration {
		prevPCR0, err := readSSMParamOptional(ctx, s.ssm, migrationPreviousPCR0Param())
		if err != nil {
			return err
		}
		// A genuine predecessor (not genesis, not rollback-onto-self) carries the
		// PCR31 commitment; mirror VerifyPredecessorCommitment's gate.
		if prevPCR0 != "" && !strings.EqualFold(prevPCR0, ownPCR0) {
			prevAttest, err := readSSMParamOptional(ctx, s.ssm, migrationPreviousPCR0AttestationParam())
			if err != nil {
				return err
			}
			entry.Purpose = lineagePurposeMigration
			entry.PrevPCR0 = prevPCR0
			entry.PrevAttestation = prevAttest
		}
	}
	return s.lineage.record(ctx, entry)
}

// stateRoot returns the canonical state_root over the artifacts owned for keyID.
// keyID is passed in (not read) so a predecessor can compute a successor's.
func (s *StateOrigin) stateRoot(ctx context.Context, keyID string) ([]byte, error) {
	arts := make([]ssmArtifactV1, 0, len(s.secrets)+2)
	arts = append(arts, ssmArtifactV1{Name: kmsKeyIDParam(), Value: keyID})

	for _, sec := range s.secrets { // config order
		param := secretCiphertextParam(sec.Name, keyID)
		ctB64, err := readSSMParamOptional(ctx, s.ssm, param)
		if err != nil {
			return nil, err
		}
		if ctB64 == "" {
			return nil, fmt.Errorf("state_root: ciphertext missing at %s", param)
		}
		h, err := sha256OfB64(ctB64)
		if err != nil {
			return nil, fmt.Errorf("state_root: hash %s: %w", param, err)
		}
		arts = append(arts, ssmArtifactV1{Name: param, ValueSHA256: h})
	}

	dekParam := storageDEKCiphertextParam(keyID)
	dekB64, err := readSSMParamOptional(ctx, s.ssm, dekParam)
	if err != nil {
		return nil, err
	}
	if dekB64 == "" {
		return nil, fmt.Errorf("state_root: storage DEK ciphertext missing at %s", dekParam)
	}
	dekHash, err := sha256OfB64(dekB64)
	if err != nil {
		return nil, fmt.Errorf("state_root: hash %s: %w", dekParam, err)
	}
	arts = append(arts, ssmArtifactV1{Name: dekParam, ValueSHA256: dekHash})

	inputBytes, err := canonicalCBOR.Marshal(stateRootInputV1{
		Schema:       stateRootSchemaV1,
		SSMArtifacts: arts,
	})
	if err != nil {
		return nil, fmt.Errorf("state_root: serialize input: %w", err)
	}

	h := sha256.New()
	h.Write([]byte(stateRootDomainV1))
	h.Write(inputBytes)

	out, err := canonicalCBOR.Marshal(stateRootV1Doc{Version: 1, Hash: h.Sum(nil)})
	if err != nil {
		return nil, fmt.Errorf("state_root: serialize doc: %w", err)
	}
	return out, nil
}

// migrationArtifactsPresent reports whether both predecessor params are present,
// erroring on a half-written pair.
func (s *StateOrigin) migrationArtifactsPresent(ctx context.Context) (bool, error) {
	prevPCR0, err := readSSMParamOptional(ctx, s.ssm, migrationPreviousPCR0Param())
	if err != nil {
		return false, err
	}
	prevAtt, err := readSSMParamOptional(ctx, s.ssm, migrationPreviousPCR0AttestationParam())
	if err != nil {
		return false, err
	}
	switch {
	case prevPCR0 == "" && prevAtt == "":
		return false, nil
	case prevPCR0 != "" && prevAtt != "":
		return true, nil
	default:
		return false, fmt.Errorf("inconsistent migration predecessor artifacts (pcr0 present=%v, attestation present=%v)", prevPCR0 != "", prevAtt != "")
	}
}

// putReceipt attests over stateRoot and stores it at param. Advanced tier: an
// attestation doc exceeds the 4 KB Standard-tier limit.
func (s *StateOrigin) putReceipt(ctx context.Context, stateRoot []byte, purpose, param string) error {
	payload, err := canonicalCBOR.Marshal(stateOriginPayloadV1{Purpose: purpose, StateRoot: stateRoot})
	if err != nil {
		return fmt.Errorf("serialize receipt payload: %w", err)
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("read nonce: %w", err)
	}

	doc, err := nitriding.Attest(nonce, payload, nil)
	if err != nil {
		return fmt.Errorf("attest state-origin receipt: %w", err)
	}

	b64 := base64.StdEncoding.EncodeToString(doc)
	if _, err := s.ssm.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(param),
		Value:     aws.String(b64),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
		Tier:      ssmtypes.ParameterTierAdvanced,
	}); err != nil {
		return fmt.Errorf("store receipt at %s: %w", param, err)
	}
	return nil
}

// attestationRoots overrides the trust anchor for state-origin receipt
// verification; nil (production) uses the default Nitro root. Set only by tests.
var attestationRoots *x509.CertPool

// verifyStateOriginReceipt: nil iff receiptB64 is a genuine NSM doc with PCR0
// expectedPCR0Hex and user_data {expectedPurpose, expectedStateRoot}.
func verifyStateOriginReceipt(receiptB64 string, expectedStateRoot []byte, expectedPCR0Hex, expectedPurpose string) error {
	doc, err := base64.StdEncoding.DecodeString(receiptB64)
	if err != nil {
		return fmt.Errorf("decode receipt base64: %w", err)
	}

	res, err := verifyAttestationDoc(doc, attestationRoots)
	if err != nil {
		return fmt.Errorf("verify receipt attestation: %w", err)
	}

	pcr0, ok := res.Document.PCRs[0]
	if !ok {
		return fmt.Errorf("receipt missing PCR0")
	}
	if !strings.EqualFold(hex.EncodeToString(pcr0), expectedPCR0Hex) {
		return fmt.Errorf("receipt PCR0 does not match this enclave's identity")
	}

	var payload stateOriginPayloadV1
	if err := cbor.Unmarshal(res.Document.UserData, &payload); err != nil {
		return fmt.Errorf("decode receipt user_data: %w", err)
	}
	if payload.Purpose != expectedPurpose {
		return fmt.Errorf("receipt purpose mismatch: got %q, want %q", payload.Purpose, expectedPurpose)
	}
	if !bytes.Equal(payload.StateRoot, expectedStateRoot) {
		return fmt.Errorf("receipt state_root does not cover the current SSM state")
	}
	return nil
}

// verifyMigrationTransitionReceipt: nil iff receiptB64 is signed by
// predecessorPCR0Hex, its user_data carries expectedStateRoot under the
// migration-transition purpose, and its PCR31 commits to ownPCR0Hex. The PCR31
// check is skipped on rollback-onto-self (predecessor == us): there PCR31
// commits to the failed forward target, and the receipt's own PCR0 (== ours) is
// the proof. Mirrors VerifyPredecessorCommitment's prevPCR0==ownPCR0 case.
func verifyMigrationTransitionReceipt(receiptB64 string, expectedStateRoot []byte, predecessorPCR0Hex, ownPCR0Hex string) error {
	doc, err := base64.StdEncoding.DecodeString(receiptB64)
	if err != nil {
		return fmt.Errorf("decode migration receipt base64: %w", err)
	}

	res, err := verifyAttestationDoc(doc, attestationRoots)
	if err != nil {
		return fmt.Errorf("verify migration receipt attestation: %w", err)
	}

	pcr0, ok := res.Document.PCRs[0]
	if !ok {
		return fmt.Errorf("migration receipt missing PCR0")
	}
	if !strings.EqualFold(hex.EncodeToString(pcr0), predecessorPCR0Hex) {
		return fmt.Errorf("migration receipt PCR0 does not match the recorded predecessor")
	}

	if !strings.EqualFold(predecessorPCR0Hex, ownPCR0Hex) {
		pcr31, ok := res.Document.PCRs[migrationPCRIndex]
		if !ok {
			return fmt.Errorf("migration receipt missing PCR%d", migrationPCRIndex)
		}
		ownPCR0Bytes, err := hex.DecodeString(ownPCR0Hex)
		if err != nil {
			return fmt.Errorf("decode own PCR0 hex: %w", err)
		}
		expectedPCR31 := sha512.Sum384(append(make([]byte, 48), ownPCR0Bytes...))
		if !bytes.Equal(pcr31, expectedPCR31[:]) {
			return fmt.Errorf("migration receipt PCR%d does not commit to this enclave", migrationPCRIndex)
		}
	}

	var payload stateOriginPayloadV1
	if err := cbor.Unmarshal(res.Document.UserData, &payload); err != nil {
		return fmt.Errorf("decode migration receipt user_data: %w", err)
	}
	if payload.Purpose != purposeMigrationTransition {
		return fmt.Errorf("migration receipt purpose mismatch: got %q, want %q", payload.Purpose, purposeMigrationTransition)
	}
	if !bytes.Equal(payload.StateRoot, expectedStateRoot) {
		return fmt.Errorf("migration receipt state_root does not cover the successor state")
	}
	return nil
}

func (s *StateOrigin) verifyResume(ctx context.Context, keyID, ownPCR0 string) error {
	stateRoot, err := s.stateRoot(ctx, keyID)
	if err != nil {
		return fmt.Errorf("recompute state_root: %w", err)
	}
	receiptB64, err := readSSMParamOptional(ctx, s.ssm, stateOriginReceiptParam(keyID))
	if err != nil {
		return err
	}
	if receiptB64 == "" {
		return fmt.Errorf("state-origin receipt missing at %s", stateOriginReceiptParam(keyID))
	}
	return verifyStateOriginReceipt(receiptB64, stateRoot, ownPCR0, purposeStateOrigin)
}

func (s *StateOrigin) verifyMigrationAdoption(ctx context.Context, keyID, ownPCR0 string) error {
	stateRoot, err := s.stateRoot(ctx, keyID)
	if err != nil {
		return fmt.Errorf("recompute successor state_root: %w", err)
	}
	receiptB64, err := readSSMParamOptional(ctx, s.ssm, migrationStateOriginReceiptParam(keyID))
	if err != nil {
		return err
	}
	if receiptB64 == "" {
		return fmt.Errorf("migration-transition receipt missing at %s", migrationStateOriginReceiptParam(keyID))
	}
	prevPCR0, err := readSSMParamOptional(ctx, s.ssm, migrationPreviousPCR0Param())
	if err != nil {
		return err
	}
	if prevPCR0 == "" {
		return fmt.Errorf("migration predecessor PCR0 missing")
	}
	return verifyMigrationTransitionReceipt(receiptB64, stateRoot, prevPCR0, ownPCR0)
}

func (s *StateOrigin) writeReceipt(ctx context.Context, keyID string) error {
	stateRoot, err := s.stateRoot(ctx, keyID)
	if err != nil {
		return fmt.Errorf("compute state_root: %w", err)
	}
	return s.putReceipt(ctx, stateRoot, purposeStateOrigin, stateOriginReceiptParam(keyID))
}

// writeTransitionReceipt is called by the predecessor during a handoff; PCR31
// must already commit to the successor PCR0.
func (s *StateOrigin) writeTransitionReceipt(ctx context.Context, keyID string) error {
	stateRoot, err := s.stateRoot(ctx, keyID)
	if err != nil {
		return fmt.Errorf("compute successor state_root: %w", err)
	}
	return s.putReceipt(ctx, stateRoot, purposeMigrationTransition, migrationStateOriginReceiptParam(keyID))
}

type startupMode int

const (
	modeGenesis   startupMode = iota // no prior state — create it, write a receipt
	modeResume                       // complete state + self-receipt — verify, then decrypt
	modeMigration                    // complete state + transition receipt — adopt, then self-receipt
)

func (m startupMode) String() string {
	switch m {
	case modeGenesis:
		return "genesis"
	case modeResume:
		return "resume"
	case modeMigration:
		return "migration"
	default:
		return fmt.Sprintf("startupMode(%d)", int(m))
	}
}

// classify decides how to boot from the active keyID ("" = unset), reading SSM
// only. It checks artifact presence, not signatures, so the caller must run the
// verifier the returned mode selects before decrypting. Fails closed on partial
// or ambiguous state.
func (s *StateOrigin) classify(ctx context.Context, keyID string) (startupMode, error) {
	hasPredecessor, err := s.migrationArtifactsPresent(ctx)
	if err != nil {
		return 0, err
	}

	if keyID == "" {
		// No key yet, so no key-scoped artifacts to find; lingering predecessor
		// params would be an ambiguous half-migration.
		if hasPredecessor {
			return 0, fmt.Errorf("KMSKeyID unset but migration predecessor artifacts present — failing closed")
		}
		return modeGenesis, nil
	}

	// Resume and migration both require the complete ciphertext set — fail
	// closed on the first gap.
	for _, sec := range s.secrets {
		param := secretCiphertextParam(sec.Name, keyID)
		ct, err := readSSMParamOptional(ctx, s.ssm, param)
		if err != nil {
			return 0, err
		}
		if ct == "" {
			return 0, fmt.Errorf("uncovered startup state for key %s: secret ciphertext missing at %s — failing closed", prefix16(keyID), param)
		}
	}
	dek, err := readSSMParamOptional(ctx, s.ssm, storageDEKCiphertextParam(keyID))
	if err != nil {
		return 0, err
	}
	if dek == "" {
		return 0, fmt.Errorf("uncovered startup state for key %s: storage DEK ciphertext missing — failing closed", prefix16(keyID))
	}

	receipt, err := readSSMParamOptional(ctx, s.ssm, stateOriginReceiptParam(keyID))
	if err != nil {
		return 0, err
	}
	if receipt != "" {
		return modeResume, nil
	}

	// No self-receipt: only a verified migration handoff may proceed.
	migReceipt, err := readSSMParamOptional(ctx, s.ssm, migrationStateOriginReceiptParam(keyID))
	if err != nil {
		return 0, err
	}
	if migReceipt != "" && hasPredecessor {
		return modeMigration, nil
	}
	return 0, fmt.Errorf("uncovered startup state for key %s: no state-origin receipt (migration_receipt=%v, predecessor=%v) — failing closed",
		prefix16(keyID), migReceipt != "", hasPredecessor)
}
