package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// State-origin receipts bind KMSKeyID and ciphertext params to enclave PCRs.

const (
	stateRootSchemaV1 = "enclave.state_root.v1"
	stateRootDomainV1 = "enclave.state_root.v1\x00" // SHA256 domain separator

	purposeStateOrigin         = "enclave.state_origin"
	purposeMigrationTransition = "enclave.state_origin.migration_transition"
)

type StartState int

const (
	StartStateGenesis StartState = iota
	StartStateResume
	StartStateMigration
	StartStateInvalid
)

// StateOrigin owns startup-state provenance: state_root computation, boot
// classification, and receipt write/verify. Shared by Runtime and Migrator.
type stateOrigin struct {
	nsm     NSM
	ssm     SSM
	secrets []StaticSecretMetadata
	enc     cbor.EncMode
}

type StateOrigin interface {
	WriteTransitionReceipt(ctx context.Context, keyID string) error
}

func ClassifyStartState(
	ctx context.Context,
	kms PrimaryKMS,
	ssm SSM,
	secrets []StaticSecretMetadata,
) (StartState, error) {
	hasMigrationArtifacts, err := hasMigrationArtifacts(ctx, ssm)
	if err != nil {
		return StartStateInvalid, fmt.Errorf("failed to check for migration artifacts: %w", err)
	}

	if kms.Genesis() {
		if hasMigrationArtifacts {
			return StartStateInvalid, fmt.Errorf(
				"genesis primary KMS with predecessor artifacts present: %s", kms.KeyID(),
			)
		}

		return StartStateGenesis, nil
	}

	dekParam := storageDEKCiphertextParam(kms.KeyID())
	if _, err := ssm.MustGet(ctx, dekParam); err != nil {
		return StartStateInvalid, fmt.Errorf(
			"required DEK missing from SSM: %s - %w", dekParam, err,
		)
	}

	for _, s := range secrets {
		param := secretCiphertextParam(s.Name, kms.KeyID())
		if _, err := ssm.MustGet(ctx, param); err != nil {
			return StartStateInvalid, fmt.Errorf(
				"required static secret missing from SSM: %s - %w", param, err,
			)
		}
	}

	receipt, err := ssm.MayGet(ctx, stateOriginReceiptParam(kms.KeyID()))
	if err != nil {
		return StartStateInvalid, fmt.Errorf(
			"failed state origin receipt request from SSM: %w", err,
		)
	}

	if receipt != "" {
		return StartStateResume, nil
	}

	migReceipt, err := ssm.MayGet(ctx, migrationStateOriginReceiptParam(kms.KeyID()))
	if err != nil {
		return StartStateInvalid, fmt.Errorf(
			"failed state origin migration receipt request from SSM: %w", err,
		)
	}

	if migReceipt != "" && hasMigrationArtifacts {
		return StartStateMigration, nil
	}

	return StartStateInvalid, fmt.Errorf(
		"invalid state: hasReceipt = %t, hasMigrationReceipt = %t, hasMigrationArtifacts = %t",
		receipt != "", migReceipt != "", hasMigrationArtifacts,
	)
}

func EstablishStateOrigin(
	ctx context.Context,
	nsm NSM,
	kms PrimaryKMS,
	ssm SSM,
	secrets []StaticSecretMetadata,
	startState StartState,
) (StateOrigin, error) {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("failed to build canonical CBOR encoder: %v", err)
	}

	stateOrigin := &stateOrigin{nsm: nsm, ssm: ssm, secrets: secrets, enc: enc}

	root, err := stateOrigin.stateRoot(ctx, kms.KeyID())
	if err != nil {
		return nil, fmt.Errorf("failed to build state root: %v", err)
	}

	switch startState {
	case StartStateInvalid:
		return nil, fmt.Errorf("invalid start state")
	case StartStateResume:
		receiptB64, err := ssm.MustGet(ctx, stateOriginReceiptParam(kms.KeyID()))
		if err != nil {
			return nil, fmt.Errorf("required state-origin receipt SSM param missing")
		}
		pcr0, err := nsm.PCR0()
		if err != nil {
			return nil, fmt.Errorf("could not read PCR0 from NSM")
		}
		if err := verifyStateOriginReceipt(
			nsm,
			receiptB64,
			purposeStateOrigin,
			root,
			map[uint]string{0: hex.EncodeToString(pcr0)},
		); err != nil {
			return nil, fmt.Errorf("invalid state-origin receipt: %w", err)
		}
	case StartStateMigration:
		receiptB64, err := ssm.MustGet(ctx, migrationStateOriginReceiptParam(kms.KeyID()))
		if err != nil {
			return nil, fmt.Errorf("required migration-transition receipt SSM param missing")
		}

		prevPCR0, err := ssm.MustGet(ctx, migrationPreviousPCR0Param())
		if err != nil {
			return nil, fmt.Errorf("required migration predecessor PCR0 SSM param missing")
		}
		pcr0, err := nsm.PCR0()
		if err != nil {
			return nil, fmt.Errorf("could not read PCR0 from NSM")
		}

		curPCR0 := hex.EncodeToString(pcr0)

		expectedPCRs := map[uint]string{
			0: prevPCR0,
		}

		// Verify PCR31 if this migration is not a rollback (curPCR0 != prevPCR0)
		if !strings.EqualFold(prevPCR0, curPCR0) {
			expectedPCRs[migrationPCRIndex] = hex.EncodeToString(pcr0ToPCR31(pcr0))
		}

		if err := verifyStateOriginReceipt(
			nsm,
			receiptB64,
			purposeMigrationTransition,
			root,
			expectedPCRs,
		); err != nil {
			return nil, fmt.Errorf("invalid state-origin receipt: %w", err)
		}

		if err := stateOrigin.putReceipt(
			ctx, root, purposeStateOrigin, stateOriginReceiptParam(kms.KeyID()),
		); err != nil {
			return nil, fmt.Errorf("failed to write state-origin receipt: %w", err)
		}
	case StartStateGenesis:
		if err := stateOrigin.putReceipt(
			ctx, root, purposeStateOrigin, stateOriginReceiptParam(kms.KeyID()),
		); err != nil {
			return nil, fmt.Errorf("failed to write state-origin receipt: %w", err)
		}
	}

	switch startState {
	case StartStateMigration, StartStateGenesis:
		slog.Info("wrote state-origin receipt",
			"start_state", startState, "key_id", prefix16(kms.KeyID()))
	}

	return stateOrigin, nil
}

// writeTransitionReceipt is called by the predecessor during a handoff; PCR31
// must already commit to the successor PCR0.
func (s *stateOrigin) WriteTransitionReceipt(ctx context.Context, keyID string) error {
	stateRoot, err := s.stateRoot(ctx, keyID)
	if err != nil {
		return fmt.Errorf("compute successor state_root: %w", err)
	}
	return s.putReceipt(
		ctx, stateRoot, purposeMigrationTransition, migrationStateOriginReceiptParam(keyID),
	)
}

// stateRoot returns the canonical state_root over the artifacts owned for keyID.
// keyID is passed in (not read) so a predecessor can compute a successor's.
func (s *stateOrigin) stateRoot(ctx context.Context, keyID string) ([]byte, error) {
	arts := make([]ssmArtifactV1, 0, len(s.secrets)+2)
	arts = append(arts, ssmArtifactV1{Name: kmsKeyIDParam(), Value: keyID})

	for _, sec := range s.secrets { // config order
		param := secretCiphertextParam(sec.Name, keyID)
		ctB64, err := s.ssm.MustGet(ctx, param)
		if err != nil {
			return nil, fmt.Errorf("required static secret SSM param missing: %w", err)
		}

		h, err := sha256OfB64(ctB64)
		if err != nil {
			return nil, fmt.Errorf("failed sha256 hash of ciphertext %s: %w", param, err)
		}
		arts = append(arts, ssmArtifactV1{Name: param, ValueSHA256: h})
	}

	dekParam := storageDEKCiphertextParam(keyID)
	dekB64, err := s.ssm.MustGet(ctx, dekParam)
	if err != nil {
		return nil, fmt.Errorf("required dek SSM param missing: %w", err)
	}

	dekHash, err := sha256OfB64(dekB64)
	if err != nil {
		return nil, fmt.Errorf("failed sha256 hash of dek %s: %w", dekParam, err)
	}

	arts = append(arts, ssmArtifactV1{Name: dekParam, ValueSHA256: dekHash})

	inputBytes, err := s.enc.Marshal(stateRootInputV1{
		Schema:       stateRootSchemaV1,
		SSMArtifacts: arts,
	})
	if err != nil {
		return nil, fmt.Errorf("state_root: serialize input: %w", err)
	}

	h := sha256.New()
	h.Write([]byte(stateRootDomainV1))
	h.Write(inputBytes)

	out, err := s.enc.Marshal(stateRootV1Doc{Version: 1, Hash: h.Sum(nil)})
	if err != nil {
		return nil, fmt.Errorf("state_root: serialize doc: %w", err)
	}
	return out, nil
}

// putReceipt attests over stateRoot and stores it at param. Advanced tier: an
// attestation doc exceeds the 4 KB Standard-tier limit.
func (s *stateOrigin) putReceipt(
	ctx context.Context,
	stateRoot []byte,
	purpose, param string,
) error {
	payload, err := s.enc.Marshal(stateOriginPayloadV1{Purpose: purpose, StateRoot: stateRoot})
	if err != nil {
		return fmt.Errorf("serialize receipt payload: %w", err)
	}

	doc, _, err := s.nsm.BuildAttestationDocument(WithUserData(payload))
	if err != nil {
		return fmt.Errorf("failed to build attestation: %w", err)
	}

	b64 := base64.StdEncoding.EncodeToString(doc)
	if err := s.ssm.Set(ctx, param, b64, WithAdvancedTier()); err != nil {
		return err
	}

	return nil
}

// hasMigrationArtifacts reports whether both predecessor params are present,
// erroring on a half-written pair.
func hasMigrationArtifacts(ctx context.Context, ssm SSM) (bool, error) {
	prevPCR0, err := ssm.MayGet(ctx, migrationPreviousPCR0Param())
	if err != nil {
		return false, err
	}
	prevAtt, err := ssm.MayGet(ctx, migrationPreviousPCR0AttestationParam())
	if err != nil {
		return false, err
	}
	switch {
	case prevPCR0 == "" && prevAtt == "":
		return false, nil
	case prevPCR0 != "" && prevAtt != "":
		return true, nil
	default:
		return false, fmt.Errorf(
			"inconsistent migration predecessor artifacts (pcr0 present=%v, attestation present=%v)",
			prevPCR0 != "",
			prevAtt != "",
		)
	}
}

// verifyStateOriginReceipt checks receipt PCRs and user_data {purpose,state_root}.
func verifyStateOriginReceipt(
	nsm NSM,
	receiptB64 string,
	purpose string,
	expectedStateRoot []byte,
	expectedPCRs map[uint]string,
) error {
	expectedUserData, err := cbor.Marshal(stateOriginPayloadV1{
		Purpose:   purpose,
		StateRoot: expectedStateRoot,
	})
	if err != nil {
		return fmt.Errorf("failed to encode state origin payload: %w", err)
	}

	return nsm.VerifyAttestation(receiptB64, expectedPCRs, expectedUserData)
}

// ssmArtifactV1 records a param value or its SHA256.
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
