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

type startState int

const (
	startStateGenesis startState = iota
	startStateResume
	startStateMigration
)

type unverifiedState struct {
	startState             startState
	currentPCR0            []byte
	kmsKeyID               string
	secretMetadata         []StaticSecretMetadata
	snapshot               persistedStateSnapshot
	receipt                string
	predecessorPCR0        string
	predecessorAttestation string
}

type verifiedState struct {
	kms                       PrimaryKMS
	dek                       DEK
	secrets                   []StaticSecret
	migrationIntentBucketName string
}

// persistedStateSnapshot is the exact SSM-backed state covered by a
// state-origin receipt. Its values are loaded or generated once and never
// reconstructed from SSM.
type persistedStateSnapshot struct {
	kmsKeyID                  string
	staticSecrets             []persistedSecret
	storageDEK                string
	migrationIntentBucketName string
}

type persistedSecret struct {
	metadata   StaticSecretMetadata
	ciphertext string
}

func EstablishState(
	ctx context.Context,
	nsm NSM,
	kmsAPI KMSAPI,
	sts STSAPI,
	ssm SSM,
) (verifiedState, error) {
	currentPCR0, err := nsm.PCR0()
	if err != nil {
		return verifiedState{}, fmt.Errorf("failed to read current PCR0: %w", err)
	}
	if len(currentPCR0) != 48 {
		return verifiedState{}, fmt.Errorf(
			"current PCR0 must be exactly 48 bytes, got %d", len(currentPCR0),
		)
	}

	state, err := loadUnverifiedState(ctx, ssm, currentPCR0)
	if err != nil {
		return verifiedState{}, fmt.Errorf("failed to load unverified state: %w", err)
	}

	if err := verifyPredecessorCommitment(nsm, state); err != nil {
		return verifiedState{}, fmt.Errorf("failed to verify predecessor commitment: %w", err)
	}

	kms, err := FetchOrCreatePrimaryKMS(
		ctx,
		nsm,
		kmsAPI,
		sts,
		state.kmsKeyID,
		state.predecessorPCR0,
		state.predecessorAttestation,
	)
	if err != nil {
		return verifiedState{}, fmt.Errorf("failed to fetch/create primary KMS key: %w", err)
	}

	return establishLoadedState(ctx, nsm, kms, ssm, state)
}

// WriteTransitionReceipt is called by the predecessor during a handoff; PCR31
// must already commit to the successor PCR0.
func WriteTransitionReceipt(
	ctx context.Context,
	nsm NSM,
	ssm SSM,
	snapshot persistedStateSnapshot,
) error {
	root, err := stateRoot(snapshot)
	if err != nil {
		return fmt.Errorf("compute successor state_root: %w", err)
	}
	return writeStateReceipt(
		ctx,
		nsm,
		ssm,
		root,
		purposeMigrationTransition,
		migrationStateOriginReceiptParam(snapshot.kmsKeyID),
	)
}

func loadUnverifiedState(
	ctx context.Context,
	ssm SSM,
	currentPCR0 []byte,
) (unverifiedState, error) {
	metadata, err := LoadStaticSecretMetadata()
	if err != nil {
		return unverifiedState{}, fmt.Errorf("failed to load static secret metadata: %w", err)
	}
	if err := validateStaticSecretNames(metadata); err != nil {
		return unverifiedState{}, fmt.Errorf("invalid static secret metadata: %w", err)
	}
	migrationIntentBucketName, err := ssm.MustGet(ctx, migrationIntentBucketParam())
	if err != nil {
		return unverifiedState{}, fmt.Errorf("failed to get migration intent bucket name: %w", err)
	}

	keyID, err := ssm.MayGet(ctx, kmsKeyIDParam())
	if err != nil {
		return unverifiedState{}, fmt.Errorf("failed to get KMS key ID SSM param: %w", err)
	}
	predecessorPCR0, err := ssm.MayGet(ctx, migrationPreviousPCR0Param())
	if err != nil {
		return unverifiedState{}, fmt.Errorf("failed to get predecessor PCR0 SSM param: %w", err)
	}
	predecessorAttestation, err := ssm.MayGet(
		ctx, migrationPreviousPCR0AttestationParam(),
	)
	if err != nil {
		return unverifiedState{}, fmt.Errorf("failed to get predecessor attestation SSM param: %w", err)
	}
	hasPredecessorPCR0 := predecessorPCR0 != ""
	hasPredecessorAttestation := predecessorAttestation != ""

	if hasPredecessorPCR0 != hasPredecessorAttestation {
		return unverifiedState{}, fmt.Errorf(
			"inconsistent migration predecessor artifacts (pcr0 present=%v, attestation present=%v)",
			hasPredecessorPCR0,
			hasPredecessorAttestation,
		)
	}

	hasPredecessor := hasPredecessorPCR0 && hasPredecessorAttestation

	state := unverifiedState{
		currentPCR0:            append([]byte(nil), currentPCR0...),
		kmsKeyID:               keyID,
		secretMetadata:         metadata,
		predecessorPCR0:        predecessorPCR0,
		predecessorAttestation: predecessorAttestation,
		snapshot: persistedStateSnapshot{
			migrationIntentBucketName: migrationIntentBucketName,
		},
	}

	if keyID == "" {
		if hasPredecessor {
			return unverifiedState{}, fmt.Errorf("genesis state has predecessor artifacts")
		}
		state.startState = startStateGenesis
		return state, nil
	}

	receipt, err := ssm.MayGet(
		ctx,
		stateOriginReceiptParam(keyID, hex.EncodeToString(currentPCR0)),
	)
	if err != nil {
		return unverifiedState{}, fmt.Errorf("failed to get state-origin receipt SSM param: %w", err)
	}
	if receipt != "" {
		state.startState = startStateResume
		state.receipt = receipt
	} else {
		receipt, err = ssm.MayGet(ctx, migrationStateOriginReceiptParam(keyID))
		if err != nil {
			return unverifiedState{}, fmt.Errorf("failed to get migration receipt SSM param: %w", err)
		}
		if receipt == "" || !hasPredecessor {
			return unverifiedState{}, fmt.Errorf(
				"invalid state: hasReceipt = false, hasMigrationReceipt = %t, hasMigrationArtifacts = %t",
				receipt != "",
				hasPredecessor,
			)
		}
		state.startState = startStateMigration
		state.receipt = receipt
	}

	secrets := make([]persistedSecret, 0, len(metadata))
	for _, secret := range metadata {
		param := secretCiphertextParam(secret.Name, keyID)
		ciphertext, err := ssm.MustGet(ctx, param)
		if err != nil {
			return unverifiedState{}, fmt.Errorf("required static secret SSM param missing: %w", err)
		}
		secrets = append(secrets, persistedSecret{
			metadata:   secret,
			ciphertext: ciphertext,
		})
	}
	dekCiphertext, err := ssm.MustGet(ctx, storageDEKCiphertextParam(keyID))
	if err != nil {
		return unverifiedState{}, fmt.Errorf("required DEK SSM param missing: %w", err)
	}
	state.snapshot.kmsKeyID = keyID
	state.snapshot.staticSecrets = secrets
	state.snapshot.storageDEK = dekCiphertext
	return state, nil
}

func verifyPredecessorCommitment(nsm NSM, state unverifiedState) error {
	eifPreviousPCR0 := getPreviousPCR0()

	if eifPreviousPCR0 == "genesis" {
		if state.predecessorPCR0 != "" || state.predecessorAttestation != "" {
			return fmt.Errorf("predecessor state set for genesis enclave")
		}
		return nil
	}
	if state.predecessorPCR0 == "" {
		return fmt.Errorf("previous PCR0 is required")
	}
	if state.predecessorAttestation == "" {
		return fmt.Errorf("previous PCR0 attestation is required")
	}

	isRollbackToSelf := strings.EqualFold(state.predecessorPCR0, hex.EncodeToString(state.currentPCR0))

	if !strings.EqualFold(eifPreviousPCR0, state.predecessorPCR0) && !isRollbackToSelf {
		return fmt.Errorf(
			"previous PCR0 SSM param does not match previous PCR0 committed in the EIF",
		)
	}

	expectedPCRs := map[uint]string{0: state.predecessorPCR0}
	// Verify PCR31 if this is not a rollback (curPCR0 != prevPCR0).
	if !isRollbackToSelf {
		expectedPCRs[migrationPCRIndex] = hex.EncodeToString(pcrExtendFromZero(state.currentPCR0))
	}

	return nsm.VerifyAttestation(state.predecessorAttestation, expectedPCRs, nil)
}

func establishLoadedState(
	ctx context.Context,
	nsm NSM,
	kms PrimaryKMS,
	ssm SSM,
	state unverifiedState,
) (verifiedState, error) {
	var snapshot persistedStateSnapshot
	var verified verifiedState
	var err error
	if state.startState == startStateGenesis {
		snapshot, verified, err = initializePersistedState(
			ctx, kms, ssm, state.secretMetadata, state.snapshot.migrationIntentBucketName,
		)
		if err != nil {
			return verifiedState{}, fmt.Errorf("failed to initialize persisted state: %w", err)
		}
	} else {
		snapshot = state.snapshot
	}

	root, err := stateRoot(snapshot)
	if err != nil {
		return verifiedState{}, fmt.Errorf("failed to build state root: %v", err)
	}

	switch state.startState {
	case startStateResume:
		if err := verifyStateOriginReceipt(
			nsm,
			state.receipt,
			purposeStateOrigin,
			root,
			map[uint]string{0: hex.EncodeToString(state.currentPCR0)},
		); err != nil {
			return verifiedState{}, fmt.Errorf("invalid state-origin receipt: %w", err)
		}
	case startStateMigration:
		curPCR0 := hex.EncodeToString(state.currentPCR0)

		expectedPCRs := map[uint]string{
			0: state.predecessorPCR0,
		}

		// Verify PCR31 if this migration is not a rollback (curPCR0 != prevPCR0)
		if !strings.EqualFold(state.predecessorPCR0, curPCR0) {
			expectedPCRs[migrationPCRIndex] = hex.EncodeToString(
				pcrExtendFromZero(state.currentPCR0),
			)
		}

		if err := verifyStateOriginReceipt(
			nsm,
			state.receipt,
			purposeMigrationTransition,
			root,
			expectedPCRs,
		); err != nil {
			return verifiedState{}, fmt.Errorf("invalid state-origin receipt: %w", err)
		}

	case startStateGenesis:
	}

	if state.startState != startStateGenesis {
		verified, err = materializePersistedState(ctx, kms, snapshot)
		if err != nil {
			return verifiedState{}, fmt.Errorf("failed to materialize persisted state: %w", err)
		}
	}

	switch state.startState {
	case startStateMigration, startStateGenesis:
		if err := writeStateReceipt(
			ctx,
			nsm,
			ssm,
			root,
			purposeStateOrigin,
			stateOriginReceiptParam(kms.KeyID(), hex.EncodeToString(state.currentPCR0)),
		); err != nil {
			return verifiedState{}, fmt.Errorf("failed to write state-origin receipt: %w", err)
		}
		if state.startState == startStateGenesis {
			if err := ssm.Set(ctx, kmsKeyIDParam(), kms.KeyID()); err != nil {
				return verifiedState{}, fmt.Errorf("failed to commit genesis KMS key ID: %w", err)
			}
		}
		slog.Info("wrote state-origin receipt",
			"start_state", state.startState, "key_id", prefix16(kms.KeyID()))
	}

	return verified, nil
}

func initializePersistedState(
	ctx context.Context,
	kms PrimaryKMS,
	ssm SSM,
	metadata []StaticSecretMetadata,
	migrationIntentBucketName string,
) (persistedStateSnapshot, verifiedState, error) {
	dekData, err := kms.GenerateDataKey(ctx)
	if err != nil {
		return persistedStateSnapshot{}, verifiedState{}, fmt.Errorf("generate DEK: %w", err)
	}
	dekCiphertext := base64.StdEncoding.EncodeToString(dekData.Ciphertext)
	if err := ssm.Set(ctx, storageDEKCiphertextParam(kms.KeyID()), dekCiphertext); err != nil {
		return persistedStateSnapshot{}, verifiedState{}, fmt.Errorf("failed to store DEK: %w", err)
	}

	persistedSecrets := make([]persistedSecret, 0, len(metadata))
	secrets := make([]StaticSecret, 0, len(metadata))
	for _, secret := range metadata {
		data, err := kms.GenerateDataKey(ctx)
		if err != nil {
			return persistedStateSnapshot{}, verifiedState{}, fmt.Errorf(
				"failed to generate static secret %s: %w", secret.Name, err,
			)
		}
		ciphertext := base64.StdEncoding.EncodeToString(data.Ciphertext)
		param := secretCiphertextParam(secret.Name, kms.KeyID())
		if err := ssm.Set(ctx, param, ciphertext); err != nil {
			return persistedStateSnapshot{}, verifiedState{}, fmt.Errorf(
				"failed to store static secret %s: %w", secret.Name, err,
			)
		}
		persistedSecrets = append(persistedSecrets, persistedSecret{
			metadata:   secret,
			ciphertext: ciphertext,
		})
		secrets = append(secrets, StaticSecret{
			StaticSecretMetadata: secret,
			Plaintext:            hex.EncodeToString(data.Plaintext),
		})
	}

	return persistedStateSnapshot{
			kmsKeyID:                  kms.KeyID(),
			staticSecrets:             persistedSecrets,
			storageDEK:                dekCiphertext,
			migrationIntentBucketName: migrationIntentBucketName,
		}, verifiedState{
			kms:                       kms,
			dek:                       &dek{key: append([]byte(nil), dekData.Plaintext...)},
			secrets:                   secrets,
			migrationIntentBucketName: migrationIntentBucketName,
		}, nil
}

func materializePersistedState(
	ctx context.Context,
	kms PrimaryKMS,
	snapshot persistedStateSnapshot,
) (verifiedState, error) {
	if kms.KeyID() != snapshot.kmsKeyID {
		return verifiedState{}, fmt.Errorf(
			"state KMS key ID %q does not match active KMS key ID %q",
			snapshot.kmsKeyID,
			kms.KeyID(),
		)
	}

	dekPlaintext, err := kms.Decrypt(ctx, snapshot.storageDEK)
	if err != nil {
		return verifiedState{}, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	secrets := make([]StaticSecret, 0, len(snapshot.staticSecrets))
	for _, secret := range snapshot.staticSecrets {
		plaintext, err := kms.Decrypt(ctx, secret.ciphertext)
		if err != nil {
			return verifiedState{}, fmt.Errorf(
				"failed to decrypt static secret %s: %w", secret.metadata.Name, err,
			)
		}
		secrets = append(secrets, StaticSecret{
			StaticSecretMetadata: secret.metadata,
			Plaintext:            hex.EncodeToString(plaintext),
		})
	}

	return verifiedState{
		kms:                       kms,
		dek:                       &dek{key: dekPlaintext},
		secrets:                   secrets,
		migrationIntentBucketName: snapshot.migrationIntentBucketName,
	}, nil
}

func validateStaticSecretNames(metadata []StaticSecretMetadata) error {
	seen := make(map[string]bool, len(metadata))
	for _, secret := range metadata {
		if secret.Name == "StorageDEK" {
			return fmt.Errorf("static secret %q collides with storage DEK", secret.Name)
		}
		if seen[secret.Name] {
			return fmt.Errorf("duplicate static secret %q", secret.Name)
		}
		seen[secret.Name] = true
	}
	return nil
}

// stateRoot returns the canonical state_root over one immutable snapshot. It
// performs no external reads.
func stateRoot(snapshot persistedStateSnapshot) ([]byte, error) {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("failed to build canonical CBOR encoder: %v", err)
	}

	arts := make([]ssmArtifactV1, 0, len(snapshot.staticSecrets)+3)
	arts = append(arts, ssmArtifactV1{
		Name: kmsKeyIDParam(), Value: snapshot.kmsKeyID,
	})
	arts = append(arts, ssmArtifactV1{
		Name: migrationIntentBucketParam(), Value: snapshot.migrationIntentBucketName,
	})

	for _, secret := range snapshot.staticSecrets {
		param := secretCiphertextParam(secret.metadata.Name, snapshot.kmsKeyID)
		h, err := sha256OfB64(secret.ciphertext)
		if err != nil {
			return nil, fmt.Errorf(
				"failed sha256 hash of ciphertext %s: %w", param, err,
			)
		}
		arts = append(arts, ssmArtifactV1{Name: param, ValueSHA256: h})
	}

	dekParam := storageDEKCiphertextParam(snapshot.kmsKeyID)
	dekHash, err := sha256OfB64(snapshot.storageDEK)
	if err != nil {
		return nil, fmt.Errorf(
			"failed sha256 hash of DEK %s: %w", dekParam, err,
		)
	}

	arts = append(arts, ssmArtifactV1{Name: dekParam, ValueSHA256: dekHash})

	inputBytes, err := enc.Marshal(stateRootInputV1{
		Schema:       stateRootSchemaV1,
		SSMArtifacts: arts,
	})
	if err != nil {
		return nil, fmt.Errorf("state_root: serialize input: %w", err)
	}

	h := sha256.New()
	h.Write([]byte(stateRootDomainV1))
	h.Write(inputBytes)

	out, err := enc.Marshal(stateRootV1Doc{Version: 1, Hash: h.Sum(nil)})
	if err != nil {
		return nil, fmt.Errorf("state_root: serialize doc: %w", err)
	}
	return out, nil
}

// writeStateReceipt attests over stateRoot and stores it at param. Advanced tier: an
// attestation doc exceeds the 4 KB Standard-tier limit.
func writeStateReceipt(
	ctx context.Context,
	nsm NSM,
	ssm SSM,
	stateRoot []byte,
	purpose, param string,
) error {
	payload, err := cbor.Marshal(stateOriginPayloadV1{Purpose: purpose, StateRoot: stateRoot})
	if err != nil {
		return fmt.Errorf("serialize receipt payload: %w", err)
	}

	doc, _, err := nsm.BuildAttestationDocument(WithUserData(payload))
	if err != nil {
		return fmt.Errorf("failed to build attestation: %w", err)
	}

	b64 := base64.StdEncoding.EncodeToString(doc)
	return ssm.Set(ctx, param, b64, WithAdvancedTier())
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
