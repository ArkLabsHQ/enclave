package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// State-origin receipts bind KMSKeyID and ciphertext params to enclave PCRs.
//
// A state_root is a deterministic hash over one immutable snapshot of the SSM
// artifacts an enclave depends on. Committing to it in an NSM attestation is
// what lets a later boot — or a successor across a migration — prove the state
// it loaded is the state some enclave of a known PCR0 actually wrote, rather
// than something the host substituted.

const (
	stateRootSchemaV1 = "enclave.state_root.v1"
	stateRootDomainV1 = "enclave.state_root.v1\x00" // SHA256 domain separator

	purposeStateOrigin         = "enclave.state_origin"
	purposeMigrationTransition = "enclave.state_origin.migration_transition"

	genesisLeaseName = "genesis"

	// genesisLeaseWait bounds how long we queue behind a peer's genesis.
	genesisLeaseWait = 10 * time.Minute
)

// bootResult is the boot machine's terminal state
type bootResult struct {
	kms     PrimaryKMS
	dek     DEK
	secrets []StaticSecret

	migrationIntentBucketName string
}

// bootSnapshot is the exact SSM-backed state covered by a
// state-origin receipt. Its values are loaded or generated once and never
// reconstructed from SSM.
type bootSnapshot struct {
	kmsKeyID                  string
	staticSecrets             map[StaticSecretMetadata]string // metadata → ciphertext
	storageDEK                string
	migrationIntentBucketName string
}

// bootState is what every boot knows, whatever brought it about.
type bootState struct {
	currentPCR0 []byte
	metadata    []StaticSecretMetadata
	kmsKeyID    string

	predecessorPCR0        string
	predecessorAttestation string
	bootReceipt            string // state-origin receipt for this PCR0
	migrationReceipt       string // predecessor's transition receipt
	snapshot               bootSnapshot
}

type bootMode interface {
	// verify ascertains this mode's preconditions hold over what was loaded.
	verify(state *bootState) error

	// buildSnapshot produces the artifacts the state_root is computed over —
	// created and persisted for genesis, already loaded for everyone else.
	buildSnapshot(ctx context.Context, state *bootState, kms PrimaryKMS, ssm SSM) (bootSnapshot, error)

	// verifySnapshot proves the snapshot came from an enclave we accept.
	verifySnapshot(state *bootState, nsm NSM, snapshotRoot []byte) error

	// commitSnapshot records what this boot established, if anything.
	commitSnapshot(ctx context.Context, state *bootState, nsm NSM, ssm SSM, kms PrimaryKMS, snapshotRoot []byte) error
}

type genesisBoot struct {
	lease *Lease
}

type resumeBoot struct{}

type migrationBoot struct{}

type Boot struct {
	nsm    NSM
	kmsAPI KMSAPI
	sts    STSAPI
	ssm    SSM
	s3     S3API
	pcr0   []byte
}

type plannedBoot struct {
	state bootState
	mode  bootMode
}

func NewBoot(nsm NSM, kmsAPI KMSAPI, sts STSAPI, ssm SSM, s3api S3API) (*Boot, error) {
	pcr0, err := nsm.PCR0()
	if err != nil {
		return nil, fmt.Errorf("failed to read current PCR0: %w", err)
	}
	if len(pcr0) != 48 {
		return nil, fmt.Errorf("current PCR0 must be exactly 48 bytes, got %d", len(pcr0))
	}
	return &Boot{nsm: nsm, kmsAPI: kmsAPI, sts: sts, ssm: ssm, s3: s3api, pcr0: pcr0}, nil
}

// plan decides, once, which of the three boots this is.
func (b *Boot) plan(ctx context.Context) (*plannedBoot, error) {
	metadata, err := LoadStaticSecretMetadata()
	if err != nil {
		return nil, fmt.Errorf("failed to load static secret metadata: %w", err)
	}
	if err := validateStaticSecretNames(metadata); err != nil {
		return nil, fmt.Errorf("invalid static secret metadata: %w", err)
	}
	migrationIntentBucketName, err := b.ssm.MustGet(ctx, migrationIntentBucketParam())
	if err != nil {
		return nil, fmt.Errorf("failed to get migration intent bucket name: %w", err)
	}

	predecessorPCR0, predecessorAttestation, err := b.loadPredecessor(ctx)
	if err != nil {
		return nil, err
	}
	state := bootState{
		currentPCR0:            append([]byte(nil), b.pcr0...),
		metadata:               metadata,
		predecessorPCR0:        predecessorPCR0,
		predecessorAttestation: predecessorAttestation,
		snapshot: bootSnapshot{
			migrationIntentBucketName: migrationIntentBucketName,
		},
	}

	mode, err := b.determineMode(ctx, &state)
	if err != nil {
		return nil, err
	}
	if err := mode.verify(&state); err != nil {
		return nil, err
	}
	return &plannedBoot{state: state, mode: mode}, nil
}

// determineMode loads what a committed key names — the params embed the key ID,
// so with none committed there is nothing to read — and decides the mode.
func (b *Boot) determineMode(ctx context.Context, state *bootState) (bootMode, error) {
	keyID, err := b.committedKeyID(ctx)
	if err != nil {
		return nil, err
	}
	state.kmsKeyID = keyID

	if keyID != "" {
		state.bootReceipt, err = b.ssm.MayGet(ctx,
			stateOriginReceiptParam(keyID, hex.EncodeToString(b.pcr0)))
		if err != nil {
			return nil, fmt.Errorf("failed to get state-origin receipt SSM param: %w", err)
		}
		state.migrationReceipt, err = b.ssm.MayGet(ctx, migrationStateOriginReceiptParam(keyID))
		if err != nil {
			return nil, fmt.Errorf("failed to get migration receipt SSM param: %w", err)
		}
		if err := b.loadSnapshotArtifacts(ctx, state, keyID); err != nil {
			return nil, err
		}
	}

	switch {
	case keyID == "":
		return &genesisBoot{}, nil
	case state.bootReceipt != "":
		return &resumeBoot{}, nil
	default:
		return &migrationBoot{}, nil
	}
}

func (b *genesisBoot) verify(state *bootState) error {
	if state.predecessorPCR0 != "" {
		return fmt.Errorf("genesis state has predecessor artifacts")
	}
	return nil
}

func (b *resumeBoot) verify(state *bootState) error {
	if state.kmsKeyID == "" || state.bootReceipt == "" {
		return fmt.Errorf("resume state missing committed key or own receipt")
	}
	return nil
}

func (b *migrationBoot) verify(state *bootState) error {
	if state.migrationReceipt == "" || state.predecessorPCR0 == "" {
		return fmt.Errorf(
			"invalid state: hasReceipt = false, hasMigrationReceipt = %t, hasMigrationArtifacts = %t",
			state.migrationReceipt != "", state.predecessorPCR0 != "",
		)
	}
	return nil
}

func (b *Boot) finalise(ctx context.Context, planned *plannedBoot) (bootResult, error) {
	if _, ok := planned.mode.(*genesisBoot); ok {
		lease, err := b.awaitGenesisLease(ctx)
		if err != nil {
			return bootResult{}, err
		}
		if lease != nil {
			defer func() { _ = lease.Release(context.WithoutCancel(ctx)) }()
		}
		// The wait may have ended with a peer's key committed, so decide once
		// more from what is true now rather than from what we planned before it.
		planned, err = b.plan(ctx)
		if err != nil {
			return bootResult{}, fmt.Errorf("failed to replan boot after genesis wait: %w", err)
		}
		if genesis, stillGenesis := planned.mode.(*genesisBoot); stillGenesis {
			genesis.lease = lease
		}
	}

	state := &planned.state
	if err := verifyPredecessorCommitment(b.nsm, state); err != nil {
		return bootResult{}, fmt.Errorf("failed to verify predecessor commitment: %w", err)
	}

	kms, err := FetchOrCreatePrimaryKMS(
		ctx, b.nsm, b.kmsAPI, b.sts,
		state.kmsKeyID, state.predecessorPCR0, state.predecessorAttestation,
	)
	if err != nil {
		return bootResult{}, fmt.Errorf("failed to fetch/create primary KMS key: %w", err)
	}

	snapshot, err := planned.mode.buildSnapshot(ctx, state, kms, b.ssm)
	if err != nil {
		return bootResult{}, err
	}
	snapshotRoot, err := stateRoot(snapshot)
	if err != nil {
		return bootResult{}, fmt.Errorf("failed to build state root: %v", err)
	}
	if err := planned.mode.verifySnapshot(state, b.nsm, snapshotRoot); err != nil {
		return bootResult{}, err
	}

	if kms.KeyID() != snapshot.kmsKeyID {
		return bootResult{}, fmt.Errorf(
			"state KMS key ID %q does not match active KMS key ID %q",
			snapshot.kmsKeyID, kms.KeyID(),
		)
	}
	dekPlaintext, err := kms.Decrypt(ctx, snapshot.storageDEK)
	if err != nil {
		return bootResult{}, fmt.Errorf("failed to decrypt DEK: %w", err)
	}
	// Config order, not map order: a secret's slice position picks its PCR
	// register.
	secrets := make([]StaticSecret, 0, len(state.metadata))
	for _, meta := range state.metadata {
		ciphertext, ok := snapshot.staticSecrets[meta]
		if !ok {
			return bootResult{}, fmt.Errorf("snapshot missing static secret %s", meta.Name)
		}
		plaintext, err := kms.Decrypt(ctx, ciphertext)
		if err != nil {
			return bootResult{}, fmt.Errorf(
				"failed to decrypt static secret %s: %w", meta.Name, err,
			)
		}
		secrets = append(secrets, StaticSecret{
			StaticSecretMetadata: meta,
			Plaintext:            hex.EncodeToString(plaintext),
		})
	}

	if err := planned.mode.commitSnapshot(ctx, state, b.nsm, b.ssm, kms, snapshotRoot); err != nil {
		return bootResult{}, err
	}
	return bootResult{
		kms:                       kms,
		dek:                       &dek{key: dekPlaintext},
		secrets:                   secrets,
		migrationIntentBucketName: snapshot.migrationIntentBucketName,
	}, nil
}

// loadSnapshotArtifacts fills in the ciphertexts a non-genesis boot inherits.
func (b *Boot) loadSnapshotArtifacts(ctx context.Context, state *bootState, keyID string) error {
	secrets := make(map[StaticSecretMetadata]string, len(state.metadata))
	for _, secret := range state.metadata {
		ciphertext, err := b.ssm.MustGet(ctx, secretCiphertextParam(secret.Name, keyID))
		if err != nil {
			return fmt.Errorf("required static secret SSM param missing: %w", err)
		}
		secrets[secret] = ciphertext
	}
	dekCiphertext, err := b.ssm.MustGet(ctx, storageDEKCiphertextParam(keyID))
	if err != nil {
		return fmt.Errorf("required DEK SSM param missing: %w", err)
	}
	state.snapshot.kmsKeyID = keyID
	state.snapshot.staticSecrets = secrets
	state.snapshot.storageDEK = dekCiphertext
	return nil
}

func (b *Boot) loadPredecessor(ctx context.Context) (pcr0, attestation string, err error) {
	pcr0, err = b.ssm.MayGet(ctx, migrationPreviousPCR0Param())
	if err != nil {
		return "", "", fmt.Errorf("failed to get predecessor PCR0 SSM param: %w", err)
	}
	attestation, err = b.ssm.MayGet(ctx, migrationPreviousPCR0AttestationParam())
	if err != nil {
		return "", "", fmt.Errorf("failed to get predecessor attestation SSM param: %w", err)
	}
	if (pcr0 != "") != (attestation != "") {
		return "", "", fmt.Errorf(
			"inconsistent migration predecessor artifacts (pcr0 present=%v, attestation present=%v)",
			pcr0 != "", attestation != "",
		)
	}
	return pcr0, attestation, nil
}

func (b *Boot) committedKeyID(ctx context.Context) (string, error) {
	keyID, err := b.ssm.MayGet(ctx, kmsKeyIDParam())
	if err != nil {
		return "", fmt.Errorf("failed to get KMS key ID SSM param: %w", err)
	}
	return keyID, nil
}

func (b *Boot) awaitGenesisLease(ctx context.Context) (*Lease, error) {
	bucket, err := b.ssm.MustGet(ctx, storageBucketParam())
	if err != nil {
		return nil, fmt.Errorf("failed to read storage bucket name for genesis lease: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, genesisLeaseWait)
	defer cancel()

	for {
		keyID, err := b.committedKeyID(waitCtx)
		if err != nil {
			return nil, err
		}
		if keyID != "" {
			slog.Info("genesis completed by a peer, resuming", "key_id", prefix16(keyID))
			return nil, nil
		}

		lease, err := TryAcquireLease(waitCtx, b.s3, bucket, genesisLeaseName, leaseTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to acquire genesis lease: %w", err)
		}
		if lease != nil {
			keyID, err := b.committedKeyID(waitCtx)
			if err != nil {
				_ = lease.Release(context.WithoutCancel(ctx))
				return nil, err
			}
			if keyID != "" {
				_ = lease.Release(context.WithoutCancel(ctx))
				slog.Info("genesis completed by a peer while we queued, resuming",
					"key_id", prefix16(keyID))
				return nil, nil
			}
			return lease, nil
		}

		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf(
				"genesis did not complete: lock s3://%s/%s held for the whole wait: %w",
				bucket, leaseObjectKey(genesisLeaseName), waitCtx.Err(),
			)
		case <-time.After(leasePollInterval):
		}
	}
}

// buildSnapshot mints and persists the fleet's ciphertexts. It deliberately
// returns only the snapshot — the generated plaintexts are dropped on the
// floor, and genesis opens the snapshot through KMS like every other boot.
func (b *genesisBoot) buildSnapshot(
	ctx context.Context, state *bootState, kms PrimaryKMS, ssm SSM,
) (bootSnapshot, error) {
	dekData, err := kms.GenerateDataKey(ctx)
	if err != nil {
		return bootSnapshot{}, fmt.Errorf("generate DEK: %w", err)
	}
	dekCiphertext := base64.StdEncoding.EncodeToString(dekData.Ciphertext)
	if err := ssm.Set(ctx, storageDEKCiphertextParam(kms.KeyID()), dekCiphertext); err != nil {
		return bootSnapshot{}, fmt.Errorf("failed to store DEK: %w", err)
	}

	persistedSecrets := make(map[StaticSecretMetadata]string, len(state.metadata))
	for _, secret := range state.metadata {
		data, err := kms.GenerateDataKey(ctx)
		if err != nil {
			return bootSnapshot{}, fmt.Errorf(
				"failed to generate static secret %s: %w", secret.Name, err,
			)
		}
		ciphertext := base64.StdEncoding.EncodeToString(data.Ciphertext)
		param := secretCiphertextParam(secret.Name, kms.KeyID())
		if err := ssm.Set(ctx, param, ciphertext); err != nil {
			return bootSnapshot{}, fmt.Errorf(
				"failed to store static secret %s: %w", secret.Name, err,
			)
		}
		persistedSecrets[secret] = ciphertext
	}

	return bootSnapshot{
		kmsKeyID:                  kms.KeyID(),
		staticSecrets:             persistedSecrets,
		storageDEK:                dekCiphertext,
		migrationIntentBucketName: state.snapshot.migrationIntentBucketName,
	}, nil
}

func (b *resumeBoot) buildSnapshot(
	_ context.Context, state *bootState, _ PrimaryKMS, _ SSM,
) (bootSnapshot, error) {
	return state.snapshot, nil
}

func (b *migrationBoot) buildSnapshot(
	_ context.Context, state *bootState, _ PrimaryKMS, _ SSM,
) (bootSnapshot, error) {
	return state.snapshot, nil
}

// Genesis has nothing to verify against: it is the origin.
func (b *genesisBoot) verifySnapshot(*bootState, NSM, []byte) error { return nil }

func (b *resumeBoot) verifySnapshot(state *bootState, nsm NSM, snapshotRoot []byte) error {
	if err := verifyStateOriginReceipt(
		nsm, state.bootReceipt, purposeStateOrigin, snapshotRoot,
		map[uint]string{0: hex.EncodeToString(state.currentPCR0)},
	); err != nil {
		return fmt.Errorf("invalid state-origin receipt: %w", err)
	}
	return nil
}

func (b *migrationBoot) verifySnapshot(state *bootState, nsm NSM, snapshotRoot []byte) error {
	expectedPCRs := map[uint]string{0: state.predecessorPCR0}
	// PCR31 commits the predecessor to this successor. A rollback to the same
	// PCR0 never extended it, so there is nothing to check.
	if !strings.EqualFold(state.predecessorPCR0, hex.EncodeToString(state.currentPCR0)) {
		expectedPCRs[migrationPCRIndex] = hex.EncodeToString(pcrExtendFromZero(state.currentPCR0))
	}
	if err := verifyStateOriginReceipt(
		nsm, state.migrationReceipt, purposeMigrationTransition, snapshotRoot, expectedPCRs,
	); err != nil {
		return fmt.Errorf("invalid state-origin receipt: %w", err)
	}
	return nil
}

// commitSnapshot publishes the state-origin receipt this boot is entitled to
// write, and for genesis performs the commit that makes the fleet's key official.
func (b *genesisBoot) commitSnapshot(
	ctx context.Context, state *bootState, nsm NSM, ssm SSM, kms PrimaryKMS, snapshotRoot []byte,
) error {
	if err := writeOriginReceipt(ctx, nsm, ssm, kms, snapshotRoot, state.currentPCR0); err != nil {
		return err
	}
	// SSM has no compare-and-swap, so verify we still hold the lease immediately
	// before committing. Otherwise, a descheduled holder could resume and clobber
	// the takeover, orphaning its DEK.
	if b.lease != nil {
		if err := b.lease.Verify(ctx); err != nil {
			return fmt.Errorf("refusing to commit genesis: %w", err)
		}
	}
	if err := ssm.Set(ctx, kmsKeyIDParam(), kms.KeyID()); err != nil {
		return fmt.Errorf("failed to commit genesis KMS key ID: %w", err)
	}
	return nil
}

// A resumed boot establishes nothing new; its receipt already exists.
func (b *resumeBoot) commitSnapshot(context.Context, *bootState, NSM, SSM, PrimaryKMS, []byte) error {
	return nil
}

func (b *migrationBoot) commitSnapshot(
	ctx context.Context, state *bootState, nsm NSM, ssm SSM, kms PrimaryKMS, snapshotRoot []byte,
) error {
	return writeOriginReceipt(ctx, nsm, ssm, kms, snapshotRoot, state.currentPCR0)
}

func writeOriginReceipt(
	ctx context.Context, nsm NSM, ssm SSM, kms PrimaryKMS, snapshotRoot, currentPCR0 []byte,
) error {
	if err := writeStateReceipt(
		ctx, nsm, ssm, snapshotRoot, purposeStateOrigin,
		stateOriginReceiptParam(kms.KeyID(), hex.EncodeToString(currentPCR0)),
	); err != nil {
		return fmt.Errorf("failed to write state-origin receipt: %w", err)
	}
	slog.Info("wrote state-origin receipt", "key_id", prefix16(kms.KeyID()))
	return nil
}

func verifyPredecessorCommitment(nsm NSM, state *bootState) error {
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

// WriteTransitionReceipt is called by the predecessor during a handoff; PCR31
// must already commit to the successor PCR0.
func WriteTransitionReceipt(
	ctx context.Context,
	nsm NSM,
	ssm SSM,
	snapshot bootSnapshot,
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

// stateRoot returns the canonical state_root over one immutable snapshot. It
// performs no external reads.
func stateRoot(snapshot bootSnapshot) ([]byte, error) {
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

	// The root must be deterministic; map order is not.
	metas := slices.SortedFunc(maps.Keys(snapshot.staticSecrets),
		func(a, b StaticSecretMetadata) int { return strings.Compare(a.Name, b.Name) })

	for _, metadata := range metas {
		param := secretCiphertextParam(metadata.Name, snapshot.kmsKeyID)
		h, err := sha256OfB64(snapshot.staticSecrets[metadata])
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
