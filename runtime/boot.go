package runtime

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	stscmd "github.com/aws/aws-sdk-go-v2/service/sts"
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

	migrationIntentBucketArtifact = "migration-intent-bucket"

	// genesisLeaseWait bounds how long we queue behind a peer's genesis.
	genesisLeaseWait = 10 * time.Minute
)

// bootResult is the boot machine's terminal state
type bootResult struct {
	kms     PrimaryKMS
	dek     DEK
	secrets []StaticSecret
	tlsKey  crypto.Signer

	migrationIntentBucketName string
}

// bootSnapshot is the exact SSM-backed state covered by a
// state-origin receipt. Its values are loaded or generated once and never
// reconstructed from SSM.
type bootSnapshot struct {
	kmsKeyID                  string
	ownerPCR0                 string                          // generation the KMSKeyID path is scoped to
	staticSecrets             map[StaticSecretMetadata]string // metadata → ciphertext
	storageDEK                string
	tlsKeyCiphertext          string
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
	// verify ascertains this mode's preconditions hold over what was loaded,
	// including the lineage baked into the EIF at build time.
	verify(nsm NSM, state *bootState) error

	// buildSnapshot produces the artifacts the state_root is computed over —
	// created and persisted for genesis, already loaded for everyone else.
	buildSnapshot(
		ctx context.Context,
		state *bootState,
		kms PrimaryKMS,
		ssm SSM,
	) (bootSnapshot, error)

	// verifySnapshot proves the snapshot came from an enclave we accept.
	verifySnapshot(state *bootState, nsm NSM, snapshotRoot []byte) error

	// commitSnapshot records what this boot established, if anything.
	commitSnapshot(
		ctx context.Context,
		state *bootState,
		nsm NSM,
		ssm SSM,
		kms PrimaryKMS,
		snapshotRoot []byte,
	) error
}

type genesisBoot struct {
	lease   *Lease
	genesis *genesisLog
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

// Boot establishes state for this enclave.
func (b *Boot) Boot(ctx context.Context) (bootResult, error) {
	planned, err := b.plan(ctx)
	if err != nil {
		return bootResult{}, err
	}

	if pending, ok := planned.mode.(*genesisBoot); ok {
		lease, err := b.awaitGenesisLease(ctx, pending.genesis)
		if err != nil {
			return bootResult{}, err
		}
		if lease != nil {
			defer func() { _ = lease.Release(context.WithoutCancel(ctx)) }()
		}

		planned, err = b.plan(ctx)
		if err != nil {
			return bootResult{}, fmt.Errorf("failed to replan boot after genesis wait: %w", err)
		}
		if genesis, stillGenesis := planned.mode.(*genesisBoot); stillGenesis {
			genesis.lease = lease
		}
	}

	state := &planned.state
	kms, err := FetchOrCreatePrimaryKMS(ctx, b.nsm, b.kmsAPI, b.sts, state.kmsKeyID)
	if err != nil {
		return bootResult{}, fmt.Errorf("failed to fetch/create primary KMS key: %w", err)
	}
	return b.establish(ctx, planned, kms)
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
	migrationIntentBucketName, err := b.migrationIntentBucket(ctx)
	if err != nil {
		return nil, err
	}
	genesis, err := newGenesisLog(b.s3, b.nsm, migrationIntentBucketName)
	if err != nil {
		return nil, fmt.Errorf("failed to open deployment genesis log: %w", err)
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
			ownerPCR0:                 hex.EncodeToString(b.pcr0),
			migrationIntentBucketName: migrationIntentBucketName,
		},
	}

	mode, err := b.determineMode(ctx, &state, genesis)
	if err != nil {
		return nil, err
	}
	if err := mode.verify(b.nsm, &state); err != nil {
		return nil, err
	}
	return &plannedBoot{state: state, mode: mode}, nil
}

func (b *Boot) determineMode(
	ctx context.Context, state *bootState, genesis *genesisLog,
) (bootMode, error) {
	genesisArtifact, err := genesis.Genesis(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read deployment genesis: %w", err)
	}
	ownPCR0 := hex.EncodeToString(b.pcr0)
	keyID, err := b.ssm.MayGet(ctx, kmsKeyIDParam(ownPCR0))
	if err != nil {
		return nil, fmt.Errorf("failed to get KMS key ID SSM param: %w", err)
	}

	state.kmsKeyID = keyID

	if genesisArtifact == nil {
		return &genesisBoot{genesis: genesis}, nil
	}

	if keyID == "" {
		return nil, fmt.Errorf(
			"deployment genesis is recorded but %s holds no key",
			kmsKeyIDParam(ownPCR0),
		)
	}

	state.bootReceipt, err = b.ssm.MayGet(ctx, stateOriginReceiptParam(keyID, ownPCR0))
	if err != nil {
		return nil, fmt.Errorf("failed to get state-origin receipt SSM param: %w", err)
	}

	if err := b.loadSnapshotArtifacts(ctx, state, keyID); err != nil {
		return nil, err
	}

	if state.bootReceipt != "" {
		return &resumeBoot{}, nil
	}

	state.migrationReceipt, err = b.ssm.MayGet(ctx, migrationStateOriginReceiptParam(keyID))
	if err != nil {
		return nil, fmt.Errorf("failed to get migration receipt SSM param: %w", err)
	}
	return &migrationBoot{}, nil
}

func (b *genesisBoot) verify(nsm NSM, state *bootState) error {
	if state.kmsKeyID != "" {
		return fmt.Errorf(
			"genesis boot with a committed KMS key: the intent log is empty but %s is set",
			kmsKeyIDParam(hex.EncodeToString(state.currentPCR0)),
		)
	}
	if state.predecessorPCR0 != "" {
		return fmt.Errorf("genesis state has predecessor artifacts")
	}
	return verifyPredecessorCommitment(nsm, state)
}

func (b *resumeBoot) verify(nsm NSM, state *bootState) error {
	if state.kmsKeyID == "" {
		return fmt.Errorf("resume state missing committed key")
	}
	if state.bootReceipt == "" {
		return fmt.Errorf("resume state missing own state-origin receipt")
	}
	return verifyPredecessorCommitment(nsm, state)
}

func (b *migrationBoot) verify(nsm NSM, state *bootState) error {
	if state.predecessorPCR0 == "" {
		return fmt.Errorf(
			"no state-origin receipt for this PCR0 and no predecessor to migrate from",
		)
	}
	if state.migrationReceipt == "" {
		return fmt.Errorf("predecessor artifacts present but no migration transition receipt")
	}
	return verifyPredecessorCommitment(nsm, state)
}

// establish adopts the planned state under the fleet key: nothing decrypts
// before verifySnapshot passes.
func (b *Boot) establish(
	ctx context.Context, planned *plannedBoot, kms PrimaryKMS,
) (bootResult, error) {
	state := &planned.state

	snapshot, err := planned.mode.buildSnapshot(ctx, state, kms, b.ssm)
	if err != nil {
		return bootResult{}, err
	}

	if kms.KeyID() != snapshot.kmsKeyID {
		return bootResult{}, fmt.Errorf(
			"state KMS key ID %q does not match active KMS key ID %q",
			snapshot.kmsKeyID, kms.KeyID(),
		)
	}
	snapshotRoot, err := stateRoot(snapshot)
	if err != nil {
		return bootResult{}, fmt.Errorf("failed to build state root: %v", err)
	}
	if err := planned.mode.verifySnapshot(state, b.nsm, snapshotRoot); err != nil {
		return bootResult{}, err
	}

	dekPlaintext, err := kms.Decrypt(ctx, snapshot.storageDEK)
	if err != nil {
		return bootResult{}, fmt.Errorf("failed to decrypt DEK: %w", err)
	}
	tlsKeyPKCS8, err := kms.Decrypt(ctx, snapshot.tlsKeyCiphertext)
	if err != nil {
		return bootResult{}, fmt.Errorf("failed to decrypt TLS key: %w", err)
	}
	tlsKeyAny, err := x509.ParsePKCS8PrivateKey(tlsKeyPKCS8)
	if err != nil {
		return bootResult{}, fmt.Errorf("failed to parse TLS key: %w", err)
	}
	tlsKey, ok := tlsKeyAny.(crypto.Signer)
	if !ok {
		return bootResult{}, fmt.Errorf("TLS key of type %T cannot sign", tlsKeyAny)
	}

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
		tlsKey:                    tlsKey,
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
	tlsKeyCiphertext, err := b.ssm.MustGet(ctx, tlsKeyCiphertextParam(keyID))
	if err != nil {
		return fmt.Errorf("required TLS key SSM param missing: %w", err)
	}
	state.snapshot.kmsKeyID = keyID
	state.snapshot.staticSecrets = secrets
	state.snapshot.storageDEK = dekCiphertext
	state.snapshot.tlsKeyCiphertext = tlsKeyCiphertext
	return nil
}

func (b *Boot) loadPredecessor(ctx context.Context) (pcr0, attestation string, err error) {
	ownPCR0 := hex.EncodeToString(b.pcr0)
	pcr0, err = b.ssm.MayGet(ctx, migrationPreviousPCR0Param(ownPCR0))
	if err != nil {
		return "", "", fmt.Errorf("failed to get predecessor PCR0 SSM param: %w", err)
	}
	attestation, err = b.ssm.MayGet(ctx, migrationPreviousPCR0AttestationParam(ownPCR0))
	if err != nil {
		return "", "", fmt.Errorf("failed to get predecessor attestation SSM param: %w", err)
	}
	if (pcr0 != "") != (attestation != "") {
		return "", "", fmt.Errorf(
			"inconsistent migration predecessor artifacts (pcr0 present=%v, attestation present=%v)",
			pcr0 != "",
			attestation != "",
		)
	}
	return pcr0, attestation, nil
}

func (b *Boot) migrationIntentBucket(ctx context.Context) (string, error) {
	identity, err := b.sts.GetCallerIdentity(ctx, &stscmd.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("sts get-caller-identity: %w", err)
	}
	accountID := aws.ToString(identity.Account)
	if accountID == "" {
		return "", fmt.Errorf("sts get-caller-identity returned no account ID")
	}
	return migrationIntentBucketName(accountID), nil
}

func (b *Boot) genesisCommitted(ctx context.Context, genesis *genesisLog) (string, error) {
	artifact, err := genesis.Genesis(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to read deployment genesis: %w", err)
	}
	if artifact == nil {
		return "", nil
	}
	keyID, err := b.ssm.MayGet(ctx, kmsKeyIDParam(hex.EncodeToString(b.pcr0)))
	if err != nil {
		return "", fmt.Errorf("failed to get KMS key ID SSM param: %w", err)
	}
	return keyID, nil
}

func (b *Boot) awaitGenesisLease(
	ctx context.Context,
	genesis *genesisLog,
) (*Lease, error) {
	bucket, err := b.ssm.MustGet(ctx, leaseBucketParam())
	if err != nil {
		return nil, fmt.Errorf("failed to read lease bucket name for genesis lease: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, genesisLeaseWait)
	defer cancel()

	for {
		keyID, err := b.genesisCommitted(waitCtx, genesis)
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
			keyID, err := b.genesisCommitted(waitCtx, genesis)
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

// buildSnapshot mints and persists the enclave ciphertexts.
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
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return bootSnapshot{}, fmt.Errorf("generate TLS key: %w", err)
	}
	tlsKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		return bootSnapshot{}, fmt.Errorf("marshal TLS key: %w", err)
	}
	tlsKeyCiphertext, err := kms.Encrypt(ctx, tlsKeyPKCS8)
	if err != nil {
		return bootSnapshot{}, fmt.Errorf("encrypt TLS key: %w", err)
	}
	if err := ssm.Set(
		ctx, tlsKeyCiphertextParam(kms.KeyID()), tlsKeyCiphertext,
	); err != nil {
		return bootSnapshot{}, fmt.Errorf("store TLS key: %w", err)
	}

	return bootSnapshot{
		kmsKeyID:                  kms.KeyID(),
		ownerPCR0:                 state.snapshot.ownerPCR0,
		staticSecrets:             persistedSecrets,
		storageDEK:                dekCiphertext,
		tlsKeyCiphertext:          tlsKeyCiphertext,
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
	if err := verifyStateReceipt(
		nsm, state.bootReceipt, purposeStateOrigin, snapshotRoot,
		map[uint]string{0: hex.EncodeToString(state.currentPCR0)},
	); err != nil {
		return fmt.Errorf("invalid state-origin receipt: %w", err)
	}
	return nil
}

func (b *migrationBoot) verifySnapshot(state *bootState, nsm NSM, snapshotRoot []byte) error {
	if err := verifyStateReceipt(
		nsm, state.migrationReceipt, purposeMigrationTransition,
		snapshotRoot, predecessorExpectedPCRs(state),
	); err != nil {
		return fmt.Errorf("invalid state-origin receipt: %w", err)
	}
	return nil
}

func (b *genesisBoot) commitSnapshot(
	ctx context.Context, state *bootState, nsm NSM, ssm SSM, kms PrimaryKMS, snapshotRoot []byte,
) error {
	if b.lease == nil {
		return fmt.Errorf("refusing to commit genesis without lease")
	}

	if err := writeOriginReceipt(ctx, nsm, ssm, kms, snapshotRoot, state.currentPCR0); err != nil {
		return err
	}

	if err := b.lease.Verify(ctx); err != nil {
		return fmt.Errorf("refusing to commit genesis: %w", err)
	}

	if err := ssm.Set(
		ctx,
		kmsKeyIDParam(hex.EncodeToString(state.currentPCR0)),
		kms.KeyID(),
		WithoutOverwrite(),
	); err != nil {
		return fmt.Errorf("failed to claim genesis KMS key ID: %w", err)
	}

	if _, err := b.genesis.CommitGenesis(ctx, hex.EncodeToString(state.currentPCR0)); err != nil {
		return fmt.Errorf("failed to commit deployment genesis: %w", err)
	}

	return nil
}

// A resumed boot establishes nothing new; its receipt already exists.
func (b *resumeBoot) commitSnapshot(
	context.Context,
	*bootState,
	NSM,
	SSM,
	PrimaryKMS,
	[]byte,
) error {
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

// predecessorExpectedPCRs is the PCR set a predecessor's attestation must carry
// for this enclave: its own PCR0, and PCR31 committing to ours. PCR31 is not
// optional — dropping it for a self-referential predecessor would let an
// attestation that names nobody satisfy the handoff check.
func predecessorExpectedPCRs(state *bootState) map[uint]string {
	return map[uint]string{
		0:                 state.predecessorPCR0,
		migrationPCRIndex: hex.EncodeToString(pcrExtendFromZero(state.currentPCR0)),
	}
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
	if strings.EqualFold(state.predecessorPCR0, hex.EncodeToString(state.currentPCR0)) {
		return fmt.Errorf("an enclave cannot be its own predecessor")
	}
	if !strings.EqualFold(eifPreviousPCR0, state.predecessorPCR0) {
		return fmt.Errorf(
			"previous PCR0 SSM param does not match previous PCR0 committed in the EIF",
		)
	}
	return nsm.VerifyAttestation(
		state.predecessorAttestation, predecessorExpectedPCRs(state), nil,
	)
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
	if snapshot.ownerPCR0 == "" {
		return nil, fmt.Errorf("state_root: snapshot has no owner PCR0")
	}

	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("failed to build canonical CBOR encoder: %v", err)
	}

	arts := make([]ssmArtifactV1, 0, len(snapshot.staticSecrets)+4)
	arts = append(arts, ssmArtifactV1{
		Name: kmsKeyIDParam(snapshot.ownerPCR0), Value: snapshot.kmsKeyID,
	})
	arts = append(arts, ssmArtifactV1{
		Name: migrationIntentBucketArtifact, Value: snapshot.migrationIntentBucketName,
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

	tlsKeyParam := tlsKeyCiphertextParam(snapshot.kmsKeyID)
	tlsKeyHash, err := sha256OfB64(snapshot.tlsKeyCiphertext)
	if err != nil {
		return nil, fmt.Errorf("failed sha256 hash of TLS key %s: %w", tlsKeyParam, err)
	}
	arts = append(arts, ssmArtifactV1{Name: tlsKeyParam, ValueSHA256: tlsKeyHash})

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

// verifyStateReceipt checks receipt PCRs and user_data {purpose,state_root}.
func verifyStateReceipt(
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
