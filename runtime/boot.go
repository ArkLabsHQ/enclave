package runtime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	stscmd "github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	genesisPreviousPCR0 = "genesis"

	genesisLeaseName = "genesis"

	// genesisLeaseWait bounds how long we queue behind a peer's genesis.
	genesisLeaseWait = 10 * time.Minute
)

type bootState struct {
	kms            PrimaryKMS
	dek            DEK
	secrets        Secrets
	tlsKey         crypto.Signer
	masterSeed     []byte
	acmeAccountKey crypto.Signer

	migrationIntentBucketName string
	snapshot                  Snapshot // as published
}

type bootConfig struct {
	cfg             *Config
	currentPCR0     []byte
	secretsMetadata SecretsMetadata
	snapshotBucket  string
}

type bootMode interface {
	buildSnapshot(ctx context.Context, b *Boot, config *bootConfig) (Snapshot, error)

	verifySnapshot(
		ctx context.Context,
		config *bootConfig, nsm NSM, snapshot Snapshot, snapshotRoot []byte,
	) error

	commitSnapshot(ctx context.Context, b *Boot, snapshot Snapshot) (Snapshot, error)
}

type plannedBoot struct {
	config bootConfig
	mode   bootMode
}

type Boot struct {
	cfg    *Config
	nsm    NSM
	kmsAPI KMSAPI
	sts    STSAPI
	ssm    SSM
	s3     S3API
	pcr0   []byte
}

func NewBoot(
	cfg *Config, nsm NSM, kmsAPI KMSAPI, sts STSAPI, ssm SSM, s3api S3API,
) (*Boot, error) {
	pcr0, err := nsm.PCR0()
	if err != nil {
		return nil, fmt.Errorf("failed to read current PCR0: %w", err)
	}
	if len(pcr0) != 48 {
		return nil, fmt.Errorf("current PCR0 must be exactly 48 bytes, got %d", len(pcr0))
	}
	return &Boot{
		cfg: cfg, nsm: nsm, kmsAPI: kmsAPI, sts: sts, ssm: ssm, s3: s3api, pcr0: pcr0,
	}, nil
}

// Boot establishes state for this enclave.
func (b *Boot) Boot(ctx context.Context) (bootState, error) {
	planned, err := b.plan(ctx)
	if err != nil {
		return bootState{}, err
	}

	if _, ok := planned.mode.(*genesisBoot); ok {
		lease, err := b.awaitGenesisLease(ctx, &planned.config)
		if err != nil {
			return bootState{}, err
		}
		if lease != nil {
			defer func() { _ = lease.Release(context.WithoutCancel(ctx)) }()
		}

		planned, err = b.plan(ctx)
		if err != nil {
			return bootState{}, fmt.Errorf("failed to replan boot after genesis wait: %w", err)
		}
		if genesis, stillGenesis := planned.mode.(*genesisBoot); stillGenesis {
			genesis.lease = lease
		}
	}

	config := &planned.config

	// Reject invalid inherited secrets before creating keys or writing state.
	inheritedSecrets, err := resolveInheritedSecrets(
		ctx, b.cfg, b.ssm, config.secretsMetadata.Inherited, time.Now(),
	)
	if err != nil {
		return bootState{}, err
	}

	result, err := b.establish(ctx, planned)
	if err != nil {
		return bootState{}, err
	}
	result.secrets.Inherited = inheritedSecrets

	return result, nil
}

func (b *Boot) plan(ctx context.Context) (*plannedBoot, error) {
	secretsMetadata, err := LoadSecretsMetadata(*b.cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load secrets metadata: %w", err)
	}
	if err := secretsMetadata.Validate(b.cfg.OverrideAllowList); err != nil {
		return nil, fmt.Errorf("invalid secrets metadata: %w", err)
	}
	bucket, err := b.migrationIntentBucket(ctx)
	if err != nil {
		return nil, err
	}

	config := bootConfig{
		cfg:             b.cfg,
		currentPCR0:     append([]byte(nil), b.pcr0...),
		secretsMetadata: secretsMetadata,
		snapshotBucket:  bucket,
	}

	mode, err := b.determineMode(ctx, &config)
	if err != nil {
		return nil, err
	}
	return &plannedBoot{config: config, mode: mode}, nil
}

// Without a snapshot, the measured PreviousPCR0 selects genesis or adoption.
// Deleting stored state cannot turn a successor into a genesis.
func (b *Boot) determineMode(
	ctx context.Context, config *bootConfig,
) (bootMode, error) {
	ownPCR0 := hex.EncodeToString(b.pcr0)
	snapshot, err := readSnapshot(ctx, b.cfg, b.s3, b.nsm, config.snapshotBucket, ownPCR0)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %w", err)
	}
	if snapshot != nil {
		return &resumeBoot{snapshot: *snapshot}, nil
	}

	if b.cfg.genesisImage() {
		return &genesisBoot{}, nil
	}

	keyID, err := b.ssm.MayGet(ctx, b.cfg.kmsKeyIDParam(ownPCR0))
	if err != nil {
		return nil, fmt.Errorf("failed to get KMS key ID SSM param: %w", err)
	}
	if keyID == "" {
		return nil, fmt.Errorf(
			"no snapshot for this PCR0 and %s holds no handoff",
			b.cfg.kmsKeyIDParam(ownPCR0),
		)
	}
	intent, err := newMigrationIntentLog(b.cfg, b.s3, b.nsm, config.snapshotBucket)
	if err != nil {
		return nil, fmt.Errorf("failed to open migration intent log: %w", err)
	}
	return &migrationBoot{intent: intent, kmsKeyID: keyID}, nil
}

// establish verifies the snapshot before decrypting any state.
func (b *Boot) establish(ctx context.Context, planned *plannedBoot) (bootState, error) {
	config := &planned.config

	snapshot, err := planned.mode.buildSnapshot(ctx, b, config)
	if err != nil {
		return bootState{}, err
	}
	snapshotRoot, err := snapshot.root(b.cfg)
	if err != nil {
		return bootState{}, fmt.Errorf("failed to build snapshot root: %v", err)
	}
	if err := planned.mode.verifySnapshot(
		ctx, config, b.nsm, snapshot, snapshotRoot,
	); err != nil {
		return bootState{}, err
	}

	kms, err := b.primaryKMS(ctx, snapshot.kmsKeyID)
	if err != nil {
		return bootState{}, err
	}
	masterSeed, err := kms.Decrypt(ctx, snapshot.masterSeedCiphertext)
	if err != nil {
		return bootState{}, fmt.Errorf("failed to decrypt master seed: %w", err)
	}
	storageKey, err := deriveSecret(masterSeed, storageDEKDerivationName)
	if err != nil {
		return bootState{}, fmt.Errorf("derive storage DEK: %w", err)
	}
	storageKeyBytes, err := hex.DecodeString(storageKey)
	if err != nil {
		return bootState{}, fmt.Errorf("decode storage DEK hex: %w", err)
	}
	accountKey, err := deriveACMEAccountKey(masterSeed)
	if err != nil {
		return bootState{}, fmt.Errorf("derive ACME account key: %w", err)
	}
	tlsKeyPKCS8, err := kms.Decrypt(ctx, snapshot.tlsKeyCiphertext)
	if err != nil {
		return bootState{}, fmt.Errorf("failed to decrypt TLS key: %w", err)
	}
	tlsKeyAny, err := x509.ParsePKCS8PrivateKey(tlsKeyPKCS8)
	if err != nil {
		return bootState{}, fmt.Errorf("failed to parse TLS key: %w", err)
	}
	tlsKey, ok := tlsKeyAny.(*ecdsa.PrivateKey)
	if !ok || tlsKey.Curve != elliptic.P256() {
		return bootState{}, fmt.Errorf("TLS key must be an ECDSA P-256 private key")
	}

	staticSecrets := make([]StaticSecret, 0, len(config.secretsMetadata.Static))
	for _, meta := range config.secretsMetadata.Static {
		plaintext, err := deriveSecret(masterSeed, meta.Name)
		if err != nil {
			return bootState{}, fmt.Errorf("derive static secret %s: %w", meta.Name, err)
		}
		staticSecrets = append(staticSecrets, StaticSecret{
			StaticSecretMetadata: meta,
			Plaintext:            plaintext,
		})
	}

	published, err := planned.mode.commitSnapshot(ctx, b, snapshot)
	if err != nil {
		return bootState{}, err
	}
	return bootState{
		kms:                       kms,
		dek:                       &dek{key: storageKeyBytes},
		secrets:                   Secrets{Static: staticSecrets},
		tlsKey:                    tlsKey,
		masterSeed:                masterSeed,
		acmeAccountKey:            accountKey,
		migrationIntentBucketName: snapshot.migrationIntentBucketName,
		snapshot:                  published,
	}, nil
}

func (b *Boot) primaryKMS(ctx context.Context, keyID string) (PrimaryKMS, error) {
	kms, err := FetchOrCreatePrimaryKMS(ctx, b.cfg, b.nsm, b.kmsAPI, b.sts, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch/create primary KMS key: %w", err)
	}
	return kms, nil
}

func (b *Boot) loadPredecessor(ctx context.Context) (pcr0, keyID string, err error) {
	ownPCR0 := hex.EncodeToString(b.pcr0)
	pcr0, err = b.ssm.MayGet(ctx, b.cfg.migrationPreviousPCR0Param(ownPCR0))
	if err != nil {
		return "", "", fmt.Errorf("failed to get predecessor PCR0 SSM param: %w", err)
	}
	keyID, err = b.ssm.MayGet(ctx, b.cfg.migrationPreviousKMSKeyIDParam(ownPCR0))
	if err != nil {
		return "", "", fmt.Errorf("failed to get predecessor KMS key ID: %w", err)
	}
	if (pcr0 == "") != (keyID == "") {
		return "", "", fmt.Errorf(
			"inconsistent migration predecessor artifacts (pcr0 present=%v, key present=%v)",
			pcr0 != "", keyID != "",
		)
	}
	return pcr0, keyID, nil
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
	return migrationIntentBucketName(b.cfg, accountID), nil
}

// awaitGenesisLease queues behind a replica of this image already running
// genesis, and returns no lease once that replica has published.
func (b *Boot) awaitGenesisLease(ctx context.Context, config *bootConfig) (*Lease, error) {
	leaseBucket, err := b.ssm.MustGet(ctx, b.cfg.leaseBucketParam())
	if err != nil {
		return nil, fmt.Errorf("failed to read lease bucket name for genesis lease: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, genesisLeaseWait)
	defer cancel()

	ownPCR0 := hex.EncodeToString(config.currentPCR0)
	published := func() (bool, error) {
		snapshot, err := readSnapshot(waitCtx, b.cfg, b.s3, b.nsm, config.snapshotBucket, ownPCR0)
		if err != nil {
			return false, fmt.Errorf("failed to read snapshot: %w", err)
		}
		return snapshot != nil, nil
	}

	for {
		done, err := published()
		if err != nil {
			return nil, err
		}
		if done {
			slog.Info("genesis completed by a peer, resuming")
			return nil, nil
		}

		lease, err := TryAcquireLease(
			waitCtx, b.cfg, b.s3, leaseBucket, genesisLeaseName, leaseTTL,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to acquire genesis lease: %w", err)
		}
		if lease != nil {
			done, err := published()
			if err != nil {
				_ = lease.Release(context.WithoutCancel(ctx))
				return nil, err
			}
			if done {
				_ = lease.Release(context.WithoutCancel(ctx))
				slog.Info("genesis completed by a peer while we queued, resuming")
				return nil, nil
			}
			return lease, nil
		}

		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf(
				"genesis did not complete: lock s3://%s/%s held for the whole wait: %w",
				leaseBucket, leaseObjectKey(b.cfg, genesisLeaseName), waitCtx.Err(),
			)
		case <-time.After(leasePollInterval):
		}
	}
}

// publishSnapshot accepts a concurrent publication only if its state matches;
// independently valid receipts may differ. Read-back also verifies the lock,
// which IAM preflight cannot check.
func (b *Boot) publishSnapshot(
	ctx context.Context, snapshot Snapshot,
) (*Snapshot, error) {
	origin, err := snapshot.attestOrigin(b.cfg, b.nsm)
	if err != nil {
		return nil, err
	}
	body, err := snapshot.marshalObject(b.cfg, origin)
	if err != nil {
		return nil, err
	}
	key := snapshotObjectKey(snapshot.ownerPCR0)

	writeCtx, cancel := context.WithTimeout(ctx, b.cfg.IntentWriteTimeout)
	defer cancel()
	var out *s3.PutObjectOutput
	for attempt := 0; ; attempt++ {
		out, err = b.s3.PutObject(writeCtx, &s3.PutObjectInput{
			Bucket:                    aws.String(snapshot.migrationIntentBucketName),
			Key:                       aws.String(key),
			Body:                      bytes.NewReader(body),
			ContentType:               aws.String("application/json"),
			IfNoneMatch:               aws.String("*"),
			ObjectLockMode:            s3types.ObjectLockModeCompliance,
			ObjectLockRetainUntilDate: aws.Time(time.Now().Add(b.cfg.SnapshotRetention)),
		})
		if !isConditionalConflict(err) || attempt == leaseConflictRetries {
			break
		}
		if err := backoff(writeCtx, attempt); err != nil {
			return nil, err
		}
	}
	switch {
	case isPreconditionFailed(err):
		slog.Info("snapshot already published; verifying it", "key", key)
	case err != nil:
		return nil, fmt.Errorf("%w: put %s: %w", errSnapshotStoreUnavailable, key, err)
	case out == nil || aws.ToString(out.VersionId) == "":
		return nil, fmt.Errorf(
			"%w: put %s: S3 returned no version ID", errSnapshotStoreUnavailable, key,
		)
	}

	published, err := readSnapshot(
		ctx, b.cfg, b.s3, b.nsm, snapshot.migrationIntentBucketName, snapshot.ownerPCR0,
	)
	if errors.Is(err, errSnapshotUnverifiable) {
		return nil, fmt.Errorf("%w; the bucket must apply compliance-mode Object Lock", err)
	}
	if err != nil {
		return nil, err
	}
	if published == nil {
		return nil, fmt.Errorf(
			"%w: %s is missing after the write", errSnapshotStoreUnavailable, key,
		)
	}
	if !published.sameState(snapshot) {
		return nil, fmt.Errorf(
			"%w: %s is %s's generation under key %s",
			errSnapshotConflict, key, prefix16(snapshot.ownerPCR0), published.kmsKeyID,
		)
	}
	return published, nil
}

type genesisBoot struct {
	lease *Lease
}

// Ciphertexts stay in memory until commitSnapshot publishes them together.
func (g *genesisBoot) buildSnapshot(
	ctx context.Context, b *Boot, config *bootConfig,
) (Snapshot, error) {
	kms, err := b.primaryKMS(ctx, "")
	if err != nil {
		return Snapshot{}, err
	}
	seedData, err := kms.GenerateDataKey(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("generate master seed: %w", err)
	}

	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Snapshot{}, fmt.Errorf("generate TLS key: %w", err)
	}
	tlsKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		return Snapshot{}, fmt.Errorf("marshal TLS key: %w", err)
	}
	tlsKeyCiphertext, err := kms.Encrypt(ctx, tlsKeyPKCS8)
	if err != nil {
		return Snapshot{}, fmt.Errorf("encrypt TLS key: %w", err)
	}

	return Snapshot{
		kmsKeyID:                  kms.KeyID(),
		ownerPCR0:                 hex.EncodeToString(config.currentPCR0),
		masterSeedCiphertext:      base64.StdEncoding.EncodeToString(seedData.Ciphertext),
		tlsKeyCiphertext:          tlsKeyCiphertext,
		migrationIntentBucketName: config.snapshotBucket,
	}, nil
}

// Validate genesis against the same format that later boots will read.
func (g *genesisBoot) verifySnapshot(
	_ context.Context, config *bootConfig, _ NSM, snapshot Snapshot, _ []byte,
) error {
	raw, err := snapshot.encode(config.cfg)
	if err != nil {
		return err
	}
	if _, err := decodeSnapshot(config.cfg, raw); err != nil {
		return fmt.Errorf("genesis snapshot would be refused on read: %w", err)
	}
	return nil
}

func (g *genesisBoot) commitSnapshot(
	ctx context.Context, b *Boot, snapshot Snapshot,
) (Snapshot, error) {
	if g.lease == nil {
		return Snapshot{}, fmt.Errorf("refusing to commit genesis without lease")
	}
	if err := g.lease.Verify(ctx); err != nil {
		return Snapshot{}, fmt.Errorf("refusing to commit genesis: %w", err)
	}
	published, err := b.publishSnapshot(ctx, snapshot)
	if err != nil {
		return Snapshot{}, fmt.Errorf("failed to publish genesis snapshot: %w", err)
	}
	slog.Info("published genesis snapshot", "key_id", prefix16(snapshot.kmsKeyID))
	return *published, nil
}

type resumeBoot struct {
	snapshot Snapshot // as published
}

func (r *resumeBoot) buildSnapshot(context.Context, *Boot, *bootConfig) (Snapshot, error) {
	return r.snapshot, nil
}

// A resumed boot's state was verified as it was read.
func (r *resumeBoot) verifySnapshot(
	context.Context, *bootConfig, NSM, Snapshot, []byte,
) error {
	return nil
}

func (r *resumeBoot) commitSnapshot(
	_ context.Context, _ *Boot, snapshot Snapshot,
) (Snapshot, error) {
	return snapshot, nil
}

type migrationBoot struct {
	intent   *migrationIntentLog
	kmsKeyID string // the handoff pointer
}

// SSM handoff values remain untrusted until the transition receipt verifies.
func (m *migrationBoot) buildSnapshot(
	ctx context.Context, b *Boot, config *bootConfig,
) (Snapshot, error) {
	ownPCR0 := hex.EncodeToString(config.currentPCR0)
	predecessorPCR0, predecessorKMSKeyID, err := b.loadPredecessor(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if predecessorPCR0 == "" {
		return Snapshot{}, fmt.Errorf(
			"no snapshot for this PCR0 and no predecessor to migrate from",
		)
	}
	if strings.EqualFold(predecessorPCR0, ownPCR0) {
		return Snapshot{}, fmt.Errorf("an enclave cannot be its own predecessor")
	}
	transitionReceipt, err := b.ssm.MayGet(
		ctx, b.cfg.migrationStateOriginReceiptParam(m.kmsKeyID, ownPCR0),
	)
	if err != nil {
		return Snapshot{}, fmt.Errorf("failed to get migration receipt SSM param: %w", err)
	}
	if transitionReceipt == "" {
		return Snapshot{}, fmt.Errorf(
			"predecessor artifacts present but no migration transition receipt",
		)
	}
	masterSeedCiphertext, err := b.ssm.MustGet(ctx, b.cfg.masterSeedCiphertextParam(m.kmsKeyID))
	if err != nil {
		return Snapshot{}, fmt.Errorf("required master seed SSM param missing: %w", err)
	}
	tlsKeyCiphertext, err := b.ssm.MustGet(ctx, b.cfg.tlsKeyCiphertextParam(m.kmsKeyID))
	if err != nil {
		return Snapshot{}, fmt.Errorf("required TLS key SSM param missing: %w", err)
	}
	return Snapshot{
		kmsKeyID:                  m.kmsKeyID,
		ownerPCR0:                 ownPCR0,
		predecessorPCR0:           predecessorPCR0,
		predecessorKMSKeyID:       predecessorKMSKeyID,
		masterSeedCiphertext:      masterSeedCiphertext,
		tlsKeyCiphertext:          tlsKeyCiphertext,
		migrationIntentBucketName: config.snapshotBucket,
		transitionReceipt:         transitionReceipt,
	}, nil
}

func (m *migrationBoot) verifySnapshot(
	ctx context.Context,
	config *bootConfig, nsm NSM, snapshot Snapshot, snapshotRoot []byte,
) error {
	if err := verifyStateReceipt(
		nsm, snapshot.transitionReceipt, purposeMigrationTransition,
		snapshotRoot, transitionPCRs(snapshot.predecessorPCR0, config.currentPCR0),
	); err != nil {
		return fmt.Errorf("invalid transition receipt: %w", err)
	}

	if m.intent == nil {
		return fmt.Errorf("migration authorization: no intent log")
	}
	head, err := m.intent.Head(ctx, snapshot.predecessorPCR0)
	if err != nil {
		return err
	}
	if head == nil {
		return fmt.Errorf(
			"%w: predecessor %s recorded no intent",
			errMigrationIntentAbsent, prefix16(snapshot.predecessorPCR0),
		)
	}
	if head.Action != migrationIntentRequested {
		return fmt.Errorf(
			"%w: intent from %s is %s",
			errMigrationIntentAborted, prefix16(snapshot.predecessorPCR0), head.Action,
		)
	}
	if !strings.EqualFold(head.TargetPCR0, hex.EncodeToString(config.currentPCR0)) {
		return fmt.Errorf(
			"%w: intent from %s targets %s, not this enclave",
			errMigrationIntentAborted, prefix16(snapshot.predecessorPCR0),
			prefix16(head.TargetPCR0),
		)
	}
	if !strings.EqualFold(config.cfg.PreviousPCR0, snapshot.predecessorPCR0) {
		return fmt.Errorf(
			"previous PCR0 SSM param does not match previous PCR0 committed in the EIF",
		)
	}
	return nil
}

// Adoption still depends on the SSM handoff until this publication succeeds.
func (m *migrationBoot) commitSnapshot(
	ctx context.Context, b *Boot, snapshot Snapshot,
) (Snapshot, error) {
	published, err := b.publishSnapshot(ctx, snapshot)
	if err != nil {
		return Snapshot{}, fmt.Errorf("failed to publish adopted snapshot: %w", err)
	}
	slog.Info("published adopted snapshot", "key_id", prefix16(snapshot.kmsKeyID),
		"predecessor_pcr0", prefix16(snapshot.predecessorPCR0))
	return *published, nil
}
