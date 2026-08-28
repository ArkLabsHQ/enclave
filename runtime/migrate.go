package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"
)

// migrationPCRIndex stores the successor-PCR0 handoff commitment.
const migrationPCRIndex = 31

type MigrationRequest struct {
	Action     string `json:"action"`
	TargetPCR0 string `json:"target_pcr0,omitempty"`
}

type CompleteMigrationResult struct {
	PCR0     string   `json:"pcr0"`
	Exported []string `json:"exported"`
}

type PreviousPCR0Info struct {
	PCR0        string
	Attestation string
}

type MigrationStatus struct {
	State            string     `json:"state"`
	SourcePCR0       string     `json:"source_pcr0,omitempty"`
	TargetPCR0       string     `json:"target_pcr0,omitempty"`
	Sequence         uint64     `json:"sequence,omitempty"`
	Action           string     `json:"action,omitempty"`
	PublishedAt      *time.Time `json:"published_at,omitempty"`
	EligibleAt       *time.Time `json:"eligible_at,omitempty"`
	RemainingSeconds int        `json:"remaining_seconds"`
}

const (
	migrationStateNone        = "none"
	migrationStateCoolingDown = "cooling_down"
	migrationStateEligible    = "eligible"
	migrationStateAborted     = "aborted"
)

type Migrator interface {
	HandleMigrationRequest(
		ctx context.Context,
		action, targetPCR0 string,
	) (*MigrationStatus, error)
	CompleteMigration(ctx context.Context) (*CompleteMigrationResult, error)
	PreviousPCR0Info(ctx context.Context) (*PreviousPCR0Info, error)
	MigrationStatus(ctx context.Context) (*MigrationStatus, error)
}

type migrator struct {
	mu            sync.Mutex
	nsm           NSM
	kms           PrimaryKMS
	ssm           SSM
	dek           DEK
	staticSecrets []StaticSecret
	intent        *migrationIntentLog
}

func NewMigrator(
	nsm NSM,
	kms PrimaryKMS,
	ssm SSM,
	s3 S3API,
	dek DEK,
	secrets []StaticSecret,
	migrationIntentBucketName string,
) (Migrator, error) {
	intent, err := newMigrationIntentLog(s3, nsm, migrationIntentBucketName)
	if err != nil {
		return nil, err
	}
	return &migrator{
		nsm:           nsm,
		kms:           kms,
		ssm:           ssm,
		dek:           dek,
		staticSecrets: secrets,
		intent:        intent,
	}, nil
}

func (m *migrator) PreviousPCR0Info(ctx context.Context) (*PreviousPCR0Info, error) {
	pcr0, err := m.ssm.MayGet(ctx, migrationPreviousPCR0Param())
	if err != nil {
		return nil, err
	}

	if pcr0 == "" {
		pcr0 = "genesis"
	}

	attest, err := m.ssm.MayGet(ctx, migrationPreviousPCR0AttestationParam())
	if err != nil {
		return nil, err
	}
	return &PreviousPCR0Info{PCR0: pcr0, Attestation: attest}, nil
}

func (m *migrator) HandleMigrationRequest(
	ctx context.Context,
	action, targetPCR0 string,
) (*MigrationStatus, error) {
	cooldown, err := getMigrationCooldown()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sourcePCR0, err := m.sourcePCR0()
	if err != nil {
		return nil, err
	}

	var intentHead *migrationIntent
	switch action {
	case migrationIntentRequested:
		intentHead, err = m.intent.Request(ctx, sourcePCR0, targetPCR0)
	case migrationIntentAborted:
		intentHead, err = m.intent.Abort(ctx, sourcePCR0)
	default:
		return nil, fmt.Errorf("unknown migration action %q", action)
	}
	if err != nil {
		return nil, err
	}
	return migrationStatusAt(intentHead, cooldown, time.Now()), nil
}

func (m *migrator) MigrationStatus(ctx context.Context) (*MigrationStatus, error) {
	cooldown, err := getMigrationCooldown()
	if err != nil {
		return nil, err
	}
	sourcePCR0, err := m.sourcePCR0()
	if err != nil {
		return nil, err
	}
	head, err := m.intent.Head(ctx, sourcePCR0)
	if err != nil {
		return nil, err
	}
	status := migrationStatusAt(head, cooldown, time.Now())
	if head == nil {
		status.SourcePCR0 = sourcePCR0
	}
	return status, nil
}

func (m *migrator) sourcePCR0() (string, error) {
	pcr0, err := m.nsm.PCR0()
	if err != nil {
		return "", fmt.Errorf("read source PCR0: %w", err)
	}
	if len(pcr0) != 48 {
		return "", fmt.Errorf("source PCR0 must be 48 bytes, got %d", len(pcr0))
	}

	return hex.EncodeToString(pcr0), nil
}

func migrationStatusAt(
	head *migrationIntent,
	cooldown time.Duration,
	now time.Time,
) *MigrationStatus {
	if head == nil {
		return &MigrationStatus{State: migrationStateNone}
	}
	publishedAt := head.PublishedAt
	status := &MigrationStatus{
		SourcePCR0:  head.SourcePCR0,
		TargetPCR0:  head.TargetPCR0,
		Sequence:    head.Sequence,
		Action:      head.Action,
		PublishedAt: &publishedAt,
	}
	if head.Action == migrationIntentAborted {
		status.State = migrationStateAborted
		return status
	}

	if cooldown == 0 {
		status.State = migrationStateEligible
		status.EligibleAt = &head.PublishedAt
		return status
	}

	eligibleAt := head.PublishedAt.Add(cooldown)
	status.EligibleAt = &eligibleAt
	remaining := eligibleAt.Sub(now)
	if remaining <= 0 {
		status.State = migrationStateEligible
		return status
	}
	status.State = migrationStateCoolingDown
	status.RemainingSeconds = int(math.Ceil(remaining.Seconds()))
	return status
}

// CompleteMigration exports state under a PCR0-locked migration key, then flips KMSKeyID.
func (m *migrator) CompleteMigration(
	ctx context.Context,
) (*CompleteMigrationResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	status, err := m.MigrationStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve migration intent: %w", err)
	}
	switch status.State {
	case migrationStateNone:
		return nil, errMigrationIntentAbsent
	case migrationStateAborted:
		return nil, errMigrationIntentAborted
	}
	if status.State == migrationStateCoolingDown {
		return nil, fmt.Errorf(
			"%w: %d seconds remaining",
			errMigrationCooldownActive,
			status.RemainingSeconds,
		)
	}
	if status.State != migrationStateEligible {
		return nil, fmt.Errorf("migration intent has unexpected state %q", status.State)
	}

	targetPCR0Bytes, err := hex.DecodeString(status.TargetPCR0)
	if err != nil {
		return nil, fmt.Errorf("migration intent has invalid target PCR0: %w", err)
	}

	if err := m.nsm.CommitPCR(migrationPCRIndex, targetPCR0Bytes); err != nil {
		return nil, fmt.Errorf("failed to commit new PCR0 to PCR31: %w", err)
	}

	migrationKMS, err := m.kms.CreateMigrationKMS(ctx, status.TargetPCR0)
	if err != nil {
		return nil, fmt.Errorf("failed to create migration key: %w", err)
	}

	pcr0, err := m.nsm.PCR0()
	if err != nil {
		return nil, fmt.Errorf("could not read own PCR0 from NSM")
	}
	ownPCR0 := hex.EncodeToString(pcr0)

	slog.Info(
		"created migration KMS key",
		"key_id", migrationKMS.KeyID(),
		"own_pcr0", prefix16(ownPCR0),
		"new_pcr0", prefix16(status.TargetPCR0),
	)

	exportedNames := make([]string, 0, len(m.staticSecrets))
	transitionSecrets := make(map[StaticSecretMetadata]string, len(m.staticSecrets))
	for _, secret := range m.staticSecrets {
		secretBytes, err := hex.DecodeString(secret.Plaintext)
		if err != nil {
			return nil, fmt.Errorf("failed to decode secret %s hex: %w", secret.Name, err)
		}

		ciphertextB64, err := migrationKMS.Encrypt(ctx, secretBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to re-encrypt secret %s: %w", secret.Name, err)
		}

		plaintext, err := migrationKMS.Decrypt(ctx, ciphertextB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt re-encrypted secret %s: %w", secret.Name, err)
		}

		if !bytes.Equal(plaintext, secretBytes) {
			return nil, fmt.Errorf("roundtrip decrypt mismatch %s", secret.Name)
		}

		ciphertextParam := secretCiphertextParam(secret.Name, migrationKMS.KeyID())
		if err := m.ssm.Set(ctx, ciphertextParam, ciphertextB64); err != nil {
			return nil, fmt.Errorf("failed to store re-encrypted secret %s: %w", secret.Name, err)
		}
		transitionSecrets[secret.StaticSecretMetadata] = ciphertextB64
		exportedNames = append(exportedNames, secret.Name)
	}

	dekCiphertext, err := m.dek.ExportKey(ctx, migrationKMS, m.ssm)
	if err != nil {
		return nil, fmt.Errorf("DEK export failed: %w", err)
	}

	attestDoc, _, err := m.nsm.BuildAttestationDocument()
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation document: %w", err)
	}

	if err := m.ssm.Set(
		ctx,
		migrationPreviousPCR0AttestationParam(),
		base64.StdEncoding.EncodeToString(attestDoc),
		WithAdvancedTier(),
	); err != nil {
		return nil, fmt.Errorf(
			"failed to set SSM param %s: %w", migrationPreviousPCR0AttestationParam(), err,
		)
	}

	if err := m.ssm.Set(ctx, migrationPreviousPCR0Param(), ownPCR0); err != nil {
		return nil, fmt.Errorf(
			"failed to set SSM param %s: %w", migrationPreviousPCR0Param(), err,
		)
	}

	// Write handoff receipt before flipping KMSKeyID.
	if err := WriteTransitionReceipt(
		ctx,
		m.nsm,
		m.ssm,
		bootSnapshot{
			kmsKeyID:                  migrationKMS.KeyID(),
			staticSecrets:             transitionSecrets,
			storageDEK:                dekCiphertext,
			migrationIntentBucketName: m.intent.bucket,
		},
	); err != nil {
		return nil, fmt.Errorf(
			"failed to write migration-transition receipt: %w", err,
		)
	}

	// Atomic commit: from here, all boots use the migration key.
	if err := m.ssm.Set(ctx, kmsKeyIDParam(), migrationKMS.KeyID()); err != nil {
		return nil, fmt.Errorf(
			"failed to update current KMS key ID: %w", err,
		)
	}

	slog.Info("KMSKeyID updated to migration key", "key_id", migrationKMS.KeyID())

	return &CompleteMigrationResult{
		PCR0:     ownPCR0,
		Exported: exportedNames,
	}, nil
}

func (r MigrationRequest) Validate() error {
	switch r.Action {
	case migrationIntentRequested:
		if _, _, err := normalizePCR0(r.TargetPCR0); err != nil {
			return fmt.Errorf("target_pcr0 %w", err)
		}
	case migrationIntentAborted:
		return nil
	default:
		return fmt.Errorf("unknown migration action %q", r.Action)
	}
	return nil
}
