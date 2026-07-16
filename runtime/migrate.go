package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"
)

// migrationPCRIndex stores the successor-PCR0 handoff commitment.
const migrationPCRIndex = 31

type StartMigrationRequest struct {
	NewPCR0 string `json:"new_pcr0"`
}

type StartMigrationResult struct {
	PCR0     string   `json:"pcr0"`
	Exported []string `json:"exported"`
}

type PreviousPCR0Info struct {
	PCR0        string
	Attestation string
}

type CooldownStatus struct {
	ConfiguredSeconds int
	RemainingSeconds  int
	Pending           bool
}

type Migrator interface {
	StartMigration(ctx context.Context, newPCR0 string) (*StartMigrationResult, error)
	PreviousPCR0Info(ctx context.Context) (*PreviousPCR0Info, error)
	CooldownStatus(ctx context.Context) (*CooldownStatus, error)
}

type migrator struct {
	nsm           NSM
	kms           PrimaryKMS
	ssm           SSM
	dek           DEK
	staticSecrets []StaticSecret
}

func NewMigrator(
	nsm NSM,
	kms PrimaryKMS,
	ssm SSM,
	dek DEK,
	secrets []StaticSecret,
) Migrator {
	return &migrator{
		nsm:           nsm,
		kms:           kms,
		ssm:           ssm,
		dek:           dek,
		staticSecrets: secrets,
	}
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

func (m *migrator) CooldownStatus(ctx context.Context) (*CooldownStatus, error) {
	cooldown := getMigrationCooldown()
	configuredSeconds := int(cooldown.Seconds())

	requestedAtStr, err := m.ssm.MayGet(ctx, migrationRequestedAtParam())
	if err != nil {
		return nil, fmt.Errorf("failed to read migration requested at SSM param: %w", err)
	}

	if requestedAtStr == "" {
		return &CooldownStatus{
			ConfiguredSeconds: configuredSeconds,
			RemainingSeconds:  0,
			Pending:           false,
		}, nil
	}

	requestedAt, err := time.Parse(time.RFC3339, requestedAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s at as RFC3339 timestamp: %w",
			migrationPreviousPCR0Param(), err)
	}

	deadline := requestedAt.Add(cooldown)
	rem := time.Until(deadline)
	if rem < 0 {
		rem = 0
	}

	return &CooldownStatus{
		ConfiguredSeconds: configuredSeconds,
		RemainingSeconds:  int(rem.Seconds()),
		Pending:           true,
	}, nil
}

// StartMigration exports state under a PCR0-locked migration key, then flips KMSKeyID.
func (m *migrator) StartMigration(
	ctx context.Context,
	newPCR0 string,
) (*StartMigrationResult, error) {
	newPCR0Bytes, err := validateNewPCR0(newPCR0)
	if err != nil {
		return nil, err
	}

	pcr0, err := m.nsm.PCR0()
	if err != nil {
		return nil, fmt.Errorf("could not read own PCR0 from NSM")
	}
	ownPCR0 := hex.EncodeToString(pcr0)

	if err := m.nsm.CommitPCR(migrationPCRIndex, newPCR0Bytes); err != nil {
		return nil, fmt.Errorf("failed to commit new PCR0 to PCR31: %w", err)
	}

	migrationKMS, err := m.kms.CreateMigrationKMS(ctx, newPCR0)
	if err != nil {
		return nil, fmt.Errorf("failed to create migration key: %w", err)
	}

	slog.Info(
		"created migration KMS key",
		"key_id", migrationKMS.KeyID(),
		"own_pcr0", prefix16(ownPCR0),
		"new_pcr0", prefix16(newPCR0),
	)

	exportedNames := make([]string, 0, len(m.staticSecrets))
	transitionSecrets := make([]persistedSecret, 0, len(m.staticSecrets))
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
		transitionSecrets = append(transitionSecrets, persistedSecret{
			metadata:   secret.StaticSecretMetadata,
			ciphertext: ciphertextB64,
		})
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
		persistedStateSnapshot{
			kmsKeyID:      migrationKMS.KeyID(),
			staticSecrets: transitionSecrets,
			storageDEK:    dekCiphertext,
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

	return &StartMigrationResult{
		PCR0:     ownPCR0,
		Exported: exportedNames,
	}, nil
}

func (r StartMigrationRequest) Validate() error {
	_, err := validateNewPCR0(r.NewPCR0)
	return err
}

func validateNewPCR0(pcr0 string) ([]byte, error) {
	if pcr0 == "" {
		return nil, fmt.Errorf("new_pcr0 is required in request body")
	}
	if len(pcr0) != 96 {
		return nil, fmt.Errorf("new_pcr0 must be 96 hex characters (SHA-384)")
	}

	bytes, err := hex.DecodeString(pcr0)
	if err != nil {
		return nil, fmt.Errorf("new_pcr0 must be valid hex")
	}

	return bytes, err
}
