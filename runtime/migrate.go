package runtime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// migrationPCRIndex stores the successor-PCR0 handoff commitment.
const (
	migrationPCRIndex      = 31
	successorClaimSchemaV1 = "enclave.successor_claim.v1"
)

// successorClaimV1 binds an attestation to its state namespace.
type successorClaimV1 struct {
	Schema     string `cbor:"schema"`
	Deployment string `cbor:"deployment"`
	AppName    string `cbor:"app_name"`
	Lock       string `cbor:"lock"`
}

// CandidateInfo is reported by an enclave still awaiting a handoff.
type CandidateInfo struct {
	AwaitingHandoffFrom string     `json:"awaiting_handoff_from,omitempty"`
	RequestedAt         *time.Time `json:"requested_at,omitempty"`
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

type migrationChallenge struct {
	nonce    []byte
	issuedAt time.Time
}

const (
	migrationStateNone        = "none"
	migrationStateCoolingDown = "cooling_down"
	migrationStateEligible    = "eligible"
	migrationStateAborted     = "aborted"
)

type Migrator interface {
	RunPredecessorHandoff(
		ctx context.Context, kms PrimaryKMS, dek DEK, secrets []StaticSecret, tlsKey crypto.Signer,
	)
	AwaitCandidateHandoff(ctx context.Context) error

	PreviousPCR0Info(ctx context.Context) (*PreviousPCR0Info, error)
	MigrationStatus(ctx context.Context) (*MigrationStatus, error)
	CandidateInfo(ctx context.Context) (*CandidateInfo, error)
}

type migrator struct {
	cfg           *Config
	mu            sync.Mutex
	nsm           NSM
	pcr0          string // hex; read from the NSM once, in newMigrator
	kms           PrimaryKMS
	ssm           SSM
	dek           DEK
	staticSecrets []StaticSecret
	tlsKey        crypto.Signer
	intent        *migrationIntentLog
	genesis       *genesisLog
	promoted      atomic.Bool

	challenge         atomic.Pointer[migrationChallenge]
	answeredChallenge string
}

// NewMigrator initializes migration before enclave state is available.
func NewMigrator(
	cfg *Config,
	nsm NSM,
	ssm SSM,
	s3 S3API,
	migrationIntentBucketName string,
) (Migrator, error) {
	m, err := newMigrator(cfg, nsm, ssm, s3, migrationIntentBucketName)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func newMigrator(
	cfg *Config,
	nsm NSM,
	ssm SSM,
	s3 S3API,
	migrationIntentBucketName string,
) (*migrator, error) {
	pcr0, err := nsm.PCR0()
	if err != nil {
		return nil, fmt.Errorf("read PCR0: %w", err)
	}
	if len(pcr0) != 48 {
		return nil, fmt.Errorf("PCR0 must be 48 bytes, got %d", len(pcr0))
	}
	intent, err := newMigrationIntentLog(cfg, s3, nsm, migrationIntentBucketName)
	if err != nil {
		return nil, err
	}
	genesis, err := newGenesisLog(cfg, s3, nsm, migrationIntentBucketName)
	if err != nil {
		return nil, err
	}
	return &migrator{
		cfg:     cfg,
		nsm:     nsm,
		pcr0:    hex.EncodeToString(pcr0),
		ssm:     ssm,
		intent:  intent,
		genesis: genesis,
	}, nil
}

func (m *migrator) PreviousPCR0Info(ctx context.Context) (*PreviousPCR0Info, error) {
	pcr0, err := m.ssm.MayGet(ctx, m.cfg.migrationPreviousPCR0Param(m.pcr0))
	if err != nil {
		return nil, err
	}

	if pcr0 == "" {
		pcr0 = "genesis"
	}

	attest, err := m.ssm.MayGet(ctx, m.cfg.migrationPreviousPCR0AttestationParam(m.pcr0))
	if err != nil {
		return nil, err
	}
	return &PreviousPCR0Info{PCR0: pcr0, Attestation: attest}, nil
}

func (m *migrator) CandidateInfo(ctx context.Context) (*CandidateInfo, error) {
	// Report only the configured predecessor's handoff.
	head, err := m.intent.Head(ctx, strings.ToLower(m.cfg.PreviousPCR0))
	if err != nil || head == nil || head.Action != migrationIntentRequested ||
		!strings.EqualFold(head.TargetPCR0, m.pcr0) {
		return nil, err
	}

	publishedAt := head.PublishedAt
	return &CandidateInfo{
		AwaitingHandoffFrom: head.SourcePCR0,
		RequestedAt:         &publishedAt,
	}, nil
}

func (m *migrator) MigrationStatus(ctx context.Context) (*MigrationStatus, error) {
	head, err := m.intent.Head(ctx, m.pcr0)
	if err != nil {
		return nil, err
	}
	if head == nil {
		return &MigrationStatus{State: migrationStateNone, SourcePCR0: m.pcr0}, nil
	}

	status := &MigrationStatus{
		SourcePCR0:  head.SourcePCR0,
		TargetPCR0:  head.TargetPCR0,
		Sequence:    head.Sequence,
		Action:      head.Action,
		PublishedAt: &head.PublishedAt,
	}
	if head.Action == migrationIntentAborted {
		status.State = migrationStateAborted
		return status, nil
	}

	eligibleAt := head.PublishedAt.Add(m.cfg.MigrationCooldown)
	status.EligibleAt = &eligibleAt
	remaining := time.Until(eligibleAt)
	// Zero cooldown ignores clock skew.
	if m.cfg.MigrationCooldown == 0 || remaining <= 0 {
		status.State = migrationStateEligible
		return status, nil
	}
	status.State = migrationStateCoolingDown
	status.RemainingSeconds = int(math.Ceil(remaining.Seconds()))
	return status, nil
}

// Migration is coordinated through SSM; candidates attest their own PCR0.
//
//	predecessor                              candidate
//	  publish challenge  -------------->  read it
//	  read answers       <--------------  publish attestation
//	  verify, record intent
//	  ... cooldown ...
//	  commit KMSKeyID/<target>  ------->  promote
//

func (m *migrator) RunPredecessorHandoff(
	ctx context.Context, kms PrimaryKMS, dek DEK, secrets []StaticSecret, tlsKey crypto.Signer,
) {
	m.mu.Lock()
	m.kms, m.dek, m.staticSecrets, m.tlsKey = kms, dek, secrets, tlsKey
	m.mu.Unlock()
	m.promoted.Store(true)

	ticker := time.NewTicker(migrationPollInterval)
	defer ticker.Stop()

	for {
		if err := m.advanceMigration(ctx); err != nil &&
			!errors.Is(err, errMigrationIntentAbsent) {
			// Handoff failures must not stop a serving enclave.
			slog.Warn("predecessor handoff", "error", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// AwaitCandidateHandoff waits for the predecessor's atomic commit. It returns
// immediately for an existing generation or a fresh deployment.
func (m *migrator) AwaitCandidateHandoff(ctx context.Context) error {
	kmsIdParam := m.cfg.kmsKeyIDParam(m.pcr0)
	keyID, err := m.ssm.MayGet(ctx, kmsIdParam)
	if err != nil {
		return fmt.Errorf("failed to get KMS key ID SSM param: %w", err)
	}
	if keyID != "" {
		return nil
	}

	artifact, err := m.genesis.Genesis(ctx)
	if err != nil {
		return fmt.Errorf("failed to read deployment genesis: %w", err)
	}
	if artifact == nil {
		return nil
	}

	if artifact.PCR0 == m.pcr0 {
		return nil
	}

	slog.Info("candidate: awaiting migration handoff", "pointer", kmsIdParam)
	ticker := time.NewTicker(migrationPollInterval)
	defer ticker.Stop()
	for keyID == "" {
		if err := m.respondToChallenge(ctx); err != nil {
			slog.Warn("candidate handoff", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		if keyID, err = m.ssm.MayGet(ctx, kmsIdParam); err != nil {
			return fmt.Errorf("failed to get KMS key ID SSM param: %w", err)
		}
	}
	return nil
}

func (m *migrator) verifyIntent(
	ctx context.Context, sourcePCR0, targetPCR0 string, sequence uint64,
) error {
	head, err := m.intent.Head(ctx, sourcePCR0)
	if err != nil {
		return fmt.Errorf("verify migration intent: %w", err)
	}
	if head == nil {
		return fmt.Errorf("%w: intent disappeared before commit", errMigrationIntentAbsent)
	}
	if head.Action == migrationIntentAborted {
		return fmt.Errorf("%w: aborted before commit", errMigrationIntentAborted)
	}
	if head.Sequence != sequence {
		return fmt.Errorf(
			"%w: intent advanced from sequence %d to %d before commit",
			errMigrationIntentAborted, sequence, head.Sequence,
		)
	}
	if !strings.EqualFold(head.TargetPCR0, targetPCR0) {
		return fmt.Errorf(
			"%w: intent target changed before commit", errMigrationIntentAborted,
		)
	}
	return nil
}

func (m *migrator) issueMigrationChallenge() (string, error) {
	challenge := make([]byte, 32)
	if _, err := secureRandom(challenge); err != nil {
		return "", fmt.Errorf("generate migration challenge: %w", err)
	}

	m.challenge.Store(&migrationChallenge{nonce: challenge, issuedAt: time.Now()})

	return hex.EncodeToString(challenge), nil
}

// advanceMigration advances the predecessor state machine once.
func (m *migrator) advanceMigration(ctx context.Context) error {
	if !m.promoted.Load() {
		return errMigrationCandidate
	}

	status, err := m.MigrationStatus(ctx)
	if err != nil {
		return err
	}

	pending := status.State == migrationStateCoolingDown || status.State == migrationStateEligible
	if pending {
		aborted, err := m.mayAbortMigration(ctx, status.TargetPCR0)
		if err != nil || aborted {
			return err
		}
	}

	switch status.State {
	case migrationStateCoolingDown:
		return nil
	case migrationStateEligible:
		if err := m.handOffToSuccessor(ctx); !errors.Is(err, errMigrationAlreadyFinalised) {
			return err
		}
		return nil
	}

	// With no pending intent, publish a challenge and inspect its answers.
	if err := m.mayPublishChallenge(ctx); err != nil {
		return err
	}

	responses, err := m.ssm.ListParams(ctx, m.cfg.migrationResponseParam(m.pcr0, ""))
	if err != nil {
		return fmt.Errorf("list migration responses: %w", err)
	}
	if len(responses) == 0 {
		return nil
	}

	target, err := m.verifyChallengeResponses(ctx, responses)
	if err != nil {
		return err
	}

	if target == "" {
		return nil
	}

	if _, err := m.intent.Request(ctx, m.pcr0, target); err != nil {
		return err
	}
	// Retire this challenge after recording its intent.
	m.challenge.Store(nil)

	slog.Info("migration intent recorded from candidate attestation",
		"target_pcr0", prefix16(target))

	return nil
}

// mayPublishChallenge creates or rotates the live nonce.
func (m *migrator) mayPublishChallenge(ctx context.Context) error {
	challenge := m.challenge.Load()
	fresh := challenge != nil && time.Since(challenge.issuedAt) < migrationChallengeRotate
	if fresh {
		return nil
	}

	newChallenge, err := m.issueMigrationChallenge()
	if err != nil {
		return err
	}
	if err := m.ssm.Set(ctx, m.cfg.migrationChallengeParam(m.pcr0), newChallenge); err != nil {
		return fmt.Errorf("publish migration challenge: %w", err)
	}
	return nil
}

// verifyChallengeResponses returns the first candidate answering the live challenge.
func (m *migrator) verifyChallengeResponses(
	ctx context.Context,
	responses []Param,
) (string, error) {
	challenge := m.challenge.Load()
	if challenge == nil {
		return "", nil
	}
	issued := challenge.nonce

	expectedPayload, err := successorClaimPayload(m.cfg)
	if err != nil {
		return "", err
	}

	reject := func(response Param, err error) {
		slog.Warn("ignoring successor attestation", "param", response.Name, "error", err)
	}
	for _, response := range responses {
		doc, err := m.nsm.VerifyAttestationDocument(response.Value, nil)
		if err != nil {
			reject(response, fmt.Errorf("verify successor attestation: %w", err))
			continue
		}
		if !bytes.Equal(doc.Document.UserData, expectedPayload) {
			reject(response, errors.New("attested user data does not match expected user data"))
			continue
		}
		if !bytes.Equal(doc.Document.Nonce, issued) {
			reject(
				response,
				errors.New("successor attestation does not answer the issued challenge"),
			)
			continue
		}
		if len(doc.Document.PCRs[0]) == 0 {
			reject(response, errors.New("successor attestation has no PCR0"))
			continue
		}

		attested, _, err := normalizePCR0(hex.EncodeToString(doc.Document.PCRs[0]))
		if err != nil {
			reject(response, fmt.Errorf("successor PCR0 %w", err))
			continue
		}
		if strings.EqualFold(attested, m.pcr0) {
			continue
		}

		return attested, nil
	}
	return "", nil
}

// mayAbortMigration records a matching abort before the handoff commits.
func (m *migrator) mayAbortMigration(ctx context.Context, targetPCR0 string) (bool, error) {
	abortParam := m.cfg.migrationResponseParam(m.pcr0, migrationAbortResponse)
	abortedPCR0, err := m.ssm.MayGet(ctx, abortParam)
	if err != nil {
		return false, fmt.Errorf("read migration abort: %w", err)
	}
	if abortedPCR0 == "" || !strings.EqualFold(abortedPCR0, targetPCR0) {
		return false, nil
	}

	// Serialize the abort check with commit.
	m.mu.Lock()
	defer m.mu.Unlock()
	targetKmsID, err := m.ssm.MayGet(ctx, m.cfg.kmsKeyIDParam(targetPCR0))
	if err != nil {
		return false, fmt.Errorf("failed to read target KMS key ID: %w", err)
	}
	if targetKmsID != "" {
		slog.Warn("ignoring migration abort: the handoff has already committed",
			"target_pcr0", prefix16(targetPCR0))
		return false, nil
	}
	if _, err := m.intent.Abort(ctx, m.pcr0); err != nil {
		return false, err
	}
	slog.Warn("migration aborted by operator", "target_pcr0", prefix16(targetPCR0))
	return true, nil
}

// eligibleHandOff returns an eligible intent. The caller holds m.mu.
func (m *migrator) eligibleHandOff(ctx context.Context) (*MigrationStatus, error) {
	status, err := m.MigrationStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve migration intent: %w", err)
	}
	switch status.State {
	case migrationStateEligible:
		return status, nil
	case migrationStateNone:
		return nil, errMigrationIntentAbsent
	case migrationStateAborted:
		return nil, errMigrationIntentAborted
	case migrationStateCoolingDown:
		return nil, fmt.Errorf(
			"%w: %d seconds remaining",
			errMigrationCooldownActive,
			status.RemainingSeconds,
		)
	}
	return nil, fmt.Errorf("migration intent has unexpected state %q", status.State)
}

// handOffToSuccessor exports state, then commits the target generation.
func (m *migrator) handOffToSuccessor(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	status, err := m.eligibleHandOff(ctx)
	if err != nil {
		return err
	}

	targetPCR0, targetPCR0Bytes, err := normalizePCR0(status.TargetPCR0)
	if err != nil {
		return fmt.Errorf("migration intent has invalid target PCR0: %w", err)
	}

	targetKmsID, err := m.ssm.MayGet(ctx, m.cfg.kmsKeyIDParam(targetPCR0))
	if err != nil {
		return fmt.Errorf("failed to read target KMS key ID: %w", err)
	}
	if targetKmsID != "" {
		return fmt.Errorf(
			"%w: %s already has a committed generation",
			errMigrationAlreadyFinalised,
			m.cfg.kmsKeyIDParam(targetPCR0),
		)
	}

	if err := m.nsm.CommitPCR(migrationPCRIndex, targetPCR0Bytes); err != nil {
		return fmt.Errorf("failed to commit new PCR0 to PCR31: %w", err)
	}

	migrationKMS, err := m.kms.CreateMigrationKMS(ctx, targetPCR0)
	if err != nil {
		return fmt.Errorf("failed to create migration key: %w", err)
	}

	slog.Info(
		"created migration KMS key",
		"key_id", migrationKMS.KeyID(),
		"own_pcr0", prefix16(m.pcr0),
		"new_pcr0", prefix16(targetPCR0),
	)

	transitionSecrets := make(map[StaticSecretMetadata]string, len(m.staticSecrets))
	for _, secret := range m.staticSecrets {
		secretBytes, err := hex.DecodeString(secret.Plaintext)
		if err != nil {
			return fmt.Errorf("failed to decode secret %s hex: %w", secret.Name, err)
		}

		ciphertextB64, err := migrationKMS.Encrypt(ctx, secretBytes)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt secret %s: %w", secret.Name, err)
		}

		ciphertextParam := m.cfg.secretCiphertextParam(secret.Name, migrationKMS.KeyID())
		if err := m.ssm.Set(ctx, ciphertextParam, ciphertextB64); err != nil {
			return fmt.Errorf("failed to store re-encrypted secret %s: %w", secret.Name, err)
		}
		transitionSecrets[secret.StaticSecretMetadata] = ciphertextB64
	}

	dekCiphertext, err := m.dek.ExportKey(ctx, m.cfg, migrationKMS, m.ssm)
	if err != nil {
		return fmt.Errorf("DEK export failed: %w", err)
	}
	tlsKey, err := x509.MarshalPKCS8PrivateKey(m.tlsKey)
	if err != nil {
		return fmt.Errorf("failed to marshal TLS key: %w", err)
	}
	tlsKeyCiphertext, err := migrationKMS.Encrypt(ctx, tlsKey)
	if err != nil {
		return fmt.Errorf("failed to re-encrypt TLS key: %w", err)
	}
	if err := m.ssm.Set(
		ctx,
		m.cfg.tlsKeyCiphertextParam(migrationKMS.KeyID()),
		tlsKeyCiphertext,
	); err != nil {
		return fmt.Errorf("failed to store TLS key: %w", err)
	}

	attestDoc, _, err := m.nsm.BuildAttestationDocument()
	if err != nil {
		return fmt.Errorf("failed to generate attestation document: %w", err)
	}

	if err := m.ssm.Set(
		ctx,
		m.cfg.migrationPreviousPCR0AttestationParam(targetPCR0),
		base64.StdEncoding.EncodeToString(attestDoc),
		WithAdvancedTier(),
	); err != nil {
		return fmt.Errorf(
			"failed to set SSM param %s: %w",
			m.cfg.migrationPreviousPCR0AttestationParam(targetPCR0), err,
		)
	}

	if err := m.ssm.Set(ctx, m.cfg.migrationPreviousPCR0Param(targetPCR0), m.pcr0); err != nil {
		return fmt.Errorf(
			"failed to set SSM param %s: %w", m.cfg.migrationPreviousPCR0Param(targetPCR0), err,
		)
	}
	if err := m.ssm.Set(
		ctx, m.cfg.migrationPreviousKMSKeyIDParam(targetPCR0), m.kms.KeyID(),
	); err != nil {
		return fmt.Errorf("failed to store predecessor KMS key ID: %w", err)
	}

	// Write handoff receipt before committing KMSKeyID.
	if err := WriteTransitionReceipt(
		ctx,
		m.cfg,
		m.nsm,
		m.ssm,
		bootSnapshot{
			kmsKeyID:                  migrationKMS.KeyID(),
			ownerPCR0:                 targetPCR0,
			predecessorPCR0:           m.pcr0,
			predecessorKMSKeyID:       m.kms.KeyID(),
			staticSecrets:             transitionSecrets,
			storageDEK:                dekCiphertext,
			tlsKeyCiphertext:          tlsKeyCiphertext,
			migrationIntentBucketName: m.intent.bucket,
		},
	); err != nil {
		return fmt.Errorf(
			"failed to write migration-transition receipt: %w", err,
		)
	}

	if err := m.verifyIntent(ctx, m.pcr0, targetPCR0, status.Sequence); err != nil {
		return err
	}

	// Atomic commit: from here, the successor boots on the migration key.
	if err := m.ssm.Set(
		ctx,
		m.cfg.kmsKeyIDParam(targetPCR0),
		migrationKMS.KeyID(),
		WithoutOverwrite(),
	); err != nil {
		if isParameterAlreadyExists(err) {
			return fmt.Errorf(
				"%w: %s was committed by a concurrent finaliser",
				errMigrationAlreadyFinalised,
				m.cfg.kmsKeyIDParam(targetPCR0),
			)
		}
		return fmt.Errorf(
			"failed to commit successor KMS key ID: %w", err,
		)
	}

	slog.Info(
		"committed successor KMSKeyID",
		"key_id", migrationKMS.KeyID(),
		"target_pcr0", prefix16(targetPCR0),
		"exported", len(transitionSecrets),
	)
	return nil
}

func (m *migrator) respondToChallenge(ctx context.Context) error {
	predecessor := m.cfg.PreviousPCR0

	// Restarting an established generation must not offer another handoff.
	keyID, err := m.ssm.MayGet(ctx, m.cfg.kmsKeyIDParam(m.pcr0))
	if err != nil {
		return fmt.Errorf("read candidate KMS key ID: %w", err)
	}
	if keyID != "" {
		return nil
	}

	publishedChallenge, err := m.ssm.MayGet(ctx, m.cfg.migrationChallengeParam(predecessor))
	if err != nil {
		return fmt.Errorf("read migration challenge: %w", err)
	}
	// Answer each challenge once.
	if publishedChallenge == m.answeredChallenge {
		return nil
	}
	challenge, err := hex.DecodeString(publishedChallenge)
	if err != nil || len(challenge) == 0 {
		return nil
	}

	// Bind the answer to the challenge nonce.
	payload, err := successorClaimPayload(m.cfg)
	if err != nil {
		return fmt.Errorf("attest successor claim: %w", err)
	}
	doc, _, err := m.nsm.BuildAttestationDocument(WithNonce(challenge), WithUserData(payload))
	if err != nil {
		return fmt.Errorf("attest successor claim: %w", err)
	}

	if err := m.ssm.Set(
		ctx, m.cfg.migrationResponseParam(predecessor, m.pcr0),
		base64.StdEncoding.EncodeToString(doc), WithAdvancedTier(),
	); err != nil {
		return fmt.Errorf("publish successor attestation: %w", err)
	}
	m.answeredChallenge = publishedChallenge
	return nil
}

func successorClaimPayload(cfg *Config) ([]byte, error) {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("build canonical CBOR encoder: %w", err)
	}
	payload, err := enc.Marshal(successorClaimV1{
		Schema:     successorClaimSchemaV1,
		Deployment: cfg.Deployment,
		AppName:    cfg.AppName,
		Lock:       cfg.lockSegment(),
	})
	if err != nil {
		return nil, fmt.Errorf("serialize successor claim: %w", err)
	}
	return payload, nil
}
