package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// migrationPCRIndex stores the successor-PCR0 handoff commitment.
const (
	migrationPCRIndex        = 31
	migrationPollInterval    = 5 * time.Second
	migrationChallengeRotate = time.Minute
	successorClaimSchemaV1   = "enclave.successor_claim.v1"
)

// successorClaimV1 is the attested pre-image a candidate offers. Deployment is
// measured and not SSM-overridable, so it binds the claim to one deployment and
// a document produced for another is rejected.
type successorClaimV1 struct {
	Schema     string `cbor:"schema"`
	Deployment string `cbor:"deployment"`
}

// CandidateInfo is reported by an enclave still awaiting a handoff.
type CandidateInfo struct {
	AwaitingHandoffFrom string     `json:"awaiting_handoff_from,omitempty"`
	RequestedAt         *time.Time `json:"requested_at,omitempty"`
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
	// RunMigrationControl drives the predecessor half, for the life of a
	// serving enclave.
	RunMigrationControl(ctx context.Context)
	// RunCandidateAttestation drives the candidate half, until promotion.
	RunCandidateAttestation(ctx context.Context)

	PreviousPCR0Info(ctx context.Context) (*PreviousPCR0Info, error)
	MigrationStatus(ctx context.Context) (*MigrationStatus, error)
	CandidateInfo(ctx context.Context) (*CandidateInfo, error)
	Ready() bool
	Promote(kms PrimaryKMS, dek DEK, secrets []StaticSecret)
}

type migrator struct {
	mu            sync.Mutex
	nsm           NSM
	kms           PrimaryKMS
	ssm           SSM
	dek           DEK
	staticSecrets []StaticSecret
	intent        *migrationIntentLog
	ready         bool

	challenge   []byte
	challengeAt time.Time
}

// NewMigrator builds the candidate half: enough to attest identity, answer a
// challenge and read the intent log, which is all an enclave can do before it
// holds state. Promote supplies the rest once state is established.
func NewMigrator(
	nsm NSM,
	ssm SSM,
	s3 S3API,
	migrationIntentBucketName string,
) (Migrator, error) {
	m, err := newMigrator(nsm, ssm, s3, migrationIntentBucketName)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (m *migrator) Promote(kms PrimaryKMS, dek DEK, secrets []StaticSecret) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kms = kms
	m.dek = dek
	m.staticSecrets = secrets
	m.ready = true
}

func (m *migrator) Ready() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ready
}

func (m *migrator) PreviousPCR0Info(ctx context.Context) (*PreviousPCR0Info, error) {
	own, err := m.nsm.PCR0()
	if err != nil {
		return nil, fmt.Errorf("could not read own PCR0 from NSM: %w", err)
	}
	ownPCR0 := hex.EncodeToString(own)

	pcr0, err := m.ssm.MayGet(ctx, migrationPreviousPCR0Param(ownPCR0))
	if err != nil {
		return nil, err
	}

	if pcr0 == "" {
		pcr0 = "genesis"
	}

	attest, err := m.ssm.MayGet(ctx, migrationPreviousPCR0AttestationParam(ownPCR0))
	if err != nil {
		return nil, err
	}
	return &PreviousPCR0Info{PCR0: pcr0, Attestation: attest}, nil
}

func (m *migrator) CandidateInfo(ctx context.Context) (*CandidateInfo, error) {
	own, err := m.nsm.PCR0()
	if err != nil {
		return nil, fmt.Errorf("could not read own PCR0 from NSM: %w", err)
	}

	inbound, err := m.intent.InboundIntent(ctx, hex.EncodeToString(own))
	if err != nil || inbound == nil {
		return nil, err
	}

	publishedAt := inbound.PublishedAt
	return &CandidateInfo{
		AwaitingHandoffFrom: inbound.SourcePCR0,
		RequestedAt:         &publishedAt,
	}, nil
}

func (m *migrator) MigrationStatus(ctx context.Context) (*MigrationStatus, error) {
	cooldown, err := getMigrationCooldown()
	if err != nil {
		return nil, err
	}
	head, err := m.intent.Head(ctx)
	if err != nil {
		return nil, err
	}
	status := migrationStatusAt(head, cooldown, time.Now())
	if head == nil {
		status.SourcePCR0, err = m.intent.sourcePCR0()
		if err != nil {
			return nil, err
		}
	}
	return status, nil
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

	targetPCR0, targetPCR0Bytes, err := normalizePCR0(status.TargetPCR0)
	if err != nil {
		return nil, fmt.Errorf("migration intent has invalid target PCR0: %w", err)
	}

	existing, err := m.ssm.MayGet(ctx, kmsKeyIDParam(targetPCR0))
	if err != nil {
		return nil, fmt.Errorf("failed to read target KMS key ID: %w", err)
	}
	if existing != "" {
		return nil, fmt.Errorf(
			"%w: %s already has a committed generation",
			errMigrationAlreadyFinalised,
			kmsKeyIDParam(targetPCR0),
		)
	}

	if err := m.nsm.CommitPCR(migrationPCRIndex, targetPCR0Bytes); err != nil {
		return nil, fmt.Errorf("failed to commit new PCR0 to PCR31: %w", err)
	}

	migrationKMS, err := m.kms.CreateMigrationKMS(ctx, targetPCR0)
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
		"new_pcr0", prefix16(targetPCR0),
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
		migrationPreviousPCR0AttestationParam(targetPCR0),
		base64.StdEncoding.EncodeToString(attestDoc),
		WithAdvancedTier(),
	); err != nil {
		return nil, fmt.Errorf(
			"failed to set SSM param %s: %w",
			migrationPreviousPCR0AttestationParam(targetPCR0), err,
		)
	}

	if err := m.ssm.Set(ctx, migrationPreviousPCR0Param(targetPCR0), ownPCR0); err != nil {
		return nil, fmt.Errorf(
			"failed to set SSM param %s: %w", migrationPreviousPCR0Param(targetPCR0), err,
		)
	}

	// Write handoff receipt before committing KMSKeyID.
	if err := WriteTransitionReceipt(
		ctx,
		m.nsm,
		m.ssm,
		persistedStateSnapshot{
			kmsKeyID:                  migrationKMS.KeyID(),
			ownerPCR0:                 targetPCR0,
			staticSecrets:             transitionSecrets,
			storageDEK:                dekCiphertext,
			migrationIntentBucketName: m.intent.bucket,
		},
	); err != nil {
		return nil, fmt.Errorf(
			"failed to write migration-transition receipt: %w", err,
		)
	}

	// Atomic commit: SSM's create-only write elects exactly one predecessor when
	// independent replicas race to hand state to the same successor.
	created, err := m.ssm.SetIfAbsent(
		ctx,
		kmsKeyIDParam(targetPCR0),
		migrationKMS.KeyID(),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to commit successor KMS key ID: %w", err,
		)
	}
	if !created {
		return nil, fmt.Errorf(
			"%w: %s already has a committed generation",
			errMigrationAlreadyFinalised,
			kmsKeyIDParam(targetPCR0),
		)
	}

	slog.Info(
		"committed successor KMSKeyID",
		"key_id", migrationKMS.KeyID(),
		"target_pcr0", prefix16(targetPCR0),
	)

	return &CompleteMigrationResult{
		PCR0:     ownPCR0,
		Exported: exportedNames,
	}, nil
}

// The migration control plane is autonomous and lives entirely in SSM. There is
// no admin endpoint, and no channel through which a host can name a successor.
//
//	predecessor                              candidate
//	  publish challenge  -------------->  read it
//	  read answers       <--------------  publish attestation
//	  verify, record intent
//	  ... cooldown ...
//	  commit KMSKeyID/<target>  ------->  promote
//

func (m *migrator) RunMigrationControl(ctx context.Context) {
	ticker := time.NewTicker(migrationPollInterval)
	defer ticker.Stop()

	for {
		if err := m.advanceMigration(ctx); err != nil &&
			!errors.Is(err, errMigrationIntentAbsent) {
			// Nothing here is fatal: a serving enclave keeps serving whether or
			// not a handoff can proceed.
			slog.Warn("migration control", "error", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunCandidateAttestation drives the candidate half: answer every published
// challenge so a predecessor can discover this enclave and prove what it is.
func (m *migrator) RunCandidateAttestation(ctx context.Context) {
	ticker := time.NewTicker(migrationPollInterval)
	defer ticker.Stop()

	for {
		if m.Ready() {
			return
		}

		if err := m.answerChallenges(ctx); err != nil {
			slog.Warn("candidate attestation", "error", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func newMigrator(
	nsm NSM,
	ssm SSM,
	s3 S3API,
	migrationIntentBucketName string,
) (*migrator, error) {
	intent, err := newMigrationIntentLog(s3, nsm, migrationIntentBucketName)
	if err != nil {
		return nil, err
	}
	return &migrator{
		nsm:    nsm,
		ssm:    ssm,
		intent: intent,
	}, nil
}

func (m *migrator) issueMigrationChallenge() (string, error) {
	challenge := make([]byte, 32)
	if _, err := secureRandom(challenge); err != nil {
		return "", fmt.Errorf("generate migration challenge: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.challenge = challenge
	m.challengeAt = time.Now()

	return hex.EncodeToString(challenge), nil
}

func (m *migrator) handleMigrationRequest(
	ctx context.Context,
	action, targetPCR0 string,
) (*MigrationStatus, error) {
	cooldown, err := getMigrationCooldown()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.ready {
		return nil, errMigrationCandidate
	}

	var intentHead *migrationIntent
	switch action {
	case migrationIntentRequested:
		intentHead, err = m.intent.Request(ctx, targetPCR0)
		if err != nil {
			return nil, err
		}
		// One challenge, one intent: the next round mints a fresh nonce, which
		// retires every answer to this one.
		m.challenge = nil
	case migrationIntentAborted:
		intentHead, err = m.intent.Abort(ctx)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown migration action %q", action)
	}

	return migrationStatusAt(intentHead, cooldown, time.Now()), nil
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

// advanceMigration moves the handoff one step: publish a challenge, adopt a
// candidate's answer as an intent, or commit once the cooldown has elapsed.
func (m *migrator) advanceMigration(ctx context.Context) error {
	own, err := m.ownPCR0()
	if err != nil {
		return err
	}

	status, err := m.MigrationStatus(ctx)
	if err != nil {
		return err
	}

	switch status.State {
	case migrationStateEligible:
		return m.commitMigration(ctx, own, status)
	case migrationStateCoolingDown:
		return nil
	}

	// No intent, or the last one was aborted: keep a live challenge published and
	// watch for an answer.
	if err := m.publishChallenge(ctx, own); err != nil {
		return err
	}
	return m.adoptCandidate(ctx, own)
}

// publishChallenge keeps a fresh nonce in SSM for candidates to answer. It
// rotates so a long-dead answer cannot be presented later.
func (m *migrator) publishChallenge(ctx context.Context, ownPCR0 string) error {
	m.mu.Lock()
	fresh := len(m.challenge) > 0 && time.Since(m.challengeAt) < migrationChallengeRotate
	m.mu.Unlock()
	if fresh {
		return nil
	}

	challenge, err := m.issueMigrationChallenge()
	if err != nil {
		return err
	}
	if err := m.ssm.Set(ctx, migrationChallengeParam(ownPCR0), challenge); err != nil {
		return fmt.Errorf("publish migration challenge: %w", err)
	}
	return nil
}

// adoptCandidate looks for a candidate that answered the live challenge and
// records the Object-Locked intent naming it.
func (m *migrator) adoptCandidate(ctx context.Context, ownPCR0 string) error {
	answers, err := m.ssm.ListParams(ctx, successorAttestationPrefix(ownPCR0))
	if err != nil {
		return fmt.Errorf("list successor attestations: %w", err)
	}
	if len(answers) == 0 {
		return nil
	}

	m.mu.Lock()
	issued := append([]byte(nil), m.challenge...)
	m.mu.Unlock()
	if len(issued) == 0 {
		return nil
	}

	// Verify every answer before choosing, so an unparseable one cannot mask a
	// second valid candidate and make an ambiguous state look decided.
	var targets []string
	for _, answer := range answers {
		target, err := m.verifySuccessorAttestation(answer.Value, issued)
		if err != nil {
			slog.Warn("ignoring successor attestation", "param", answer.Name, "error", err)
			continue
		}
		if strings.EqualFold(target, ownPCR0) {
			continue
		}
		targets = append(targets, target)
	}

	switch len(targets) {
	case 0:
		return nil
	case 1:
	default:
		// Two live candidates means nobody knows which should win. Keep serving.
		return fmt.Errorf(
			"%w: %d candidates answered", errMigrationSuccessorAmbiguous, len(targets),
		)
	}

	if _, err := m.handleMigrationRequest(ctx, migrationIntentRequested, targets[0]); err != nil {
		return err
	}

	slog.Info("migration intent recorded from candidate attestation",
		"target_pcr0", prefix16(targets[0]))
	return nil
}

// commitMigration finalises once the cooldown has elapsed, unless an operator
// has written an abort naming the pending target.
func (m *migrator) commitMigration(
	ctx context.Context,
	ownPCR0 string,
	status *MigrationStatus,
) error {
	abort, err := m.ssm.MayGet(ctx, migrationAbortParam(ownPCR0))
	if err != nil {
		return fmt.Errorf("read migration abort: %w", err)
	}
	if strings.EqualFold(strings.TrimSpace(abort), status.TargetPCR0) {
		if _, err := m.handleMigrationRequest(ctx, migrationIntentAborted, ""); err != nil {
			return err
		}
		slog.Warn("migration aborted by operator", "target_pcr0", prefix16(status.TargetPCR0))
		return nil
	}

	res, err := m.CompleteMigration(ctx)
	if errors.Is(err, errMigrationAlreadyFinalised) {
		// The successor already holds a committed generation. Nothing to do.
		return nil
	}
	if err != nil {
		return err
	}

	slog.Info("migration committed", "from_pcr0", prefix16(res.PCR0),
		"exported", len(res.Exported))
	return nil
}

func (m *migrator) answerChallenges(ctx context.Context) error {
	own, err := m.ownPCR0()
	if err != nil {
		return err
	}

	challenges, err := m.ssm.ListParams(ctx, migrationChallengePrefix())
	if err != nil {
		return fmt.Errorf("list migration challenges: %w", err)
	}

	for _, published := range challenges {
		source := strings.TrimPrefix(published.Name, migrationChallengePrefix())
		if source == "" || strings.EqualFold(source, own) {
			continue
		}

		challenge, err := hex.DecodeString(strings.TrimSpace(published.Value))
		if err != nil || len(challenge) == 0 {
			continue
		}

		doc, err := m.buildSuccessorAttestation(challenge)
		if err != nil {
			return fmt.Errorf("attest successor claim: %w", err)
		}

		if err := m.ssm.Set(
			ctx,
			successorAttestationParam(source, own),
			doc,
			WithAdvancedTier(),
		); err != nil {
			return fmt.Errorf("publish successor attestation: %w", err)
		}
	}

	return nil
}

// buildSuccessorAttestation is the candidate side of migration initiation. The
// challenge lands in the document's nonce, so the predecessor can tell a live
// answer from a replayed one.
func (m *migrator) buildSuccessorAttestation(challenge []byte) (string, error) {
	if len(challenge) == 0 {
		return "", fmt.Errorf("migration challenge is required")
	}

	payload, err := successorClaimPayload(getDeployment())
	if err != nil {
		return "", err
	}

	doc, _, err := m.nsm.BuildAttestationDocument(WithNonce(challenge), WithUserData(payload))
	if err != nil {
		return "", fmt.Errorf("attest successor claim: %w", err)
	}

	return base64.StdEncoding.EncodeToString(doc), nil
}

// verifySuccessorAttestation is the predecessor side. It returns the successor's
// PCR0, taken from the verified document — the target is an output here, never
// an input, which is the whole point of the exchange.
func (m *migrator) verifySuccessorAttestation(docB64 string, challenge []byte) (string, error) {
	if docB64 == "" {
		return "", fmt.Errorf("successor attestation is required")
	}
	if len(challenge) == 0 {
		return "", fmt.Errorf("migration challenge is required")
	}

	// Built from our own deployment, so a claim naming another one cannot match.
	expected, err := successorClaimPayload(getDeployment())
	if err != nil {
		return "", err
	}

	// No expected PCRs: PCR0 is what we are here to learn. The signature and
	// certificate chain establish that some real enclave produced this.
	doc, err := m.nsm.VerifyAttestationDocument(docB64, nil, expected)
	if err != nil {
		return "", fmt.Errorf("verify successor attestation: %w", err)
	}

	if !bytes.Equal(doc.Document.Nonce, challenge) {
		return "", fmt.Errorf("successor attestation does not answer the issued challenge")
	}

	pcr0, ok := doc.Document.PCRs[0]
	if !ok {
		return "", fmt.Errorf("successor attestation has no PCR0")
	}

	targetPCR0, _, err := normalizePCR0(hex.EncodeToString(pcr0))
	if err != nil {
		return "", fmt.Errorf("successor PCR0 %w", err)
	}

	return targetPCR0, nil
}

func (m *migrator) ownPCR0() (string, error) {
	pcr0, err := m.nsm.PCR0()
	if err != nil {
		return "", fmt.Errorf("could not read own PCR0 from NSM: %w", err)
	}
	return hex.EncodeToString(pcr0), nil
}

func successorClaimPayload(deployment string) ([]byte, error) {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("build canonical CBOR encoder: %w", err)
	}
	payload, err := enc.Marshal(successorClaimV1{
		Schema:     successorClaimSchemaV1,
		Deployment: deployment,
	})
	if err != nil {
		return nil, fmt.Errorf("serialize successor claim: %w", err)
	}
	return payload, nil
}
