package runtime

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/hf/nsm"
)

// migrationPCRIndex: PCR the old enclave extends with the new enclave's PCR0,
// binding the handoff inside the NSM-signed attestation. Above 16 to avoid the
// secret-pubkey PCRs.
const migrationPCRIndex = 31
const keyDeletionPendingDays int32 = 7

type PreviousPCR0Info struct {
	PCR0        string
	Attestation string
}

// Migrator owns migration-related SSM state, the start-migration handler,
// and the migration-cooldown cache.
type Migrator struct {
	aws           *AWSClient
	kms           *KMS
	staticSecrets *StaticSecrets
	storage       *Storage
	auth          func(http.ResponseWriter, *http.Request) bool

	// 5s SSM cache so /v1/enclave-info doesn't hammer the API.
	cooldownMu        sync.Mutex
	cooldownPending   bool
	cooldownRemaining int
	cooldownFetchedAt time.Time
}

func NewMigrator(aws *AWSClient, kms *KMS, static *StaticSecrets, storage *Storage, auth func(http.ResponseWriter, *http.Request) bool) *Migrator {
	return &Migrator{
		aws:           aws,
		kms:           kms,
		staticSecrets: static,
		storage:       storage,
		auth:          auth,
	}
}

func (m *Migrator) RegisterRoutes(mux Mux) {
	mux.HandleFunc("POST /v1/start-migration", m.handleStartMigration)
}

func (m *Migrator) ReadPreviousPCR0(ctx context.Context) (string, error) {
	return readSSMParam(ctx, m.aws.SSM, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", getDeployment(), getAppName()))
}

func (m *Migrator) ReadPreviousPCR0Attestation(ctx context.Context) (string, error) {
	return readSSMParam(ctx, m.aws.SSM, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0Attestation", getDeployment(), getAppName()))
}

func (m *Migrator) GetPreviousPCR0Info(ctx context.Context) (*PreviousPCR0Info, error) {
	pcr0, err := m.ReadPreviousPCR0(ctx)
	if err != nil {
		return nil, err
	}
	attest, err := m.ReadPreviousPCR0Attestation(ctx)
	if err != nil {
		return nil, err
	}
	return &PreviousPCR0Info{PCR0: pcr0, Attestation: attest}, nil
}

func (m *Migrator) CooldownStatus(ctx context.Context) (configuredSeconds, remaining int, pending bool) {
	cooldown := getMigrationCooldown()
	configuredSeconds = int(cooldown.Seconds())

	m.cooldownMu.Lock()
	if time.Since(m.cooldownFetchedAt) < 5*time.Second {
		rem := m.cooldownRemaining
		pend := m.cooldownPending
		m.cooldownMu.Unlock()
		return configuredSeconds, rem, pend
	}
	m.cooldownMu.Unlock()

	if m.aws == nil {
		return configuredSeconds, 0, false
	}
	deployment := getDeployment()
	appName := getAppName()

	requestedAtStr, err := readSSMParam(ctx, m.aws.SSM, fmt.Sprintf("/%s/%s/MigrationRequestedAt", deployment, appName))
	if err != nil || requestedAtStr == "" {
		m.cooldownMu.Lock()
		m.cooldownPending = false
		m.cooldownRemaining = 0
		m.cooldownFetchedAt = time.Now()
		m.cooldownMu.Unlock()
		return configuredSeconds, 0, false
	}

	requestedAt, err := time.Parse(time.RFC3339, requestedAtStr)
	if err != nil {
		return configuredSeconds, 0, false
	}

	deadline := requestedAt.Add(cooldown)
	rem := time.Until(deadline)
	if rem < 0 {
		rem = 0
	}

	m.cooldownMu.Lock()
	m.cooldownPending = true
	m.cooldownRemaining = int(rem.Seconds())
	m.cooldownFetchedAt = time.Now()
	m.cooldownMu.Unlock()

	return configuredSeconds, int(rem.Seconds()), true
}

// handleStartMigration mints the migration key PCR0-locked at birth, re-encrypts
// secrets + DEK into its key-scoped SSM paths, verifies them, then flips
// KMSKeyID (one atomic write) and schedules the old key for deletion.
func (m *Migrator) handleStartMigration(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewPCR0 string `json:"new_pcr0"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NewPCR0 == "" {
		http.Error(w, "new_pcr0 is required in request body", http.StatusBadRequest)
		return
	}
	if len(req.NewPCR0) != 96 {
		http.Error(w, "new_pcr0 must be 96 hex characters (SHA-384)", http.StatusBadRequest)
		return
	}
	if _, err := hex.DecodeString(req.NewPCR0); err != nil {
		http.Error(w, "new_pcr0 must be valid hex", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	deployment := getDeployment()
	appName := getAppName()

	ownPCR0 := getPCR0()
	if ownPCR0 == "" {
		http.Error(w, "could not read own PCR0 from NSM", http.StatusInternalServerError)
		return
	}

	// Commit PCR31 before any KMSKeyID/ciphertext writes: a retry at a different
	// target then fails here, leaving the live key untouched.
	newPCR0Bytes, _ := hex.DecodeString(req.NewPCR0)
	if err := commitPCR31(req.NewPCR0, newPCR0Bytes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Mint the migration key with the final PCR0-locked policy in one call.
	// No external principal ever holds authority over the key.
	migrationKeyID, err := m.kms.CreateMigrationKey(ctx, ownPCR0, req.NewPCR0)
	if err != nil {
		http.Error(w, fmt.Sprintf("create migration key: %v", err), http.StatusInternalServerError)
		return
	}
	slog.Info("created migration KMS key", "key_id", migrationKeyID, "own_pcr0", prefix16(ownPCR0), "new_pcr0", prefix16(req.NewPCR0))

	committed := false
	defer func() {
		if committed {
			return
		}
		pendingDays := keyDeletionPendingDays
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, derr := m.aws.KMS.ScheduleKeyDeletion(cleanupCtx, &kms.ScheduleKeyDeletionInput{
			KeyId:               aws.String(migrationKeyID),
			PendingWindowInDays: &pendingDays,
		}); derr != nil {
			slog.Warn("schedule unused migration key for deletion failed", "key_id", migrationKeyID, "error", derr)
		} else {
			slog.Info("scheduled unused migration key for deletion (handleStartMigration failed before commit)", "key_id", migrationKeyID)
		}
	}()

	type encryptedSecret struct {
		name          string
		keyBytes      []byte
		ciphertextB64 string
	}
	var encryptedSecrets []encryptedSecret
	for _, secret := range m.staticSecrets.Secrets() {
		secretValue := os.Getenv(secret.EnvVar)
		if secretValue == "" {
			continue
		}
		keyBytes, err := hex.DecodeString(secretValue)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid key format for %s", secret.Name), http.StatusInternalServerError)
			return
		}
		ciphertextB64, err := m.kms.Encrypt(ctx, migrationKeyID, keyBytes)
		if err != nil {
			http.Error(w, fmt.Sprintf("KMS encrypt failed for %s", secret.Name), http.StatusInternalServerError)
			return
		}
		ciphertextParam := secretCiphertextParam(secret.Name, migrationKeyID)
		if err := m.kms.StoreCiphertext(ctx, ciphertextParam, ciphertextB64); err != nil {
			http.Error(w, fmt.Sprintf("SSM store failed for %s", secret.Name), http.StatusInternalServerError)
			return
		}
		encryptedSecrets = append(encryptedSecrets, encryptedSecret{
			name:          secret.Name,
			keyBytes:      keyBytes,
			ciphertextB64: ciphertextB64,
		})
	}

	if err := m.storage.ExportDEK(ctx, migrationKeyID); err != nil {
		http.Error(w, fmt.Sprintf("storage DEK export failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Verify before commit: ownPCR0 is in the policy, so we can decrypt our own writes.
	for _, es := range encryptedSecrets {
		decrypted, err := decryptDEK(ctx, m.kms.aws.KMS, migrationKeyID, es.ciphertextB64)
		if err != nil {
			http.Error(w, fmt.Sprintf("verify: decrypt failed for %s: %v", es.name, err), http.StatusInternalServerError)
			return
		}
		if !bytes.Equal(decrypted, es.keyBytes) {
			http.Error(w, fmt.Sprintf("verify: ciphertext mismatch for %s", es.name), http.StatusInternalServerError)
			return
		}
	}

	// Record this enclave as the next one's predecessor (with attestation)
	// before flipping KMSKeyID, so a failure here leaves nothing committed.
	pcr0, _, err := storePCR0WithAttestation(ctx, m.aws.SSM, deployment, appName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	oldKeyID, _ := m.kms.GetKeyID(ctx) // for deletion below

	// Atomic commit: from here, all boots use the migration key.
	if _, err := m.aws.SSM.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(fmt.Sprintf("/%s/%s/KMSKeyID", deployment, appName)),
		Value:     aws.String(migrationKeyID),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	}); err != nil {
		http.Error(w, fmt.Sprintf("update KMSKeyID: %v", err), http.StatusInternalServerError)
		return
	}
	committed = true
	slog.Info("KMSKeyID updated to migration key", "key_id", migrationKeyID)

	// Schedule old key for deletion (best-effort — failure is non-fatal).
	if oldKeyID != "" && oldKeyID != migrationKeyID {
		pendingDays := keyDeletionPendingDays
		if _, err := m.aws.KMS.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
			KeyId:               aws.String(oldKeyID),
			PendingWindowInDays: &pendingDays,
		}); err != nil {
			slog.Warn("schedule old key deletion failed", "key_id", oldKeyID, "error", err)
		} else {
			slog.Info("scheduled old KMS key for deletion", "key_id", oldKeyID, "pending_days", keyDeletionPendingDays)
		}
	}

	var exportedNames []string
	for _, es := range encryptedSecrets {
		exportedNames = append(exportedNames, es.name)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		PCR0     string   `json:"pcr0"`
		Exported []string `json:"exported"`
	}{
		PCR0:     pcr0,
		Exported: exportedNames,
	})
}

// storePCR0WithAttestation writes the old enclave's PCR0 and attestation doc
// directly to MigrationPreviousPCR0 / MigrationPreviousPCR0Attestation.
func storePCR0WithAttestation(ctx context.Context, ssmClient SSMAPI, deployment, appName string) (string, string, error) {
	pcr0 := getPCR0()
	if pcr0 == "" {
		return "", "", fmt.Errorf("could not read PCR0 from NSM")
	}

	pcr0Param := fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", deployment, appName)
	if _, err := ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(pcr0Param),
		Value:     aws.String(pcr0),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	}); err != nil {
		return "", "", fmt.Errorf("store PCR0 in SSM: %w", err)
	}

	attestDocB64, err := getAttestationDocumentB64()
	if err != nil {
		return "", "", fmt.Errorf("generate attestation document: %w", err)
	}

	attestParam := fmt.Sprintf("/%s/%s/MigrationPreviousPCR0Attestation", deployment, appName)
	if _, err := ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(attestParam),
		Value:     aws.String(attestDocB64),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
		Tier:      ssmtypes.ParameterTierAdvanced,
	}); err != nil {
		return "", "", fmt.Errorf("store PCR0 attestation in SSM: %w", err)
	}

	return pcr0, attestDocB64, nil
}

// prefix16 truncates a hex PCR0 / KMS key ID for less noisy log fields.
func prefix16(s string) string {
	return s[:min(16, len(s))]
}

// readSSMParam returns an error if the parameter is missing or set to "UNSET".
func readSSMParam(ctx context.Context, ssmClient SSMAPI, paramName string) (string, error) {
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", fmt.Errorf("parameter %s has no value", paramName)
	}
	value := strings.TrimSpace(*out.Parameter.Value)
	if value == "" || value == "UNSET" {
		return "", fmt.Errorf("parameter %s is unset", paramName)
	}
	return value, nil
}

// readSSMParamOptional is like readSSMParam but returns ("", nil) when the
// param is missing or holds the tofu placeholder "UNSET". Real SSM errors
// (network, IAM) still propagate.
func readSSMParamOptional(ctx context.Context, ssmClient SSMAPI, paramName string) (string, error) {
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		var pnf *ssmtypes.ParameterNotFound
		if errors.As(err, &pnf) {
			return "", nil
		}
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", nil
	}
	v := strings.TrimSpace(*out.Parameter.Value)
	if v == "" || v == "UNSET" {
		return "", nil
	}
	return v, nil
}

func getPCR0() string {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return ""
	}
	defer func() { _ = session.Close() }()

	attestDoc, _, err := buildAttestationDocument(session)
	if err != nil {
		return ""
	}

	pcr0, err := extractPCR0FromAttestation(attestDoc)
	if err != nil {
		return ""
	}
	return pcr0
}

// commitPCR31 extends PCR31 with newPCR0 and locks it, binding the handoff
// into the attestation. Idempotent within an enclave instance: if PCR31
// already holds SHA384(zeros‖newPCR0) it only ensures the lock; if PCR31 holds
// any other non-zero value (e.g. a prior start-migration aimed at a different
// target) it errors rather than corrupting the register.
func commitPCR31(newPCR0Hex string, newPCR0Bytes []byte) error {
	want := sha512.Sum384(append(make([]byte, 48), newPCR0Bytes...))
	cur, locked, err := describePCR(migrationPCRIndex)
	if err != nil {
		return fmt.Errorf("describePCR(%d): %w", migrationPCRIndex, err)
	}
	switch {
	case bytes.Equal(cur, want[:]):
		if !locked {
			if err := lockPCR(migrationPCRIndex); err != nil {
				return fmt.Errorf("lock PCR%d: %w", migrationPCRIndex, err)
			}
		}
		slog.Info("PCR31 already committed to new_pcr0, skipped re-extension", "new_pcr0", prefix16(newPCR0Hex))
		return nil
	case !bytes.Equal(cur, make([]byte, len(cur))):
		return fmt.Errorf("PCR%d holds an unexpected value; reboot the enclave to retry migration", migrationPCRIndex)
	}
	if err := extendPCR(migrationPCRIndex, newPCR0Bytes); err != nil {
		return fmt.Errorf("extend PCR%d with new_pcr0: %w", migrationPCRIndex, err)
	}
	if err := lockPCR(migrationPCRIndex); err != nil {
		return fmt.Errorf("lock PCR%d: %w", migrationPCRIndex, err)
	}
	return nil
}

// VerifyPredecessorCommitment checks that the previous enclave's stored
// attestation document committed (via PCR31) to handing off to ownPCR0.
// No-op when there's no predecessor (genesis), or when the chain entry
// points at our own PCR0 — that's the rolled-back-onto-self case: this
// enclave wrote the attestation before a failed migration, and its PCR31
// commits to the failed target rather than to itself.
func (m *Migrator) VerifyPredecessorCommitment(ctx context.Context, ownPCR0 string) error {
	deployment := getDeployment()
	appName := getAppName()
	prevPCR0, err := readSSMParamOptional(ctx, m.aws.SSM, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", deployment, appName))
	if err != nil {
		return fmt.Errorf("read previous PCR0: %w", err)
	}
	if prevPCR0 == "" || strings.EqualFold(prevPCR0, ownPCR0) {
		return nil
	}
	attestB64, err := readSSMParamOptional(ctx, m.aws.SSM, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0Attestation", deployment, appName))
	if err != nil {
		return fmt.Errorf("read previous attestation: %w", err)
	}
	if attestB64 == "" {
		return nil
	}
	return verifyPCR31Commitment(attestB64, ownPCR0)
}

// verifyPCR31Commitment: nil iff the previous enclave's attestation document
// committed to handing off to THIS enclave's PCR0 (by extending PCR31).
func verifyPCR31Commitment(attestDocB64, myPCR0 string) error {
	attestDoc, err := base64.StdEncoding.DecodeString(attestDocB64)
	if err != nil {
		return fmt.Errorf("decode attestation base64: %w", err)
	}
	pcr31, err := extractPCRFromAttestation(attestDoc, migrationPCRIndex)
	if err != nil {
		return fmt.Errorf("extract PCR%d: %w", migrationPCRIndex, err)
	}
	myPCR0Bytes, err := hex.DecodeString(myPCR0)
	if err != nil {
		return fmt.Errorf("decode own PCR0 hex: %w", err)
	}
	expected := sha512.Sum384(append(make([]byte, 48), myPCR0Bytes...))
	if !bytes.Equal(pcr31, expected[:]) {
		return fmt.Errorf("PCR%d mismatch: previous enclave committed to a different target PCR0", migrationPCRIndex)
	}
	return nil
}
