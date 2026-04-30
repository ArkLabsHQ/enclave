package runtime

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hf/nsm"
)

// migrationPCRIndex: PCR register reserved for the handoff commitment.
// During export-key, the old enclave extends this PCR with the new enclave's
// PCR0 before generating the attestation document, cryptographically binding
// "PCR0=A committed to handing off to PCR0=B" inside one NSM-signed doc.
// Chosen above 16 to avoid collision with the secret-pubkey PCRs.
const migrationPCRIndex = 31

type MigrationBootRole int

const (
	BootRoleNoMigration     MigrationBootRole = iota
	BootRoleMigrationTarget
	BootRoleAbortMigration
)

// Migrator owns migration-related SSM state, the export-key handler, and
// the migration-cooldown cache.
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
	mux.HandleFunc("POST /v1/export-key", m.handleExportKey)
}

func (m *Migrator) ReadPreviousPCR0(ctx context.Context) (string, error) {
	return readSSMParam(ctx, m.aws.SSM, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", getDeployment(), getAppName()))
}

func (m *Migrator) ReadPreviousPCR0Attestation(ctx context.Context) (string, error) {
	return readSSMParam(ctx, m.aws.SSM, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0Attestation", getDeployment(), getAppName()))
}

// ReadKMSKeyID: non-empty result means migration mode is active and Init
// should read from Migration/* staging params instead of primary.
func (m *Migrator) ReadKMSKeyID(ctx context.Context) (string, error) {
	return readSSMParam(ctx, m.aws.SSM, fmt.Sprintf("/%s/%s/MigrationKMSKeyID", getDeployment(), getAppName()))
}

func (m *Migrator) ReadTargetPCR0(ctx context.Context) (string, error) {
	return readSSMParam(ctx, m.aws.SSM, fmt.Sprintf("/%s/%s/MigrationTargetPCR0", getDeployment(), getAppName()))
}

func (m *Migrator) PutPreviousPCR0(ctx context.Context, pcr0 string) error {
	_, err := m.aws.SSM.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", getDeployment(), getAppName())),
		Value:     aws.String(pcr0),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	return err
}

func (m *Migrator) clearTargetPCR0(ctx context.Context) error {
	_, err := m.aws.SSM.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(fmt.Sprintf("/%s/%s/MigrationTargetPCR0", getDeployment(), getAppName())),
		Value:     aws.String("UNSET"),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	return err
}

func (m *Migrator) clearKMSKeyID(ctx context.Context) error {
	_, err := m.aws.SSM.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(fmt.Sprintf("/%s/%s/MigrationKMSKeyID", getDeployment(), getAppName())),
		Value:     aws.String("UNSET"),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	return err
}

// clearOldKMSKeyID prevents DeleteOldKMSKey in a future successful boot
// from targeting a key from a failed migration attempt.
func (m *Migrator) clearOldKMSKeyID(ctx context.Context) error {
	_, err := m.aws.SSM.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(fmt.Sprintf("/%s/%s/MigrationOldKMSKeyID", getDeployment(), getAppName())),
		Value:     aws.String("UNSET"),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	return err
}

func (m *Migrator) clearPreviousPCR0Attestation(ctx context.Context) error {
	_, err := m.aws.SSM.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(fmt.Sprintf("/%s/%s/MigrationPreviousPCR0Attestation", getDeployment(), getAppName())),
		Value:     aws.String("UNSET"),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
		Tier:      ssmtypes.ParameterTierAdvanced,
	})
	return err
}

// PromoteToPrimary copies Migration/* ciphertexts to primary SSM params and
// clears MigrationKMSKeyID as the atomic commit. Called by the new enclave
// at the end of migration-mode Init() after all decryption succeeds.
//
// Ordering is critical: clear MigrationKMSKeyID LAST. While it's set, Init()
// reads from Migration/*; when cleared, Init() reads from primary. Each SSM
// PutParameter is atomic, and all copies use Overwrite:true — if any step
// fails, MigrationKMSKeyID stays set and the next retry re-runs idempotently.
func (m *Migrator) PromoteToPrimary(ctx context.Context, migrationKeyID string) error {
	deployment := getDeployment()
	appName := getAppName()
	ssmClient := m.aws.SSM
	secrets := m.staticSecrets.Secrets()

	// Stage 1: copy each secret's ciphertext from Migration/ to primary.
	for _, s := range secrets {
		src := fmt.Sprintf("/%s/%s/Migration/%s/Ciphertext", deployment, appName, s.Name)
		dst := fmt.Sprintf("/%s/%s/%s/Ciphertext", deployment, appName, s.Name)
		ct, err := m.kms.LoadCiphertext(ctx, src)
		if err != nil {
			return fmt.Errorf("read migration ciphertext %s: %w", s.Name, err)
		}
		if ct == "" {
			return fmt.Errorf("migration ciphertext missing at %s", src)
		}
		if err := m.kms.StoreCiphertext(ctx, dst, ct); err != nil {
			return fmt.Errorf("promote secret %s: %w", s.Name, err)
		}
	}

	// Stage 2: copy StorageDEK ciphertext if present.
	dekSrc := fmt.Sprintf("/%s/%s/Migration/StorageDEK/Ciphertext", deployment, appName)
	dekDst := fmt.Sprintf("/%s/%s/StorageDEK/Ciphertext", deployment, appName)
	dekCT, err := m.kms.LoadCiphertext(ctx, dekSrc)
	if err != nil {
		return fmt.Errorf("read migration DEK: %w", err)
	}
	if dekCT != "" {
		if err := m.kms.StoreCiphertext(ctx, dekDst, dekCT); err != nil {
			return fmt.Errorf("promote DEK: %w", err)
		}
	}

	// Stage 3: point primary KMSKeyID at the migration key.
	if _, err := ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(fmt.Sprintf("/%s/%s/KMSKeyID", deployment, appName)),
		Value:     aws.String(migrationKeyID),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	}); err != nil {
		return fmt.Errorf("promote KMSKeyID: %w", err)
	}

	// Stage 4: clear MigrationTargetPCR0.
	if err := m.clearTargetPCR0(ctx); err != nil {
		return fmt.Errorf("clear MigrationTargetPCR0: %w", err)
	}

	// Stage 5: atomic commit — clear MigrationKMSKeyID.
	if err := m.clearKMSKeyID(ctx); err != nil {
		return fmt.Errorf("commit (clear MigrationKMSKeyID): %w", err)
	}

	// Stage 6 (post-commit cleanup): clear Migration/* staging, best-effort.
	for _, s := range secrets {
		param := fmt.Sprintf("/%s/%s/Migration/%s/Ciphertext", deployment, appName, s.Name)
		if _, err := ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
			Name:      aws.String(param),
			Value:     aws.String("UNSET"),
			Type:      ssmtypes.ParameterTypeString,
			Overwrite: aws.Bool(true),
		}); err != nil {
			slog.Warn("post-commit cleanup: clear staging ciphertext failed", "param", param, "error", err)
		}
	}
	dekParam := fmt.Sprintf("/%s/%s/Migration/StorageDEK/Ciphertext", deployment, appName)
	if _, err := ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(dekParam),
		Value:     aws.String("UNSET"),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	}); err != nil {
		slog.Warn("post-commit cleanup: clear staging DEK failed", "param", dekParam, "error", err)
	}

	return nil
}

// AbortOrphaned wipes every migration-specific SSM flag and re-asserts the
// baked predecessor PCR0. Re-asserting MigrationPreviousPCR0 is safe because
// expectedPreviousPCR0 is baked into the EIF and bound to our own PCR0.
func (m *Migrator) AbortOrphaned(ctx context.Context, expectedPreviousPCR0 string) error {
	if err := m.PutPreviousPCR0(ctx, expectedPreviousPCR0); err != nil {
		return fmt.Errorf("restore MigrationPreviousPCR0: %w", err)
	}
	if err := m.clearPreviousPCR0Attestation(ctx); err != nil {
		return fmt.Errorf("clear MigrationPreviousPCR0Attestation: %w", err)
	}
	if err := m.clearOldKMSKeyID(ctx); err != nil {
		return fmt.Errorf("clear MigrationOldKMSKeyID: %w", err)
	}
	if err := m.clearTargetPCR0(ctx); err != nil {
		return fmt.Errorf("clear MigrationTargetPCR0: %w", err)
	}
	// Atomic abort commit — clearing this flips future boots out of the abort path.
	if err := m.clearKMSKeyID(ctx); err != nil {
		return fmt.Errorf("clear MigrationKMSKeyID: %w", err)
	}
	return nil
}

// DeleteOldKMSKey schedules the key in MigrationOldKMSKeyID for deletion.
// Refuses if the old-key ID matches the current primary KMSKeyID — a corrupted
// state from a failed migration could leave MigrationOldKMSKeyID pointing at
// the live primary key, and deleting it would brick the enclave.
func (m *Migrator) DeleteOldKMSKey(ctx context.Context) {
	deployment := getDeployment()
	appName := getAppName()
	ssmClient := m.aws.SSM

	oldKeyID, err := readSSMParam(ctx, ssmClient, fmt.Sprintf("/%s/%s/MigrationOldKMSKeyID", deployment, appName))
	if err != nil {
		return // no old key to delete — normal case
	}

	currentKeyID, err := m.kms.GetKeyID(ctx)
	if err != nil {
		slog.Warn("DeleteOldKMSKey: cannot read current KMSKeyID, skipping deletion for safety", "error", err)
		return
	}
	if shouldRefuseKeyDeletion(oldKeyID, currentKeyID) {
		slog.Error("DeleteOldKMSKey: MigrationOldKMSKeyID matches current KMSKeyID, refusing deletion",
			"key_id", oldKeyID)
		_, putErr := ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
			Name:      aws.String(fmt.Sprintf("/%s/%s/MigrationOldKMSKeyID", deployment, appName)),
			Value:     aws.String("UNSET"),
			Type:      ssmtypes.ParameterTypeString,
			Overwrite: aws.Bool(true),
		})
		if putErr != nil {
			slog.Warn("DeleteOldKMSKey: failed to clear stale MigrationOldKMSKeyID", "error", putErr)
		}
		return
	}

	pendingDays := int32(7)
	_, err = m.aws.KMS.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId:               aws.String(oldKeyID),
		PendingWindowInDays: &pendingDays,
	})
	if err != nil {
		slog.Warn("DeleteOldKMSKey: schedule deletion failed", "key_id", oldKeyID, "error", err)
		return
	}
	slog.Info("scheduled old KMS key for deletion", "key_id", oldKeyID, "pending_days", 7)

	_, err = ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(fmt.Sprintf("/%s/%s/MigrationOldKMSKeyID", deployment, appName)),
		Value:     aws.String("UNSET"),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		slog.Warn("DeleteOldKMSKey: clear SSM param failed", "error", err)
	}
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

// handleExportKey: exports all configured secrets re-encrypted under the
// migration KMS key. Only operates when MigrationKMSKeyID is set in SSM
// (written by the CLI). The exported ciphertexts are encrypted to the new
// KMS key, so only the new enclave can decrypt them.
func (m *Migrator) handleExportKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MigrationKeyID string `json:"migration_key_id"`
		NewPCR0        string `json:"new_pcr0"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MigrationKeyID == "" || req.NewPCR0 == "" {
		http.Error(w, "migration_key_id and new_pcr0 are required in request body", http.StatusBadRequest)
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

	migrationKeyID, err := readSSMParam(ctx, m.aws.SSM, fmt.Sprintf("/%s/%s/MigrationKMSKeyID", deployment, appName))
	if err != nil {
		http.Error(w, "migration key not configured", http.StatusPreconditionFailed)
		return
	}
	if migrationKeyID != req.MigrationKeyID {
		http.Error(w, "migration_key_id does not match", http.StatusForbidden)
		return
	}

	// Lock the migration key to the new enclave's PCR0 BEFORE encrypting.
	currentPolicy, err := m.aws.KMS.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
		KeyId:      aws.String(migrationKeyID),
		PolicyName: aws.String("default"),
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("get migration key policy: %v", err), http.StatusInternalServerError)
		return
	}
	currentPolicyText := ""
	if currentPolicy.Policy != nil {
		currentPolicyText = *currentPolicy.Policy
	}
	alreadyLocked, _ := parseKMSPolicyState(currentPolicyText, req.NewPCR0)
	if alreadyLocked {
		slog.Info("migration key already locked to target PCR0, skipping PutKeyPolicy", "key_id", migrationKeyID, "new_pcr0", prefix16(req.NewPCR0))
	} else {
		identity, err := m.aws.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			http.Error(w, fmt.Sprintf("sts get-caller-identity: %v", err), http.StatusInternalServerError)
			return
		}
		roleARN, err := assumedRoleARNToRoleARN(*identity.Arn)
		if err != nil {
			http.Error(w, fmt.Sprintf("resolve IAM role ARN: %v", err), http.StatusInternalServerError)
			return
		}
		// Migration key inherits the running build's strict-mode semantics:
		// ENCLAVE_KMS_KEY_LOCKED=true → no root recovery on the migration key.
		builder := NewKMSPolicyBuilder().ForRole(roleARN).LockedToPCR0(req.NewPCR0)
		if !kmsKeyLocked() {
			account, err := arnAccount(*identity.Arn)
			if err != nil {
				http.Error(w, fmt.Sprintf("resolve AWS account ID for recovery principal: %v", err), http.StatusInternalServerError)
				return
			}
			builder = builder.WithRootRecovery(account)
		}
		lockedPolicy := builder.Build()
		if _, err := m.aws.KMS.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{
			KeyId:                          aws.String(migrationKeyID),
			Policy:                         aws.String(lockedPolicy),
			PolicyName:                     aws.String("default"),
			BypassPolicyLockoutSafetyCheck: true,
		}); err != nil {
			http.Error(w, fmt.Sprintf("lock migration key policy: %v", err), http.StatusInternalServerError)
			return
		}
		slog.Info("applied PCR0-locked policy to migration key", "key_id", migrationKeyID, "new_pcr0", prefix16(req.NewPCR0))
	}

	var exported []string
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

		ciphertextParam := fmt.Sprintf("/%s/%s/Migration/%s/Ciphertext", deployment, appName, secret.Name)
		if err := m.kms.StoreCiphertext(ctx, ciphertextParam, ciphertextB64); err != nil {
			http.Error(w, fmt.Sprintf("SSM store failed for %s", secret.Name), http.StatusInternalServerError)
			return
		}

		exported = append(exported, secret.Name)
	}

	if err := m.storage.ExportDEK(ctx, migrationKeyID); err != nil {
		http.Error(w, fmt.Sprintf("storage DEK export failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Commit the new enclave's PCR0 into PCR31 so the attestation document
	// cryptographically binds this handoff: "I (PCR0=A) am handing off to
	// PCR0=B." PCR31 is then locked.
	newPCR0Bytes, _ := hex.DecodeString(req.NewPCR0) // already validated above
	if err := extendPCR(migrationPCRIndex, newPCR0Bytes); err != nil {
		http.Error(w, fmt.Sprintf("extend PCR%d with new_pcr0: %v", migrationPCRIndex, err), http.StatusInternalServerError)
		return
	}
	if err := lockPCR(migrationPCRIndex); err != nil {
		http.Error(w, fmt.Sprintf("lock PCR%d: %v", migrationPCRIndex, err), http.StatusInternalServerError)
		return
	}

	pcr0, _, err := storePCR0WithAttestation(ctx, m.aws.SSM, deployment, appName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp := struct {
		PCR0     string   `json:"pcr0"`
		Exported []string `json:"exported"`
	}{
		PCR0:     pcr0,
		Exported: exported,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// storePCR0WithAttestation writes both the plain PCR0 and the COSE Sign1
// attestation document in SSM at migration commit time.
func storePCR0WithAttestation(ctx context.Context, ssmClient SSMAPI, deployment, appName string) (string, string, error) {
	pcr0 := getPCR0()
	if pcr0 == "" {
		return "", "", fmt.Errorf("could not read PCR0 from NSM")
	}

	pcr0Param := fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", deployment, appName)
	_, err := ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(pcr0Param),
		Value:     aws.String(pcr0),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return "", "", fmt.Errorf("store PCR0 in SSM: %w", err)
	}

	attestDocB64, err := getAttestationDocumentB64()
	if err != nil {
		return "", "", fmt.Errorf("generate attestation document: %w", err)
	}

	attestParam := fmt.Sprintf("/%s/%s/MigrationPreviousPCR0Attestation", deployment, appName)
	_, err = ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(attestParam),
		Value:     aws.String(attestDocB64),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
		Tier:      ssmtypes.ParameterTierAdvanced,
	})
	if err != nil {
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

// classifyBootRole: empty ownPCR0 (NSM unavailable) is treated as abort,
// since we can't prove we're the target.
func classifyBootRole(migrationInProgress bool, ownPCR0, migrationTargetPCR0 string) MigrationBootRole {
	if !migrationInProgress {
		return BootRoleNoMigration
	}
	if ownPCR0 != "" && migrationTargetPCR0 != "" && ownPCR0 == migrationTargetPCR0 {
		return BootRoleMigrationTarget
	}
	return BootRoleAbortMigration
}

func shouldRefuseKeyDeletion(oldKeyID, currentKeyID string) bool {
	return oldKeyID != "" && oldKeyID == currentKeyID
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

	// NSM extend computes SHA384(old_value || data). PCR31 starts as 48 zero
	// bytes, so after one extension with new_pcr0_bytes the value is
	// SHA384(zeros_48 || new_pcr0_bytes).
	myPCR0Bytes, err := hex.DecodeString(myPCR0)
	if err != nil {
		return fmt.Errorf("decode own PCR0 hex: %w", err)
	}
	expected := sha512.Sum384(append(make([]byte, 48), myPCR0Bytes...))

	if !bytes.Equal(pcr31, expected[:]) {
		return fmt.Errorf("PCR%d mismatch: old enclave committed to a different target PCR0", migrationPCRIndex)
	}

	return nil
}
