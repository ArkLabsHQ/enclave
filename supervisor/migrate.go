package supervisor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const eifPath = "/home/ec2-user/app/server/enclave.eif"
const supervisorBinaryPath = "/home/ec2-user/app/supervisor"

// Migration drives the 11-step locked-key KMS migration handshake (and
// the optional supervisor self-update tail) plus /schedule-key-deletion.
// Calls requestShutdown after a successful self-update so the composer
// can hand off to the new binary.
type Migration struct {
	aws       *AWSClient
	lifecycle *Lifecycle
	cooldown  time.Duration

	migrateMu sync.Mutex // serialises /migrate

	abortMu sync.Mutex
	abortCh chan struct{} // open during cooldown; closed by /migrate/abort

	requestShutdown func() // signals Supervisor to shut down after a self-update
}

func NewMigration(aws *AWSClient, lifecycle *Lifecycle, cooldown time.Duration, requestShutdown func()) *Migration {
	return &Migration{
		aws:             aws,
		lifecycle:       lifecycle,
		cooldown:        cooldown,
		requestShutdown: requestShutdown,
	}
}

func (m *Migration) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /migrate", m.handleMigrate)
	mux.HandleFunc("POST /migrate/abort", m.handleMigrateAbort)
	mux.HandleFunc("POST /schedule-key-deletion", m.handleScheduleKeyDeletion)
}

// InProgress reports whether a /migrate request is currently running.
func (m *Migration) InProgress() bool {
	if !m.migrateMu.TryLock() {
		return true
	}
	m.migrateMu.Unlock()
	return false
}

type migrateRequest struct {
	EIFBucket              string   `json:"eif_bucket"`
	EIFKey                 string   `json:"eif_key"`
	PCR0                   string   `json:"pcr0"`
	SecretNames            []string `json:"secret_names"`
	SupervisorBinaryBucket string   `json:"supervisor_binary_bucket,omitempty"`
	SupervisorBinaryKey    string   `json:"supervisor_binary_key,omitempty"`
}

type migrateStatus struct {
	Step    int    `json:"step"`
	Total   int    `json:"total"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

func (m *Migration) handleMigrate(w http.ResponseWriter, r *http.Request) {
	if !m.migrateMu.TryLock() {
		http.Error(w, `{"error":"migration already in progress"}`, http.StatusConflict)
		return
	}
	defer m.migrateMu.Unlock()

	ctx := r.Context()

	var req migrateRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid request: %v"}`, err), http.StatusBadRequest)
		return
	}
	if req.EIFBucket == "" || req.EIFKey == "" || req.PCR0 == "" {
		http.Error(w, `{"error":"eif_bucket, eif_key, and pcr0 are required"}`, http.StatusBadRequest)
		return
	}
	if len(req.SecretNames) == 0 {
		http.Error(w, `{"error":"secret_names is required"}`, http.StatusBadRequest)
		return
	}
	if (req.SupervisorBinaryBucket == "") != (req.SupervisorBinaryKey == "") {
		http.Error(w, `{"error":"supervisor_binary_bucket and supervisor_binary_key must be set together"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	totalSteps := 11
	emit := func(step int, status, msg string) {
		slog.Info("migrate step", "step", step, "total", totalSteps, "status", status, "msg", msg)
		_ = json.NewEncoder(w).Encode(migrateStatus{
			Step:    step,
			Total:   totalSteps,
			Status:  status,
			Message: msg,
		})
		if flusher != nil {
			flusher.Flush()
		}
	}

	emitErr := func(step int, msg string) {
		emit(step, "error", msg)
	}

	// Step 0: Cooldown period (if configured).
	if m.cooldown > 0 {
		requestedAt := time.Now().UTC()
		if err := m.putParam(ctx, "MigrationRequestedAt", requestedAt.Format(time.RFC3339)); err != nil {
			emitErr(0, fmt.Sprintf("store MigrationRequestedAt: %v", err))
			return
		}

		m.abortMu.Lock()
		m.abortCh = make(chan struct{})
		abortCh := m.abortCh
		m.abortMu.Unlock()

		emit(0, "cooldown", fmt.Sprintf("Migration cooldown: %s (abort via POST /migrate/abort)", m.cooldown))
		deadline := requestedAt.Add(m.cooldown)

		// Scale tick interval: 1min for cooldowns > 1h, 10s otherwise.
		tickInterval := 10 * time.Second
		if m.cooldown > time.Hour {
			tickInterval = time.Minute
		}
		ticker := time.NewTicker(tickInterval)
		defer ticker.Stop()

		aborted := false
		for time.Now().UTC().Before(deadline) {
			select {
			case <-abortCh:
				aborted = true
			case <-ctx.Done():
				aborted = true
			case <-ticker.C:
			}
			if aborted {
				break
			}
			remaining := time.Until(deadline).Round(time.Second)
			emit(0, "cooldown", fmt.Sprintf("Cooldown: %s remaining", remaining))
		}

		m.resetParam(ctx, "MigrationRequestedAt")

		m.abortMu.Lock()
		m.abortCh = nil
		m.abortMu.Unlock()

		if aborted {
			emit(0, "aborted", "Migration aborted during cooldown")
			return
		}
		emit(0, "cooldown", "Cooldown expired, proceeding with migration")
	}

	// Step 1: Read current KMS key ID from SSM.
	emit(1, "progress", "Reading current KMS key ID...")
	oldKMSKeyID, err := m.getParam(ctx, "KMSKeyID")
	if err != nil || oldKMSKeyID == "" {
		emitErr(1, fmt.Sprintf("KMSKeyID not found in SSM: %v", err))
		return
	}

	// Idempotency: a previous attempt may have left a MigrationKMSKeyID.
	var newKMSKeyID string
	resuming := false
	existingMigKey, _ := m.getParam(ctx, "MigrationKMSKeyID")
	if existingMigKey != "" {
		newKMSKeyID = existingMigKey
		resuming = true
		emit(1, "progress", fmt.Sprintf("Resuming previous migration with key: %s", newKMSKeyID))
	} else {
		// Step 2: Create new KMS key.
		emit(2, "progress", "Creating migration KMS key...")
		pcr0Short := req.PCR0
		if len(pcr0Short) > 16 {
			pcr0Short = pcr0Short[:16]
		}
		out, err := m.aws.KMS.CreateKey(ctx, &kms.CreateKeyInput{
			Description: aws.String(fmt.Sprintf("migration key for PCR0 %s...", pcr0Short)),
		})
		if err != nil {
			emitErr(2, fmt.Sprintf("create KMS key: %v", err))
			return
		}
		newKMSKeyID = *out.KeyMetadata.KeyId
		emit(2, "progress", fmt.Sprintf("Created KMS key: %s", newKMSKeyID))
	}

	// rollbackKey schedules the newly created KMS key for deletion on
	// failure. Skipped when resuming (key was already persisted).
	rollbackKey := func() {
		if resuming {
			return
		}
		pendingDays := int32(7)
		if _, err := m.aws.KMS.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
			KeyId:               aws.String(newKMSKeyID),
			PendingWindowInDays: &pendingDays,
		}); err != nil {
			slog.Warn("failed to schedule orphaned key for deletion", "key_id", newKMSKeyID, "error", err)
		} else {
			slog.Info("scheduled orphaned key for deletion", "key_id", newKMSKeyID, "pending_days", 7)
		}
		m.resetParam(ctx, "MigrationKMSKeyID")
		m.resetParam(ctx, "MigrationTargetPCR0")
	}

	// Step 3: Apply transitional KMS policy.
	emit(3, "progress", "Applying transitional KMS policy...")
	roleARN, accountID, err := m.getCallerRole(ctx)
	if err != nil {
		rollbackKey()
		emitErr(3, fmt.Sprintf("get caller identity: %v", err))
		return
	}
	policy := buildTransitionalPolicy(roleARN, fmt.Sprintf("arn:aws:iam::%s:root", accountID))
	_, err = m.aws.KMS.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{
		KeyId:      aws.String(newKMSKeyID),
		Policy:     aws.String(policy),
		PolicyName: aws.String("default"),
	})
	if err != nil {
		rollbackKey()
		emitErr(3, fmt.Sprintf("apply transitional policy: %v", err))
		return
	}
	emit(3, "progress", "Transitional KMS policy applied")

	// Step 4: Store migration parameters in SSM.
	// MigrationTargetPCR0 is written before MigrationKMSKeyID — the latter
	// is the "in progress" flag the enclave-side classifier gates on.
	emit(4, "progress", "Storing migration parameters in SSM...")
	if err := m.putParam(ctx, "MigrationTargetPCR0", req.PCR0); err != nil {
		rollbackKey()
		emitErr(4, fmt.Sprintf("store MigrationTargetPCR0: %v", err))
		return
	}
	if err := m.putParam(ctx, "MigrationKMSKeyID", newKMSKeyID); err != nil {
		rollbackKey()
		emitErr(4, fmt.Sprintf("store MigrationKMSKeyID: %v", err))
		return
	}
	if err := m.putParam(ctx, "MigrationOldKMSKeyID", oldKMSKeyID); err != nil {
		rollbackKey()
		emitErr(4, fmt.Sprintf("store MigrationOldKMSKeyID: %v", err))
		return
	}
	emit(4, "progress", "Migration KMS key IDs stored in SSM")

	// Step 5: Call start-migration on the running enclave.
	// The enclave replaces the transitional policy with the final
	// PCR0-locked one (targeting the new enclave's PCR0) before encrypting
	// any secret under this key, so no decryptable ciphertext can exist
	// under a policy mutable by supervisor.
	emit(5, "progress", "Calling start-migration on old enclave...")
	if err := m.callStartMigration(ctx, newKMSKeyID, req.PCR0); err != nil {
		rollbackKey()
		emitErr(5, fmt.Sprintf("start-migration failed: %v", err))
		return
	}
	emit(5, "progress", "Start-migration succeeded")

	// Step 6: Poll for migration ciphertexts.
	emit(6, "progress", "Waiting for migration ciphertexts...")
	if err := m.pollMigrationCiphertexts(ctx, req.SecretNames); err != nil {
		rollbackKey()
		emitErr(6, fmt.Sprintf("poll ciphertexts: %v", err))
		return
	}
	emit(6, "progress", fmt.Sprintf("All %d migration ciphertexts found", len(req.SecretNames)))

	// Step 7: Back up old EIF, then download new EIF + swap.
	// Ordering is critical: download → stop → swap → start. Any failure
	// before "start new" leaves the old enclave alive and retry-safe.
	eifDest := envOrDefault("ENCLAVE_EIF_PATH", eifPath)
	eifBackup := eifDest + ".backup"
	stopCmd := os.Getenv("ENCLAVE_STOP_CMD")
	startCmd := os.Getenv("ENCLAVE_START_CMD")

	emit(7, "progress", "Backing up old EIF...")
	if err := copyFile(eifDest, eifBackup); err != nil {
		rollbackKey()
		emitErr(7, fmt.Sprintf("backup old EIF: %v", err))
		return
	}

	emit(7, "progress", "Downloading new EIF from S3...")
	tmpEIF := "/tmp/new-enclave.eif"
	if err := m.downloadS3Object(ctx, req.EIFBucket, req.EIFKey, tmpEIF); err != nil {
		_ = os.Remove(eifBackup)
		rollbackKey()
		emitErr(7, fmt.Sprintf("download EIF: %v", err))
		return
	}

	// Step 8: Stop old enclave, swap EIF, start new enclave.
	emit(8, "progress", "Stopping old enclave...")
	if err := m.lifecycle.Stop(ctx, stopCmd); err != nil {
		slog.Warn("stop command failed", "error", err)
		emit(8, "progress", fmt.Sprintf("Stop returned error (continuing): %v", err))
	}

	emit(8, "progress", fmt.Sprintf("Replacing EIF at %s...", eifDest))
	if err := os.Rename(tmpEIF, eifDest); err != nil {
		if cpErr := copyFile(tmpEIF, eifDest); cpErr != nil {
			// Restore backup since we've already stopped the old enclave.
			_ = os.Rename(eifBackup, eifDest)
			_ = m.lifecycle.Start(ctx, startCmd)
			rollbackKey()
			emitErr(8, fmt.Sprintf("replace EIF: %v", cpErr))
			return
		}
	}

	emit(8, "progress", "Starting new enclave...")
	if err := m.lifecycle.Start(ctx, startCmd); err != nil {
		emitErr(8, fmt.Sprintf("start enclave: %v", err))
		m.rollbackMigration(ctx, eifDest, eifBackup, stopCmd, startCmd, newKMSKeyID, emit)
		return
	}
	emit(8, "progress", "New enclave started; waiting for Init to commit...")

	// Step 9: Wait for new enclave to commit migration. Init() copies
	// Migration/* → primary then clears MigrationKMSKeyID. Two success
	// indicators:
	//   (a) MigrationKMSKeyID cleared in SSM (authoritative commit)
	//   (b) /health returns 200 (enclave's own IsReady() = initOK)
	// Both required; either failing within timeout = rollback.
	commitTimeout := 5 * time.Minute
	if v := envOrDefault("ENCLAVE_MIGRATION_COMMIT_TIMEOUT", ""); v != "" {
		if d, perr := time.ParseDuration(v); perr == nil && d > 0 {
			commitTimeout = d
		}
	}
	emit(9, "progress", fmt.Sprintf("Polling for new enclave to commit migration (timeout: %s)...", commitTimeout))
	if err := m.waitForMigrationCommit(ctx, commitTimeout); err != nil {
		emitErr(9, fmt.Sprintf("commit timeout: %v", err))
		m.rollbackMigration(ctx, eifDest, eifBackup, stopCmd, startCmd, newKMSKeyID, emit)
		return
	}
	emit(9, "progress", "Migration committed by new enclave")

	// Step 10: Post-commit cleanup. Supervisor only removes host-local artifacts.
	emit(10, "progress", "Removing EIF backup...")
	_ = os.Remove(eifBackup)
	emit(10, "progress", "Host-side cleanup done")

	// Step 11: Optional supervisor binary update. Download → validate →
	// rename → signal exit. If validate fails we keep the old supervisor.
	exitAfter := false
	if req.SupervisorBinaryBucket != "" && req.SupervisorBinaryKey != "" {
		emit(11, "progress", "Updating supervisor binary...")
		if err := m.atomicSupervisorUpdate(ctx, req.SupervisorBinaryBucket, req.SupervisorBinaryKey); err != nil {
			emit(11, "warn", fmt.Sprintf("supervisor binary update failed, old supervisor still running: %v", err))
		} else {
			exitAfter = true
			emit(11, "progress", "supervisor update ready — old supervisor will exit after this response")
		}
	}

	emit(11, "complete", fmt.Sprintf("Migration complete. New KMS key: %s", newKMSKeyID))

	if exitAfter && m.requestShutdown != nil {
		m.requestShutdown()
	}
}

// waitForMigrationCommit polls SSM + /health until MigrationKMSKeyID is
// cleared AND /health returns 200 (belt-and-suspenders). Errors on timeout.
func (m *Migration) waitForMigrationCommit(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	pollInterval := 5 * time.Second

	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for time.Now().Before(deadline) {
		val, _ := m.getParam(ctx, "MigrationKMSKeyID")
		if val == "" {
			resp, err := client.Get(enclaveURL + "/health")
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
	return fmt.Errorf("migration did not commit within %s", timeout)
}

// rollbackMigration restores the old EIF and restarts the old enclave.
// Migration SSM flags stay set so the restarted enclave's Init can run
// AbortOrphaned, which clears the in-flight flags + the staging chain
// proof (Migration/PreviousPCR0, Migration/PreviousPCR0Attestation) that
// the failed start-migration wrote. Primary chain keys (MigrationPreviousPCR0,
// MigrationPreviousPCR0Attestation) are untouched, so the rolled-back
// enclave's /v1/enclave-info still reports the true predecessor.
func (m *Migration) rollbackMigration(ctx context.Context, eifDest, eifBackup, stopCmd, startCmd, failedKeyID string, emit func(step int, status, msg string)) {
	emit(9, "rollback", "Initiating rollback...")

	emit(9, "rollback", "Stopping failed new enclave...")
	if err := m.lifecycle.Stop(ctx, stopCmd); err != nil {
		slog.Warn("rollback stop failed", "error", err)
	}

	emit(9, "rollback", fmt.Sprintf("Restoring old EIF from %s...", eifBackup))
	if err := os.Rename(eifBackup, eifDest); err != nil {
		if cpErr := copyFile(eifBackup, eifDest); cpErr != nil {
			emit(9, "rollback", fmt.Sprintf("CRITICAL: failed to restore EIF backup: %v", cpErr))
			return
		}
		_ = os.Remove(eifBackup)
	}

	emit(9, "rollback", "Starting old enclave...")
	if err := m.lifecycle.Start(ctx, startCmd); err != nil {
		emit(9, "rollback", fmt.Sprintf("CRITICAL: failed to start old enclave: %v", err))
		return
	}

	pendingDays := int32(7)
	if _, err := m.aws.KMS.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId:               aws.String(failedKeyID),
		PendingWindowInDays: &pendingDays,
	}); err != nil {
		slog.Warn("rollback: schedule failed migration key deletion", "key_id", failedKeyID, "error", err)
	}

	emit(9, "rollback-complete", "Rollback complete; old enclave restored")
}

// atomicSupervisorUpdate swaps the supervisor binary; systemd relaunches
// us with the new code. Trust model: if the new binary passes
// ENCLAVE_SUPERVISOR_VALIDATE=1, it's good enough. No rollback — the rare
// "validate passed but bind fails" case is fixable by redeploying from S3.
func (m *Migration) atomicSupervisorUpdate(ctx context.Context, bucket, key string) error {
	binPath := envOrDefault("ENCLAVE_SUPERVISOR_BINARY_PATH", supervisorBinaryPath)
	stagePath := binPath + ".new"

	if err := m.downloadS3Object(ctx, bucket, key, stagePath); err != nil {
		return fmt.Errorf("download supervisor binary: %w", err)
	}
	if err := os.Chmod(stagePath, 0o755); err != nil {
		_ = os.Remove(stagePath)
		return fmt.Errorf("chmod supervisor binary: %w", err)
	}

	validateCmd := exec.CommandContext(ctx, stagePath)
	validateCmd.Env = append(os.Environ(), "ENCLAVE_SUPERVISOR_VALIDATE=1")
	if out, err := validateCmd.CombinedOutput(); err != nil {
		_ = os.Remove(stagePath)
		return fmt.Errorf("validate new supervisor binary: %w (output: %s)", err, out)
	}

	if err := os.Rename(stagePath, binPath); err != nil {
		_ = os.Remove(stagePath)
		return fmt.Errorf("promote new supervisor binary: %w", err)
	}
	return nil
}

func (m *Migration) callStartMigration(ctx context.Context, migrationKeyID, newPCR0 string) error {
	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	body := fmt.Sprintf(`{"migration_key_id":%q,"new_pcr0":%q}`, migrationKeyID, newPCR0)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enclaveURL+"/v1/start-migration", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("start-migration returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (m *Migration) pollMigrationCiphertexts(ctx context.Context, secretNames []string) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var missing []string
		for _, name := range secretNames {
			ct, _ := m.getParam(ctx, "Migration/"+name+"/Ciphertext")
			if ct == "" {
				missing = append(missing, name)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	var missing []string
	for _, name := range secretNames {
		ct, _ := m.getParam(ctx, "Migration/"+name+"/Ciphertext")
		if ct == "" {
			missing = append(missing, name)
		}
	}
	return fmt.Errorf("timed out waiting for migration ciphertexts (missing: %s)", strings.Join(missing, ", "))
}

func (m *Migration) handleMigrateAbort(w http.ResponseWriter, r *http.Request) {
	m.abortMu.Lock()
	ch := m.abortCh
	m.abortMu.Unlock()

	if ch == nil {
		http.Error(w, `{"error":"no migration in cooldown"}`, http.StatusConflict)
		return
	}

	select {
	case <-ch:
		http.Error(w, `{"error":"migration already past cooldown or aborted"}`, http.StatusConflict)
	default:
		close(ch)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "aborted",
			"message": "migration cooldown aborted",
		})
	}
}

type deletionResponse struct {
	KeyID       string `json:"key_id"`
	PendingDays int    `json:"pending_window_days"`
}

func (m *Migration) handleScheduleKeyDeletion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	kmsParam := ssmParamPath("KMSKeyID")
	kmsOut, err := m.aws.SSM.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(kmsParam),
		WithDecryption: aws.Bool(false),
	})
	if err != nil || kmsOut.Parameter == nil || kmsOut.Parameter.Value == nil {
		slog.Error("read KMSKeyID from SSM failed", "error", err)
		http.Error(w, "KMS key ID not found", http.StatusInternalServerError)
		return
	}
	keyID := strings.TrimSpace(*kmsOut.Parameter.Value)
	if keyID == "" || keyID == "UNSET" {
		http.Error(w, "KMS key ID not configured", http.StatusInternalServerError)
		return
	}

	pendingDays := int32(7)
	_, err = m.aws.KMS.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId:               aws.String(keyID),
		PendingWindowInDays: &pendingDays,
	})
	if err != nil {
		slog.Error("KMS schedule-key-deletion failed", "error", err, "key_id", keyID)
		http.Error(w, fmt.Sprintf("KMS schedule-key-deletion failed: %v", err), http.StatusInternalServerError)
		return
	}

	slog.Info("KMS key scheduled for deletion", "key_id", keyID, "pending_days", 7)
	writeJSON(w, http.StatusOK, deletionResponse{
		KeyID:       keyID,
		PendingDays: 7,
	})
}

func (m *Migration) getParam(ctx context.Context, name string) (string, error) {
	out, err := m.aws.SSM.GetParameter(ctx, &ssm.GetParameterInput{
		Name: aws.String(ssmParamPath(name)),
	})
	if err != nil {
		return "", err
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", nil
	}
	v := strings.TrimSpace(*out.Parameter.Value)
	if v == "UNSET" {
		return "", nil
	}
	return v, nil
}

func (m *Migration) putParam(ctx context.Context, name, value string) error {
	_, err := m.aws.SSM.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(ssmParamPath(name)),
		Value:     aws.String(value),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	return err
}

func (m *Migration) resetParam(ctx context.Context, name string) {
	_ = m.putParam(ctx, name, "UNSET")
}

func (m *Migration) downloadS3Object(ctx context.Context, bucket, key, destPath string) error {
	out, err := m.aws.S3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("S3 GetObject: %w", err)
	}
	defer func() { _ = out.Body.Close() }()

	tmp := destPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, out.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, destPath)
}

func (m *Migration) getCallerRole(ctx context.Context) (roleARN, accountID string, err error) {
	out, err := m.aws.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", "", err
	}
	accountID = *out.Account
	roleARN = assumedRoleARNToRoleARN(*out.Arn)
	return roleARN, accountID, nil
}

// assumedRoleARNToRoleARN converts an STS assumed-role ARN to an IAM role ARN.
// e.g. arn:aws:sts::123456:assumed-role/MyRole/session → arn:aws:iam::123456:role/MyRole
func assumedRoleARNToRoleARN(arn string) string {
	if !strings.Contains(arn, ":assumed-role/") {
		return arn
	}
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return arn
	}
	resource := parts[5]
	segments := strings.Split(resource, "/")
	if len(segments) < 2 {
		return arn
	}
	roleName := segments[1]
	parts[2] = "iam"
	parts[5] = "role/" + roleName
	return strings.Join(parts[:6], ":")
}

// buildTransitionalPolicy returns a KMS key policy for locked-key migration.
// Grants Encrypt + PutKeyPolicy to the EC2 role so the running enclave can
// replace this with the final PCR0-locked policy before encrypting any
// secret. Intentionally omits Decrypt — the running enclave adds that,
// gated on the new enclave's PCR0, inside handleStartMigration.
func buildTransitionalPolicy(ec2RoleARN, accountRoot string) string {
	return fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable encrypt and self-apply from enclave",
      "Effect": "Allow",
      "Principal": {"AWS": %q},
      "Action": [
        "kms:Encrypt",
        "kms:GetKeyPolicy",
        "kms:PutKeyPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Enable key administration (no decrypt)",
      "Effect": "Allow",
      "Principal": {"AWS": %q},
      "Action": [
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListResourceTags",
        "kms:PutKeyPolicy",
        "kms:EnableKeyRotation",
        "kms:DisableKeyRotation",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
        "kms:Encrypt"
      ],
      "Resource": "*"
    }
  ]
}`, ec2RoleARN, accountRoot)
}

// copyFile copies src to dst as a fallback when rename fails (cross-device).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
