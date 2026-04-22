package main

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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const eifPath = "/home/ec2-user/app/server/enclave.eif"
const mgmtBinaryPath = "/home/ec2-user/app/enclave-mgmt"

type migrateRequest struct {
	EIFBucket        string   `json:"eif_bucket"`
	EIFKey           string   `json:"eif_key"`
	PCR0             string   `json:"pcr0"`
	SecretNames      []string `json:"secret_names"`
	MgmtBinaryBucket string   `json:"mgmt_binary_bucket,omitempty"`
	MgmtBinaryKey    string   `json:"mgmt_binary_key,omitempty"`
}

type migrateStatus struct {
	Step    int    `json:"step"`
	Total   int    `json:"total"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

func (s *server) handleMigrate(w http.ResponseWriter, r *http.Request) {
	// Prevent concurrent migrations.
	if !s.migrateMu.TryLock() {
		http.Error(w, `{"error":"migration already in progress"}`, http.StatusConflict)
		return
	}
	defer s.migrateMu.Unlock()

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
	if (req.MgmtBinaryBucket == "") != (req.MgmtBinaryKey == "") {
		http.Error(w, `{"error":"mgmt_binary_bucket and mgmt_binary_key must be set together"}`, http.StatusBadRequest)
		return
	}

	// Set up streaming response.
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
	if s.migrationCooldown > 0 {
		requestedAt := time.Now().UTC()
		if err := s.putParam(ctx, "MigrationRequestedAt", requestedAt.Format(time.RFC3339)); err != nil {
			emitErr(0, fmt.Sprintf("store MigrationRequestedAt: %v", err))
			return
		}

		s.migrationAbortMu.Lock()
		s.migrationAbort = make(chan struct{})
		abortCh := s.migrationAbort
		s.migrationAbortMu.Unlock()

		emit(0, "cooldown", fmt.Sprintf("Migration cooldown: %s (abort via POST /migrate/abort)", s.migrationCooldown))
		deadline := requestedAt.Add(s.migrationCooldown)

		// Scale tick interval: 1min for cooldowns > 1h, 10s otherwise.
		tickInterval := 10 * time.Second
		if s.migrationCooldown > time.Hour {
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

		s.resetParam(ctx, "MigrationRequestedAt")

		s.migrationAbortMu.Lock()
		s.migrationAbort = nil
		s.migrationAbortMu.Unlock()

		if aborted {
			emit(0, "aborted", "Migration aborted during cooldown")
			return
		}
		emit(0, "cooldown", "Cooldown expired, proceeding with migration")
	}

	// Step 1: Read current KMS key ID from SSM.
	emit(1, "progress", "Reading current KMS key ID...")
	oldKMSKeyID, err := s.getParam(ctx, "KMSKeyID")
	if err != nil || oldKMSKeyID == "" {
		emitErr(1, fmt.Sprintf("KMSKeyID not found in SSM: %v", err))
		return
	}

	// Idempotency: check if a previous migration attempt left a MigrationKMSKeyID.
	var newKMSKeyID string
	resuming := false
	existingMigKey, _ := s.getParam(ctx, "MigrationKMSKeyID")
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
		out, err := s.kms.CreateKey(ctx, &kms.CreateKeyInput{
			Description: aws.String(fmt.Sprintf("migration key for PCR0 %s...", pcr0Short)),
		})
		if err != nil {
			emitErr(2, fmt.Sprintf("create KMS key: %v", err))
			return
		}
		newKMSKeyID = *out.KeyMetadata.KeyId
		emit(2, "progress", fmt.Sprintf("Created KMS key: %s", newKMSKeyID))
	}

	// rollbackKey schedules the newly created KMS key for deletion on failure.
	// Skipped when resuming a previous attempt (key was already persisted).
	rollbackKey := func() {
		if resuming {
			return
		}
		pendingDays := int32(7)
		if _, err := s.kms.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
			KeyId:               aws.String(newKMSKeyID),
			PendingWindowInDays: &pendingDays,
		}); err != nil {
			slog.Warn("failed to schedule orphaned key for deletion", "key_id", newKMSKeyID, "error", err)
		} else {
			slog.Info("scheduled orphaned key for deletion", "key_id", newKMSKeyID, "pending_days", 7)
		}
		s.resetParam(ctx, "MigrationKMSKeyID")
		s.resetParam(ctx, "MigrationTargetPCR0")
	}

	// Step 3: Apply transitional KMS policy.
	emit(3, "progress", "Applying transitional KMS policy...")
	roleARN, accountID, err := s.getCallerRole(ctx)
	if err != nil {
		rollbackKey()
		emitErr(3, fmt.Sprintf("get caller identity: %v", err))
		return
	}
	policy := buildTransitionalPolicy(roleARN, fmt.Sprintf("arn:aws:iam::%s:root", accountID))
	_, err = s.kms.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{
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
	// MigrationTargetPCR0 is written before MigrationKMSKeyID — the latter is
	// the "in progress" flag that gates the enclave-side classifier.
	emit(4, "progress", "Storing migration parameters in SSM...")
	if err := s.putParam(ctx, "MigrationTargetPCR0", req.PCR0); err != nil {
		rollbackKey()
		emitErr(4, fmt.Sprintf("store MigrationTargetPCR0: %v", err))
		return
	}
	if err := s.putParam(ctx, "MigrationKMSKeyID", newKMSKeyID); err != nil {
		rollbackKey()
		emitErr(4, fmt.Sprintf("store MigrationKMSKeyID: %v", err))
		return
	}
	if err := s.putParam(ctx, "MigrationOldKMSKeyID", oldKMSKeyID); err != nil {
		rollbackKey()
		emitErr(4, fmt.Sprintf("store MigrationOldKMSKeyID: %v", err))
		return
	}
	emit(4, "progress", "Migration KMS key IDs stored in SSM")

	// Step 5: Call export-key on the running enclave.
	// The enclave replaces the transitional policy with the final PCR0-locked
	// policy (targeting the new enclave's PCR0) before encrypting any secret
	// under this key, so no decryptable ciphertext can exist under a policy
	// mutable by mgmt.
	emit(5, "progress", "Calling export-key on old enclave...")
	if err := s.callExportKey(ctx, newKMSKeyID, req.PCR0); err != nil {
		rollbackKey()
		emitErr(5, fmt.Sprintf("export-key failed: %v", err))
		return
	}
	emit(5, "progress", "Export-key succeeded")

	// Step 6: Poll for migration ciphertexts.
	emit(6, "progress", "Waiting for migration ciphertexts...")
	if err := s.pollMigrationCiphertexts(ctx, req.SecretNames); err != nil {
		rollbackKey()
		emitErr(6, fmt.Sprintf("poll ciphertexts: %v", err))
		return
	}
	emit(6, "progress", fmt.Sprintf("All %d migration ciphertexts found", len(req.SecretNames)))

	// Step 7: Back up old EIF before swap, then download new EIF + swap.
	// Ordering: download first, then stop old, then swap, then start new.
	// If any step fails before "start new", old enclave is still alive and
	// retry is safe. After "start new", the new enclave's Init() either
	// succeeds (commit) or fails (we rollback by restoring the backup EIF).
	eifDest := envOrDefault("ENCLAVE_EIF_PATH", eifPath)
	eifBackup := eifDest + ".backup"
	stopCmd := envOrDefault("ENCLAVE_STOP_CMD", "systemctl stop enclave-watchdog")
	startCmd := envOrDefault("ENCLAVE_START_CMD", "systemctl start enclave-watchdog")

	emit(7, "progress", "Backing up old EIF...")
	if err := copyFile(eifDest, eifBackup); err != nil {
		rollbackKey()
		emitErr(7, fmt.Sprintf("backup old EIF: %v", err))
		return
	}

	emit(7, "progress", "Downloading new EIF from S3...")
	tmpEIF := "/tmp/new-enclave.eif"
	if err := s.downloadS3Object(ctx, req.EIFBucket, req.EIFKey, tmpEIF); err != nil {
		_ = os.Remove(eifBackup)
		rollbackKey()
		emitErr(7, fmt.Sprintf("download EIF: %v", err))
		return
	}

	// Step 8: Stop old enclave, swap EIF, start new enclave.
	emit(8, "progress", fmt.Sprintf("Stopping old enclave (%s)...", stopCmd))
	if out, err := exec.CommandContext(ctx, "sh", "-c", stopCmd).CombinedOutput(); err != nil {
		slog.Warn("stop command failed", "output", string(out), "error", err)
		emit(8, "progress", fmt.Sprintf("Stop returned error (continuing): %v", err))
	}

	emit(8, "progress", fmt.Sprintf("Replacing EIF at %s...", eifDest))
	if err := os.Rename(tmpEIF, eifDest); err != nil {
		if cpErr := copyFile(tmpEIF, eifDest); cpErr != nil {
			// Restore backup since we've already stopped the old enclave.
			_ = os.Rename(eifBackup, eifDest)
			_, _ = exec.CommandContext(ctx, "sh", "-c", startCmd).CombinedOutput()
			rollbackKey()
			emitErr(8, fmt.Sprintf("replace EIF: %v", cpErr))
			return
		}
	}

	emit(8, "progress", fmt.Sprintf("Starting new enclave (%s)...", startCmd))
	if out, err := exec.CommandContext(ctx, "sh", "-c", startCmd).CombinedOutput(); err != nil {
		emitErr(8, fmt.Sprintf("start enclave: %v: %s", err, out))
		s.rollbackMigration(ctx, eifDest, eifBackup, stopCmd, startCmd, newKMSKeyID, emit)
		return
	}
	emit(8, "progress", "New enclave started; waiting for Init to commit...")

	// Step 9: Wait for new enclave to commit migration.
	// The new enclave's Init() performs the atomic promotion (copy Migration/*
	// → primary, clear MigrationKMSKeyID). We poll for two success indicators:
	//   (a) MigrationKMSKeyID cleared in SSM (authoritative commit signal)
	//   (b) /health returns 200 (enclave's own IsReady() = initOK)
	// Either indicator is sufficient; both failing within timeout = rollback.
	// Timeout is configurable via ENCLAVE_MIGRATION_COMMIT_TIMEOUT (default 5min).
	commitTimeout := 5 * time.Minute
	if v := envOrDefault("ENCLAVE_MIGRATION_COMMIT_TIMEOUT", ""); v != "" {
		if d, perr := time.ParseDuration(v); perr == nil && d > 0 {
			commitTimeout = d
		}
	}
	emit(9, "progress", fmt.Sprintf("Polling for new enclave to commit migration (timeout: %s)...", commitTimeout))
	if err := s.waitForMigrationCommit(ctx, commitTimeout); err != nil {
		emitErr(9, fmt.Sprintf("commit timeout: %v", err))
		s.rollbackMigration(ctx, eifDest, eifBackup, stopCmd, startCmd, newKMSKeyID, emit)
		return
	}
	emit(9, "progress", "Migration committed by new enclave")

	// Step 10: Post-commit cleanup.  Mgmt only removes host-local artifacts here.
	emit(10, "progress", "Removing EIF backup...")
	_ = os.Remove(eifBackup)
	emit(10, "progress", "Host-side cleanup done")

	// Step 11: Optional mgmt binary update.
	//
	// Download → validate (new binary's Init runs) → rename → signal exit.
	// If validate fails we leave old mgmt running. If it succeeds we trust
	// the new binary and let the supervisor relaunch us. There is no
	// rollback: if the rare case "validate passed but :8443 bind fails"
	// happens, the operator redeploys from S3.
	exitAfter := false
	if req.MgmtBinaryBucket != "" && req.MgmtBinaryKey != "" {
		emit(11, "progress", "Updating mgmt binary...")
		if err := s.atomicMgmtUpdate(ctx, req.MgmtBinaryBucket, req.MgmtBinaryKey); err != nil {
			emit(11, "warn", fmt.Sprintf("mgmt binary update failed, old mgmt still running: %v", err))
		} else {
			exitAfter = true
			emit(11, "progress", "mgmt update ready — old mgmt will exit after this response")
		}
	}

	emit(11, "complete", fmt.Sprintf("Migration complete. New KMS key: %s", newKMSKeyID))

	if exitAfter {
		// Signal main() to gracefully shut down after the response flushes.
		// Non-blocking send so we never wedge on a full channel.
		select {
		case s.exitAfterResponse <- struct{}{}:
		default:
		}
	}
}

// waitForMigrationCommit polls SSM + /health until either:
//   - MigrationKMSKeyID is cleared ("UNSET" / empty) — enclave committed
//   - /health returns 200 AND MigrationKMSKeyID is cleared — belt-and-suspenders
//
// Returns error on timeout.
func (s *server) waitForMigrationCommit(ctx context.Context, timeout time.Duration) error {
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
		// Primary signal: MigrationKMSKeyID cleared.
		val, _ := s.getParam(ctx, "MigrationKMSKeyID")
		if val == "" {
			// Double-check /health also returns 200 (enclave fully initialized).
			resp, err := client.Get(enclaveURL + "/health")
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
			}
			// MigrationKMSKeyID cleared but enclave not yet healthy — keep polling.
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
// Called when the new enclave fails to commit within the timeout. Migration
// SSM flags are left set so the restarted old enclave's Init can run
// abortOrphanedMigration, which clears them and re-asserts MigrationPreviousPCR0.
func (s *server) rollbackMigration(ctx context.Context, eifDest, eifBackup, stopCmd, startCmd, failedKeyID string, emit func(step int, status, msg string)) {
	emit(9, "rollback", "Initiating rollback...")

	// Stop failed new enclave.
	emit(9, "rollback", fmt.Sprintf("Stopping failed new enclave (%s)...", stopCmd))
	if out, err := exec.CommandContext(ctx, "sh", "-c", stopCmd).CombinedOutput(); err != nil {
		slog.Warn("rollback stop failed", "output", string(out), "error", err)
	}

	// Restore EIF backup.
	emit(9, "rollback", fmt.Sprintf("Restoring old EIF from %s...", eifBackup))
	if err := os.Rename(eifBackup, eifDest); err != nil {
		if cpErr := copyFile(eifBackup, eifDest); cpErr != nil {
			emit(9, "rollback", fmt.Sprintf("CRITICAL: failed to restore EIF backup: %v", cpErr))
			return
		}
		_ = os.Remove(eifBackup)
	}

	emit(9, "rollback", fmt.Sprintf("Starting old enclave (%s)...", startCmd))
	if out, err := exec.CommandContext(ctx, "sh", "-c", startCmd).CombinedOutput(); err != nil {
		emit(9, "rollback", fmt.Sprintf("CRITICAL: failed to start old enclave: %v: %s", err, out))
		return
	}

	// Schedule failed migration key for deletion (locked to unreachable PCR0).
	pendingDays := int32(7)
	if _, err := s.kms.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId:               aws.String(failedKeyID),
		PendingWindowInDays: &pendingDays,
	}); err != nil {
		slog.Warn("rollback: schedule failed migration key deletion", "key_id", failedKeyID, "error", err)
	}

	emit(9, "rollback-complete", "Rollback complete; old enclave restored")
}

// atomicMgmtUpdate swaps the mgmt binary and leaves it to the supervisor to
// relaunch us with the new code. Trust model: if the new binary passes
// ENCLAVE_MGMT_VALIDATE=1 (full Init — AWS config, STS, SSM connectivity),
// it's good enough. We don't need a separate preflight, helper, rollback,
// or cross-process signal; a broken binary would have failed validate, and
// once validate passes the only remaining risk is a prod-only edge case
// that the operator can fix by redeploying from S3.
func (s *server) atomicMgmtUpdate(ctx context.Context, bucket, key string) error {
	binPath := envOrDefault("ENCLAVE_MGMT_BINARY_PATH", mgmtBinaryPath)
	stagePath := binPath + ".new"

	if err := s.downloadS3Object(ctx, bucket, key, stagePath); err != nil {
		return fmt.Errorf("download mgmt binary: %w", err)
	}
	if err := os.Chmod(stagePath, 0o755); err != nil {
		_ = os.Remove(stagePath)
		return fmt.Errorf("chmod mgmt binary: %w", err)
	}

	validateCmd := exec.CommandContext(ctx, stagePath)
	validateCmd.Env = append(os.Environ(), "ENCLAVE_MGMT_VALIDATE=1")
	if out, err := validateCmd.CombinedOutput(); err != nil {
		_ = os.Remove(stagePath)
		return fmt.Errorf("validate new mgmt binary: %w (output: %s)", err, out)
	}

	if err := os.Rename(stagePath, binPath); err != nil {
		_ = os.Remove(stagePath)
		return fmt.Errorf("promote new mgmt binary: %w", err)
	}
	return nil
}

// callExportKey calls POST /v1/export-key on the running enclave.
// The enclave URL defaults to https://127.0.0.1:443 but can be overridden
// via ENCLAVE_URL for testing (e.g. https://127.0.0.1:8443 via gvproxy).
func (s *server) callExportKey(ctx context.Context, migrationKeyID, newPCR0 string) error {
	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	body := fmt.Sprintf(`{"migration_key_id":%q,"new_pcr0":%q}`, migrationKeyID, newPCR0)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enclaveURL+"/v1/export-key", strings.NewReader(body))
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
		return fmt.Errorf("export-key returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// pollMigrationCiphertexts waits up to 60s for all migration ciphertexts to appear.
func (s *server) pollMigrationCiphertexts(ctx context.Context, secretNames []string) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var missing []string
		for _, name := range secretNames {
			ct, _ := s.getParam(ctx, "Migration/"+name+"/Ciphertext")
			if ct == "" {
				missing = append(missing, name)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	// Build list of missing ciphertexts for the error message.
	var missing []string
	for _, name := range secretNames {
		ct, _ := s.getParam(ctx, "Migration/"+name+"/Ciphertext")
		if ct == "" {
			missing = append(missing, name)
		}
	}
	return fmt.Errorf("timed out waiting for migration ciphertexts (missing: %s)", strings.Join(missing, ", "))
}

// --- AWS helpers ---

func (s *server) getParam(ctx context.Context, name string) (string, error) {
	out, err := s.ssm.GetParameter(ctx, &ssm.GetParameterInput{
		Name: aws.String(s.ssmParam(name)),
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

func (s *server) putParam(ctx context.Context, name, value string) error {
	_, err := s.ssm.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(s.ssmParam(name)),
		Value:     aws.String(value),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	return err
}

func (s *server) resetParam(ctx context.Context, name string) {
	_ = s.putParam(ctx, name, "UNSET")
}

func (s *server) downloadS3Object(ctx context.Context, bucket, key, destPath string) error {
	out, err := s.s3Client.GetObject(ctx, &s3.GetObjectInput{
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

// getCallerRole returns the IAM role ARN and account ID from STS.
func (s *server) getCallerRole(ctx context.Context) (roleARN, accountID string, err error) {
	out, err := s.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
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
	resource := parts[5] // "assumed-role/MyRole/session"
	segments := strings.Split(resource, "/")
	if len(segments) < 2 {
		return arn
	}
	roleName := segments[1]
	parts[2] = "iam" // sts → iam
	parts[5] = "role/" + roleName
	return strings.Join(parts[:6], ":")
}

// buildTransitionalPolicy returns a KMS key policy for locked-key migration.
// Grants Encrypt + PutKeyPolicy to the EC2 role (so the running enclave can
// replace this policy with the final PCR0-locked one before encrypting) and
// admin to the account root. Intentionally omits Decrypt — the running enclave
// adds that, gated on the new enclave's PCR0, inside handleExportKey.
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

// handleMigrateAbort cancels a migration that is in the cooldown phase.
func (s *server) handleMigrateAbort(w http.ResponseWriter, r *http.Request) {
	s.migrationAbortMu.Lock()
	ch := s.migrationAbort
	s.migrationAbortMu.Unlock()

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
