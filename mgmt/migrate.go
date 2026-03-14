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
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const eifPath = "/home/ec2-user/app/server/enclave.eif"

type migrateRequest struct {
	EIFBucket   string   `json:"eif_bucket"`
	EIFKey      string   `json:"eif_key"`
	PCR0        string   `json:"pcr0"`
	SecretNames []string `json:"secret_names"`
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

	// Set up streaming response.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	totalSteps := 9
	emit := func(step int, status, msg string) {
		slog.Info("migrate step", "step", step, "total", totalSteps, "status", status, "msg", msg)
		json.NewEncoder(w).Encode(migrateStatus{
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
		KeyId:  aws.String(newKMSKeyID),
		Policy: aws.String(policy),
	})
	if err != nil {
		rollbackKey()
		emitErr(3, fmt.Sprintf("apply transitional policy: %v", err))
		return
	}
	emit(3, "progress", "Transitional KMS policy applied")

	// Step 4: Store migration parameters in SSM.
	emit(4, "progress", "Storing migration parameters in SSM...")
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
	emit(5, "progress", "Calling export-key on old enclave...")
	if err := s.callExportKey(ctx, newKMSKeyID); err != nil {
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

	// Step 7: Adopt ciphertexts and update KMS key ID.
	emit(7, "progress", "Adopting migration ciphertexts...")
	for _, name := range req.SecretNames {
		ct, _ := s.getParam(ctx, "Migration/"+name+"/Ciphertext")
		if err := s.putParam(ctx, name+"/Ciphertext", ct); err != nil {
			emitErr(7, fmt.Sprintf("copy ciphertext for %s: %v", name, err))
			return
		}
	}
	if err := s.putParam(ctx, "KMSKeyID", newKMSKeyID); err != nil {
		emitErr(7, fmt.Sprintf("update KMSKeyID: %v", err))
		return
	}
	emit(7, "progress", "Ciphertexts adopted, KMSKeyID updated")

	// Step 8: Download new EIF, stop old enclave, replace, restart.
	// Commands are configurable for different environments:
	//   Production: systemctl stop/start enclave-watchdog (default)
	//   Test/QEMU:  custom commands to kill/restart boot-qemu.sh
	// Commands are split on whitespace — shell metacharacters are not supported.
	eifDest := envOrDefault("ENCLAVE_EIF_PATH", eifPath)
	stopCmd := envOrDefault("ENCLAVE_STOP_CMD", "systemctl stop enclave-watchdog")
	startCmd := envOrDefault("ENCLAVE_START_CMD", "systemctl start enclave-watchdog")

	// Download EIF before stopping enclave — if the download fails, the old
	// enclave keeps running and we can retry the migration.
	emit(8, "progress", "Downloading new EIF from S3...")
	tmpEIF := "/tmp/new-enclave.eif"
	if err := s.downloadEIF(ctx, req.EIFBucket, req.EIFKey, tmpEIF); err != nil {
		emitErr(8, fmt.Sprintf("download EIF: %v", err))
		return
	}

	// Stop old enclave only after successful download.
	// Commands use sh -c because they may contain shell features (pipes, redirects, &&).
	emit(8, "progress", fmt.Sprintf("Stopping old enclave (%s)...", stopCmd))
	if out, err := exec.CommandContext(ctx, "sh", "-c", stopCmd).CombinedOutput(); err != nil {
		slog.Warn("stop command failed", "output", string(out), "error", err)
		// Non-fatal: enclave may already be stopped.
		emit(8, "progress", fmt.Sprintf("Stop command returned error (continuing): %v", err))
	}

	emit(8, "progress", fmt.Sprintf("Replacing EIF at %s...", eifDest))
	if err := os.Rename(tmpEIF, eifDest); err != nil {
		if cpErr := copyFile(tmpEIF, eifDest); cpErr != nil {
			emitErr(8, fmt.Sprintf("replace EIF: %v", cpErr))
			return
		}
	}

	emit(8, "progress", fmt.Sprintf("Starting new enclave (%s)...", startCmd))
	if out, err := exec.CommandContext(ctx, "sh", "-c", startCmd).CombinedOutput(); err != nil {
		emitErr(8, fmt.Sprintf("start enclave: %v: %s", err, out))
		return
	}
	emit(8, "progress", "Enclave restarted with new EIF")

	// Step 9: Clean up migration SSM params.
	emit(9, "progress", "Cleaning up migration parameters...")
	s.resetParam(ctx, "MigrationKMSKeyID")
	for _, name := range req.SecretNames {
		s.resetParam(ctx, "Migration/"+name+"/Ciphertext")
	}

	emit(9, "complete", fmt.Sprintf("Migration complete. New KMS key: %s", newKMSKeyID))
}

// callExportKey calls POST /v1/export-key on the running enclave.
// The enclave URL defaults to https://127.0.0.1:443 but can be overridden
// via ENCLAVE_URL for testing (e.g. https://127.0.0.1:8443 via gvproxy).
func (s *server) callExportKey(ctx context.Context, migrationKeyID string) error {
	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	body := fmt.Sprintf(`{"migration_key_id":%q}`, migrationKeyID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enclaveURL+"/v1/export-key", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
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
	s.putParam(ctx, name, "UNSET")
}

func (s *server) downloadEIF(ctx context.Context, bucket, key, destPath string) error {
	out, err := s.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("S3 GetObject: %w", err)
	}
	defer out.Body.Close()

	tmp := destPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, out.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
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
// Grants Encrypt + PutKeyPolicy to the EC2 role (so the new enclave can self-apply
// PCR0-restricted Decrypt during Init) and admin to the account root.
// Intentionally omits Decrypt — only the new enclave can add that.
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
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Suppress unused import warnings.
var (
	_ kmstypes.KeyState
)
