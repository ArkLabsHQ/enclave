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

const migrateTotalSteps = 7

const (
	stepCooldown         = 0
	stepReadCurrentKey   = 1
	stepStartMigration   = 2
	stepDownloadEIF      = 3
	stepSwapAndStart     = 4
	stepWaitOutcome      = 5
	stepHostCleanup      = 6
	stepSupervisorUpdate = 7
)

const (
	statusProgress = "progress"
	statusCooldown = "cooldown"
	statusError    = "error"
	statusWarn     = "warn"
	statusComplete = "complete"
	statusAborted  = "aborted"
)

const (
	tmpNewEIFPath          = "/tmp/new-enclave.eif"
	defaultCommitTimeout   = 5 * time.Minute
	cooldownTickShort      = 10 * time.Second
	cooldownTickLong       = time.Minute
	cooldownTickThreshold  = time.Hour
	keyDeletionPendingDays = 7
)

// migrateEmitter streams NDJSON migrateStatus events to the /migrate caller.
type migrateEmitter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func newMigrateEmitter(w http.ResponseWriter) *migrateEmitter {
	flusher, _ := w.(http.Flusher)
	return &migrateEmitter{w: w, flusher: flusher}
}

func (e *migrateEmitter) emit(step int, status, msg string) {
	slog.Info("migrate step", "step", step, "total", migrateTotalSteps, "status", status, "msg", msg)
	_ = json.NewEncoder(e.w).Encode(migrateStatus{
		Step:    step,
		Total:   migrateTotalSteps,
		Status:  status,
		Message: msg,
	})
	if e.flusher != nil {
		e.flusher.Flush()
	}
}

func (e *migrateEmitter) progress(step int, msg string) { e.emit(step, statusProgress, msg) }
func (e *migrateEmitter) cooldown(step int, msg string) { e.emit(step, statusCooldown, msg) }
func (e *migrateEmitter) error(step int, msg string)    { e.emit(step, statusError, msg) }
func (e *migrateEmitter) warn(step int, msg string)     { e.emit(step, statusWarn, msg) }
func (e *migrateEmitter) complete(step int, msg string) { e.emit(step, statusComplete, msg) }
func (e *migrateEmitter) aborted(step int, msg string)  { e.emit(step, statusAborted, msg) }

func (e *migrateEmitter) progressf(step int, format string, args ...any) {
	e.progress(step, fmt.Sprintf(format, args...))
}
func (e *migrateEmitter) errorf(step int, format string, args ...any) {
	e.error(step, fmt.Sprintf(format, args...))
}
func (e *migrateEmitter) warnf(step int, format string, args ...any) {
	e.warn(step, fmt.Sprintf(format, args...))
}

// handleMigrate orchestrates the migration handshake plus the optional
// supervisor self-update tail. The enclave creates and lifecycle-manages the
// migration KMS key internally; the supervisor only sequences cooldown, EIF
// swap, health-poll, and rollback.
func (m *Migration) handleMigrate(w http.ResponseWriter, r *http.Request) {
	if !m.migrateMu.TryLock() {
		http.Error(w, `{"error":"migration already in progress"}`, http.StatusConflict)
		return
	}
	defer m.migrateMu.Unlock()

	req, ok := decodeMigrateRequest(w, r)
	if !ok {
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)

	ctx := r.Context()
	p := newMigrateEmitter(w)

	if !m.runCooldown(ctx, p) {
		return
	}

	if _, err := m.readCurrentKMSKey(ctx, p); err != nil {
		return
	}

	if err := m.invokeStartMigration(ctx, p, req.PCR0); err != nil {
		return
	}

	eifDest := envOrDefault("ENCLAVE_EIF_PATH", eifPath)
	eifBackup := eifDest + ".backup"
	stopCmd := os.Getenv("ENCLAVE_STOP_CMD")
	startCmd := os.Getenv("ENCLAVE_START_CMD")

	if err := m.stageNewEIF(ctx, p, req, eifDest, eifBackup); err != nil {
		return
	}
	if err := m.swapAndStart(ctx, p, eifDest, eifBackup, stopCmd, startCmd); err != nil {
		return // rollback already performed
	}
	if !m.awaitMigrationOutcome(ctx, p, eifDest, eifBackup, stopCmd, startCmd) {
		return // rollback already performed
	}

	m.cleanupHostArtifacts(p, eifBackup)
	exitAfter := m.maybeUpdateSupervisor(ctx, p, req)

	newKeyID, _ := m.getParam(ctx, "KMSKeyID")
	p.complete(stepSupervisorUpdate, fmt.Sprintf("Migration complete. New KMS key: %s", newKeyID))

	if exitAfter && m.requestShutdown != nil {
		m.requestShutdown()
	}
}

// decodeMigrateRequest validates the request body and writes a 4xx response
// on failure. Returns ok=false when the caller should abort.
func decodeMigrateRequest(w http.ResponseWriter, r *http.Request) (migrateRequest, bool) {
	var req migrateRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid request: %v"}`, err), http.StatusBadRequest)
		return req, false
	}
	if req.EIFBucket == "" || req.EIFKey == "" || req.PCR0 == "" {
		http.Error(w, `{"error":"eif_bucket, eif_key, and pcr0 are required"}`, http.StatusBadRequest)
		return req, false
	}
	if len(req.SecretNames) == 0 {
		http.Error(w, `{"error":"secret_names is required"}`, http.StatusBadRequest)
		return req, false
	}
	if (req.SupervisorBinaryBucket == "") != (req.SupervisorBinaryKey == "") {
		http.Error(w, `{"error":"supervisor_binary_bucket and supervisor_binary_key must be set together"}`, http.StatusBadRequest)
		return req, false
	}
	return req, true
}

// runCooldown waits out the configured cooldown window, accepting aborts
// via /migrate/abort. Returns false if the migration was aborted or the
// cooldown failed to record (caller should return).
func (m *Migration) runCooldown(ctx context.Context, p *migrateEmitter) bool {
	if m.cooldown <= 0 {
		return true
	}

	requestedAt := time.Now().UTC()
	if err := m.putParam(ctx, "MigrationRequestedAt", requestedAt.Format(time.RFC3339)); err != nil {
		p.errorf(stepCooldown, "store MigrationRequestedAt: %v", err)
		return false
	}

	m.abortMu.Lock()
	m.abortCh = make(chan struct{})
	abortCh := m.abortCh
	m.abortMu.Unlock()

	defer func() {
		m.resetParam(ctx, "MigrationRequestedAt")
		m.abortMu.Lock()
		m.abortCh = nil
		m.abortMu.Unlock()
	}()

	p.cooldown(stepCooldown, fmt.Sprintf("Migration cooldown: %s (abort via POST /migrate/abort)", m.cooldown))
	deadline := requestedAt.Add(m.cooldown)

	tickInterval := cooldownTickShort
	if m.cooldown > cooldownTickThreshold {
		tickInterval = cooldownTickLong
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for time.Now().UTC().Before(deadline) {
		select {
		case <-abortCh:
			p.aborted(stepCooldown, "Migration aborted during cooldown")
			return false
		case <-ctx.Done():
			p.aborted(stepCooldown, "Migration aborted during cooldown")
			return false
		case <-ticker.C:
		}
		p.cooldown(stepCooldown, fmt.Sprintf("Cooldown: %s remaining", time.Until(deadline).Round(time.Second)))
	}

	p.cooldown(stepCooldown, "Cooldown expired, proceeding with migration")
	return true
}

func (m *Migration) readCurrentKMSKey(ctx context.Context, p *migrateEmitter) (string, error) {
	p.progress(stepReadCurrentKey, "Reading current KMS key ID...")
	keyID, err := m.getParam(ctx, "KMSKeyID")
	if err != nil || keyID == "" {
		p.errorf(stepReadCurrentKey, "KMSKeyID not found in SSM: %v", err)
		if err == nil {
			err = fmt.Errorf("KMSKeyID is empty")
		}
		return "", err
	}
	return keyID, nil
}

// invokeStartMigration calls /v1/start-migration on the running enclave.
// The enclave creates the migration key with the final PCR0-locked policy at
// CreateKey time, re-encrypts secrets under it, then flips KMSKeyID.
func (m *Migration) invokeStartMigration(ctx context.Context, p *migrateEmitter, targetPCR0 string) error {
	p.progress(stepStartMigration, "Calling start-migration on old enclave...")
	if err := m.callStartMigration(ctx, targetPCR0); err != nil {
		p.errorf(stepStartMigration, "start-migration failed: %v", err)
		return err
	}
	p.progress(stepStartMigration, "Start-migration succeeded")
	return nil
}

// stageNewEIF backs up the running EIF and downloads the new one to a tmp
// path. The dest file is not touched yet — swapAndStart performs the swap
// only after the old enclave has been stopped.
func (m *Migration) stageNewEIF(ctx context.Context, p *migrateEmitter, req migrateRequest, eifDest, eifBackup string) error {
	p.progress(stepDownloadEIF, "Backing up old EIF...")
	if err := copyFile(eifDest, eifBackup); err != nil {
		p.errorf(stepDownloadEIF, "backup old EIF: %v", err)
		return err
	}

	p.progress(stepDownloadEIF, "Downloading new EIF from S3...")
	if err := m.downloadS3Object(ctx, req.EIFBucket, req.EIFKey, tmpNewEIFPath); err != nil {
		_ = os.Remove(eifBackup)
		p.errorf(stepDownloadEIF, "download EIF: %v", err)
		return err
	}
	return nil
}

// swapAndStart stops the old enclave, swaps the EIF, and starts the new one.
// On failure after the swap it restores the v2 EIF and restarts it. The
// enclave's handleStartMigration owns its own key cleanup; the supervisor
// no longer schedules migration-key deletion.
func (m *Migration) swapAndStart(
	ctx context.Context,
	p *migrateEmitter,
	eifDest, eifBackup, stopCmd, startCmd string,
) error {
	p.progress(stepSwapAndStart, "Stopping old enclave...")
	if err := m.lifecycle.Stop(ctx, stopCmd); err != nil {
		slog.Warn("stop command failed", "error", err)
		p.progressf(stepSwapAndStart, "Stop returned error (continuing): %v", err)
	}

	p.progressf(stepSwapAndStart, "Replacing EIF at %s...", eifDest)
	if err := os.Rename(tmpNewEIFPath, eifDest); err != nil {
		if cpErr := copyFile(tmpNewEIFPath, eifDest); cpErr != nil {
			// Old enclave is already stopped — restore backup and restart so
			// the system always has a healthy enclave running.
			_ = os.Rename(eifBackup, eifDest)
			_ = m.lifecycle.Start(ctx, startCmd)
			p.errorf(stepSwapAndStart, "replace EIF: %v", cpErr)
			return cpErr
		}
	}

	p.progress(stepSwapAndStart, "Starting new enclave...")
	if err := m.lifecycle.Start(ctx, startCmd); err != nil {
		p.errorf(stepSwapAndStart, "start enclave: %v", err)
		m.rollbackMigration(ctx, eifDest, eifBackup, stopCmd, startCmd, p.emit)
		return err
	}
	p.progress(stepSwapAndStart, "New enclave started; waiting for it to become healthy...")
	return nil
}

// awaitMigrationOutcome polls /v1/enclave-info for the new enclave's
// migration verdict. Returns false if the verdict was abort or the timeout
// elapsed, after triggering a full rollback.
func (m *Migration) awaitMigrationOutcome(
	ctx context.Context,
	p *migrateEmitter,
	eifDest, eifBackup, stopCmd, startCmd string,
) bool {
	timeout := defaultCommitTimeout
	if v := envOrDefault("ENCLAVE_MIGRATION_COMMIT_TIMEOUT", ""); v != "" {
		if d, perr := time.ParseDuration(v); perr == nil && d > 0 {
			timeout = d
		}
	}
	p.progressf(stepWaitOutcome, "Polling new enclave until healthy (timeout: %s)...", timeout)

	if err := m.awaitEnclaveReady(ctx, timeout); err != nil {
		p.errorf(stepWaitOutcome, "new enclave not healthy within timeout: %v", err)
		m.rollbackMigration(ctx, eifDest, eifBackup, stopCmd, startCmd, p.emit)
		return false
	}
	p.progress(stepWaitOutcome, "New enclave is healthy")
	return true
}

func (m *Migration) cleanupHostArtifacts(p *migrateEmitter, eifBackup string) {
	p.progress(stepHostCleanup, "Removing EIF backup...")
	_ = os.Remove(eifBackup)
	p.progress(stepHostCleanup, "Host-side cleanup done")
}

// maybeUpdateSupervisor downloads, validates, and stages a new supervisor
// binary when the request specifies one. Returns true when the update is
// ready and the caller should request shutdown after the final response.
func (m *Migration) maybeUpdateSupervisor(ctx context.Context, p *migrateEmitter, req migrateRequest) bool {
	if req.SupervisorBinaryBucket == "" || req.SupervisorBinaryKey == "" {
		return false
	}
	p.progress(stepSupervisorUpdate, "Updating supervisor binary...")
	if err := m.atomicSupervisorUpdate(ctx, req.SupervisorBinaryBucket, req.SupervisorBinaryKey); err != nil {
		p.warnf(stepSupervisorUpdate, "supervisor binary update failed, old supervisor still running: %v", err)
		return false
	}
	p.progress(stepSupervisorUpdate, "supervisor update ready — old supervisor will exit after this response")
	return true
}

// awaitEnclaveReady polls /v1/enclave-info until the new enclave returns
// HTTP 200 (initOK=true) or the timeout elapses.
func (m *Migration) awaitEnclaveReady(ctx context.Context, timeout time.Duration) error {
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
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, enclaveURL+"/v1/enclave-info", nil)
		if err != nil {
			return err
		}
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
	return fmt.Errorf("new enclave did not become healthy within %s", timeout)
}

// rollbackMigration restores the old EIF and restarts the old enclave after
// the new enclave failed to start or become healthy. KMSKeyID already points
// to the migration key (set by the old enclave before we swapped EIFs), so
// the restored old enclave will decrypt from it — its PCR0 is in the policy.
func (m *Migration) rollbackMigration(ctx context.Context, eifDest, eifBackup, stopCmd, startCmd string, emit func(step int, status, msg string)) {
	emit(stepWaitOutcome, "rollback", "Initiating rollback...")

	emit(stepWaitOutcome, "rollback", "Stopping failed new enclave...")
	if err := m.lifecycle.Stop(ctx, stopCmd); err != nil {
		slog.Warn("rollback stop failed", "error", err)
	}

	emit(stepWaitOutcome, "rollback", fmt.Sprintf("Restoring old EIF from %s...", eifBackup))
	if err := os.Rename(eifBackup, eifDest); err != nil {
		if cpErr := copyFile(eifBackup, eifDest); cpErr != nil {
			emit(stepWaitOutcome, "rollback", fmt.Sprintf("CRITICAL: failed to restore EIF backup: %v", cpErr))
			return
		}
		_ = os.Remove(eifBackup)
	}

	emit(stepWaitOutcome, "rollback", "Starting old enclave...")
	if err := m.lifecycle.Start(ctx, startCmd); err != nil {
		emit(stepWaitOutcome, "rollback", fmt.Sprintf("CRITICAL: failed to start old enclave: %v", err))
		return
	}

	emit(stepWaitOutcome, "rollback-complete", "Rollback complete; old enclave restored")
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

func (m *Migration) callStartMigration(ctx context.Context, newPCR0 string) error {
	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	client := &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	body := fmt.Sprintf(`{"new_pcr0":%q}`, newPCR0)
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
