package supervisor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	"github.com/mdlayher/vsock"
)

const (
	eifPath                          = "/home/ec2-user/app/server/enclave.eif"
	supervisorBinaryPath             = "/home/ec2-user/app/supervisor"
	migrationControlPort      uint32 = 8003
	migrationRequestPath             = "/request-migration"
	migrationFinalisationPath        = "/finalise-migration"
	migrationControlBaseURL          = "http://enclave"
	migrationRequestURL              = migrationControlBaseURL + migrationRequestPath
	migrationFinalisationURL         = migrationControlBaseURL + migrationFinalisationPath
)

// Migration drives the locked-key KMS migration handshake (and
// the optional supervisor self-update tail) plus /schedule-key-deletion.
// Calls requestShutdown after a successful self-update so the composer
// can hand off to the new binary.
type Migration struct {
	aws       *AWSClient
	lifecycle *Lifecycle

	migrateMu sync.Mutex // serialises migration intent changes and execution

	controlClient   *http.Client
	requestShutdown func() // signals Supervisor to shut down after a self-update
}

func NewMigration(aws *AWSClient, lifecycle *Lifecycle, requestShutdown func()) *Migration {
	return &Migration{
		aws:             aws,
		lifecycle:       lifecycle,
		controlClient:   newMigrationControlClient(uint32(lifecycle.enclaveCID)),
		requestShutdown: requestShutdown,
	}
}

func newMigrationControlClient(enclaveCID uint32) *http.Client {
	return &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return vsock.Dial(enclaveCID, migrationControlPort, nil)
			},
		},
	}
}

func (m *Migration) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /migrate", m.handleMigrate)
	mux.HandleFunc("POST /migrate/request", m.handleMigrateRequest)
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
	Finalize               *bool    `json:"finalize"`
	EIFBucket              string   `json:"eif_bucket"`
	EIFKey                 string   `json:"eif_key"`
	PCR0                   string   `json:"pcr0"`
	SecretNames            []string `json:"secret_names"`
	SupervisorBinaryBucket string   `json:"supervisor_binary_bucket,omitempty"`
	SupervisorBinaryKey    string   `json:"supervisor_binary_key,omitempty"`
}

type migrateIntentRequest struct {
	TargetPCR0 string `json:"target_pcr0"`
}

type migrationControlRequest struct {
	Action     string `json:"action"`
	TargetPCR0 string `json:"target_pcr0,omitempty"`
}

type migrationControlResponse struct {
	statusCode  int
	contentType string
	body        []byte
}

type migrateStatus struct {
	Step    int    `json:"step"`
	Total   int    `json:"total"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

const migrateTotalSteps = 7

const (
	stepReadCurrentKey    = 1
	stepFinaliseMigration = 2
	stepDownloadEIF       = 3
	stepSwapAndStart      = 4
	stepWaitOutcome       = 5
	stepHostCleanup       = 6
	stepSupervisorUpdate  = 7
)

const (
	statusProgress = "progress"
	statusError    = "error"
	statusWarn     = "warn"
	statusComplete = "complete"
)

const (
	tmpNewEIFPath          = "/tmp/new-enclave.eif"
	defaultCommitTimeout   = 5 * time.Minute
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
func (e *migrateEmitter) error(step int, msg string)    { e.emit(step, statusError, msg) }
func (e *migrateEmitter) warn(step int, msg string)     { e.emit(step, statusWarn, msg) }
func (e *migrateEmitter) complete(step int, msg string) { e.emit(step, statusComplete, msg) }

func (e *migrateEmitter) progressf(step int, format string, args ...any) {
	e.progress(step, fmt.Sprintf(format, args...))
}
func (e *migrateEmitter) errorf(step int, format string, args ...any) {
	e.error(step, fmt.Sprintf(format, args...))
}
func (e *migrateEmitter) warnf(step int, format string, args ...any) {
	e.warn(step, fmt.Sprintf(format, args...))
}

// handleMigrate optionally finalises the enclave handoff, then orchestrates the
// EIF swap, health check, rollback, and optional supervisor update.
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

	ctx := r.Context()
	if *req.Finalize {
		response, err := m.callFinaliseMigration(ctx, req.PCR0)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if response.statusCode != http.StatusOK {
			writeMigrationControlResponse(w, response)
			return
		}
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)

	p := newMigrateEmitter(w)

	if _, err := m.readCurrentKMSKey(ctx, p); err != nil {
		return
	}

	if *req.Finalize {
		p.progress(stepFinaliseMigration, "Finalise-migration succeeded")
	} else {
		p.progress(stepFinaliseMigration, "Skipping enclave finalisation as requested")
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

	newKeyID, _ := m.getParamAt(ctx, kmsSubtreeParamPath("KMSKeyID"))
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
	if req.Finalize == nil {
		http.Error(w, `{"error":"finalize is required"}`, http.StatusBadRequest)
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

func (m *Migration) readCurrentKMSKey(ctx context.Context, p *migrateEmitter) (string, error) {
	p.progress(stepReadCurrentKey, "Reading current KMS key ID...")
	keyID, err := m.getParamAt(ctx, kmsSubtreeParamPath("KMSKeyID"))
	if err != nil || keyID == "" {
		p.errorf(stepReadCurrentKey, "KMSKeyID not found in SSM: %v", err)
		if err == nil {
			err = fmt.Errorf("KMSKeyID is empty")
		}
		return "", err
	}
	return keyID, nil
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
// enclave's migration finalisation owns its own key cleanup; the supervisor
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

func (m *Migration) callMigrationControl(
	ctx context.Context,
	path string,
	payload any,
) (*migrationControlResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		migrationControlBaseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.controlClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return &migrationControlResponse{
		statusCode:  resp.StatusCode,
		contentType: resp.Header.Get("Content-Type"),
		body:        responseBody,
	}, nil
}

func (m *Migration) callFinaliseMigration(
	ctx context.Context,
	newPCR0 string,
) (*migrationControlResponse, error) {
	response, err := m.callMigrationControl(ctx, migrationFinalisationPath, struct {
		NewPCR0 string `json:"new_pcr0"`
	}{NewPCR0: newPCR0})
	if err != nil {
		return nil, fmt.Errorf("finalise-migration request failed: %w", err)
	}
	return response, nil
}

func (m *Migration) handleMigrateRequest(w http.ResponseWriter, r *http.Request) {
	var req migrateIntentRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid request: %v"}`, err), http.StatusBadRequest)
		return
	}
	if req.TargetPCR0 == "" {
		http.Error(w, `{"error":"target_pcr0 is required"}`, http.StatusBadRequest)
		return
	}
	m.proxyMigrationControl(w, r, migrationRequestPath, migrationControlRequest{
		Action:     "requested",
		TargetPCR0: req.TargetPCR0,
	})
}

func (m *Migration) handleMigrateAbort(w http.ResponseWriter, r *http.Request) {
	m.proxyMigrationControl(w, r, migrationRequestPath, migrationControlRequest{Action: "aborted"})
}

func (m *Migration) proxyMigrationControl(
	w http.ResponseWriter,
	r *http.Request,
	path string,
	payload any,
) {
	if !m.migrateMu.TryLock() {
		http.Error(w, `{"error":"migration already in progress"}`, http.StatusConflict)
		return
	}
	defer m.migrateMu.Unlock()

	response, err := m.callMigrationControl(r.Context(), path, payload)
	if err != nil {
		http.Error(w, fmt.Sprintf("migration control request failed: %v", err), http.StatusBadGateway)
		return
	}
	writeMigrationControlResponse(w, response)
}

func writeMigrationControlResponse(w http.ResponseWriter, response *migrationControlResponse) {
	if response.contentType != "" {
		w.Header().Set("Content-Type", response.contentType)
	}
	w.WriteHeader(response.statusCode)
	_, _ = w.Write(response.body)
}

type deletionResponse struct {
	KeyID       string `json:"key_id"`
	PendingDays int    `json:"pending_window_days"`
}

func (m *Migration) handleScheduleKeyDeletion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	kmsParam := kmsSubtreeParamPath("KMSKeyID")
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

// getParamAt reads an SSM param at an explicit path (UNSET treated as ""). Used
// for KMS-subtree params, whose path carries the lock segment.
func (m *Migration) getParamAt(ctx context.Context, path string) (string, error) {
	out, err := m.aws.SSM.GetParameter(ctx, &ssm.GetParameterInput{
		Name: aws.String(path),
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
