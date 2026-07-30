package supervisor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	lifecycle migrationLifecycle

	migrateMu sync.Mutex // serialises migration intent changes and execution

	controlClient   *http.Client
	requestShutdown func() // signals Supervisor to shut down after a self-update
}

type migrationLifecycle interface {
	Start(context.Context, string) error
	Stop(context.Context, string) error
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
		Timeout: migrationControlTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				conn, err := vsock.Dial(enclaveCID, migrationControlPort, nil)
				if err == nil && enclaveCID == 1 {
					// vhost-device-vsock can reset loopback streams when data is sent
					// before the guest finishes accepting the connection.
					time.Sleep(250 * time.Millisecond)
				}
				return conn, err
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
	tmpNewEIFPath           = "/tmp/new-enclave.eif"
	migrationControlTimeout = 2 * time.Minute
	defaultCommitTimeout    = 5 * time.Minute
	keyDeletionPendingDays  = 7
	candidateResponseLimit  = 1 << 20
	candidatePollInterval   = 5 * time.Second
)

var errCandidateInitializing = errors.New("candidate is still initializing")

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
	// The server's generic write timeout is shorter than migration readiness.
	// Extend this response only, while the CLI still provides the outer bound.
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(migrationWriteTimeout())); err != nil && !errors.Is(err, http.ErrNotSupported) {
		slog.Warn("set migration response deadline", "error", err)
	}
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
	if !m.awaitMigrationOutcome(ctx, p, req.PCR0, eifDest, eifBackup, stopCmd, startCmd) {
		return // rollback already performed
	}

	if err := m.cleanupHostArtifacts(p, tmpNewEIFPath, eifBackup); err != nil {
		return
	}
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
	pcr0, err := normalizePCR0(req.PCR0)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid pcr0: %v"}`, err), http.StatusBadRequest)
		return req, false
	}
	req.PCR0 = pcr0
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
			p.errorf(stepSwapAndStart, "replace EIF: %v", cpErr)
			m.rollbackMigration(ctx, eifDest, eifBackup, stopCmd, startCmd, p.emit)
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

// awaitMigrationOutcome verifies the candidate and rolls the EIF back on any
// health, identity, transport, or timeout failure.
func (m *Migration) awaitMigrationOutcome(
	ctx context.Context,
	p *migrateEmitter,
	expectedPCR0 string,
	eifDest, eifBackup, stopCmd, startCmd string,
) bool {
	timeout := migrationCommitTimeout()
	p.progressf(stepWaitOutcome, "Verifying new enclave health and PCR0 (timeout: %s)...", timeout)

	if err := m.awaitEnclaveReady(ctx, newCandidateVerificationClient(), expectedPCR0, timeout); err != nil {
		p.errorf(stepWaitOutcome, "new enclave verification failed: %v", err)
		m.rollbackMigration(ctx, eifDest, eifBackup, stopCmd, startCmd, p.emit)
		return false
	}
	p.progress(stepWaitOutcome, "New enclave is ready and reports the requested PCR0")
	return true
}

func migrationCommitTimeout() time.Duration {
	if v := envOrDefault("ENCLAVE_MIGRATION_COMMIT_TIMEOUT", ""); v != "" {
		if timeout, err := time.ParseDuration(v); err == nil && timeout > 0 {
			return timeout
		}
	}
	return defaultCommitTimeout
}

func migrationWriteTimeout() time.Duration {
	return migrationControlTimeout + migrationCommitTimeout() + 2*time.Minute
}

func (m *Migration) cleanupHostArtifacts(p *migrateEmitter, tmpEIF, eifBackup string) error {
	p.progress(stepHostCleanup, "Removing temporary EIF artifacts...")
	for _, path := range []string{tmpEIF + ".tmp", tmpEIF, eifBackup} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("remove %s: %w", path, err)
			p.errorf(stepHostCleanup, "host-side cleanup failed: %v", err)
			return err
		}
	}
	p.progress(stepHostCleanup, "Host-side cleanup done")
	return nil
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

func newCandidateVerificationClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// awaitEnclaveReady retries only startup transport failures and HTTP 503.
// Any HTTP 200 response with invalid content is a terminal verification error.
func (m *Migration) awaitEnclaveReady(ctx context.Context, client *http.Client, expectedPCR0 string, timeout time.Duration) error {
	verificationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer client.CloseIdleConnections()

	enclaveURL := strings.TrimRight(envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443"), "/")
	var lastStartupError error
	for {
		err := verifyCandidate(verificationCtx, client, enclaveURL, expectedPCR0)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errCandidateInitializing) {
			return err
		}
		lastStartupError = err

		select {
		case <-verificationCtx.Done():
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("candidate verification timed out after %s: %v", timeout, lastStartupError)
		case <-time.After(candidatePollInterval):
		}
	}
}

func verifyCandidate(ctx context.Context, client *http.Client, enclaveURL, expectedPCR0 string) error {
	status, body, err := candidateGET(ctx, client, enclaveURL+"/health")
	if err != nil {
		return err
	}
	if status == http.StatusServiceUnavailable {
		return fmt.Errorf("%w: GET /health returned 503", errCandidateInitializing)
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET /health returned HTTP %d", status)
	}
	var health struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		return fmt.Errorf("decode GET /health response: %w", err)
	}
	if health.Status != "ready" {
		return fmt.Errorf("GET /health status is %q, want %q", health.Status, "ready")
	}

	status, body, err = candidateGET(ctx, client, enclaveURL+"/v1/enclave-info")
	if err != nil {
		return err
	}
	if status == http.StatusServiceUnavailable {
		return fmt.Errorf("%w: GET /v1/enclave-info returned 503", errCandidateInitializing)
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET /v1/enclave-info returned HTTP %d", status)
	}
	var info struct {
		Migration struct {
			SourcePCR0 string `json:"source_pcr0"`
		} `json:"migration"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return fmt.Errorf("decode GET /v1/enclave-info response: %w", err)
	}
	if info.Migration.SourcePCR0 != expectedPCR0 {
		return fmt.Errorf("GET /v1/enclave-info migration.source_pcr0 is %q, want %q", info.Migration.SourcePCR0, expectedPCR0)
	}
	return nil
}

func candidateGET(ctx context.Context, client *http.Client, url string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: GET %s: %v", errCandidateInitializing, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, candidateResponseLimit+1))
	if err != nil {
		return 0, nil, fmt.Errorf("read GET %s response: %w", req.URL.Path, err)
	}
	if len(body) > candidateResponseLimit {
		return 0, nil, fmt.Errorf("read GET %s response: response exceeds %d bytes", req.URL.Path, candidateResponseLimit)
	}
	return resp.StatusCode, body, nil
}

func normalizePCR0(pcr0 string) (string, error) {
	decoded, err := hex.DecodeString(pcr0)
	if err != nil {
		return "", fmt.Errorf("must be 96 hexadecimal characters: %w", err)
	}
	if len(decoded) != 48 {
		return "", errors.New("must be 96 hexadecimal characters")
	}
	return hex.EncodeToString(decoded), nil
}

// rollbackMigration restores the old EIF and restarts the old enclave after
// the new enclave failed to start or become healthy. KMSKeyID already points
// to the migration key (set by the old enclave before we swapped EIFs), so
// the restored old enclave will decrypt from it — its PCR0 is in the policy.
func (m *Migration) rollbackMigration(ctx context.Context, eifDest, eifBackup, stopCmd, startCmd string, emit func(step int, status, msg string)) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrationControlTimeout)
	defer cancel()

	emit(stepWaitOutcome, "rollback", "Initiating rollback...")

	emit(stepWaitOutcome, "rollback", "Stopping failed new enclave...")
	if err := m.lifecycle.Stop(rollbackCtx, stopCmd); err != nil {
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
	if err := m.lifecycle.Start(rollbackCtx, startCmd); err != nil {
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
