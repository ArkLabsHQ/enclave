package supervisor

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Lifecycle runs `nitro-cli run-enclave` at supervisor startup, polls
// `describe-enclaves` to detect unexpected exits, and restarts with bounded
// backoff. Replaces the former enclave-watchdog.service + enclave_init.sh.
type Lifecycle struct {
	enclaveName  string
	eifPath      string
	cpuCount     int
	memoryMiB    int
	enclaveCID   int
	debug        bool
	pollInterval time.Duration

	mu      sync.Mutex
	running bool
	stopped bool // operator invoked StopOnce
}

func NewLifecycle() (*Lifecycle, error) {
	l := &Lifecycle{
		enclaveName:  envOrDefault("ENCLAVE_NAME", "app"),
		eifPath:      envOrDefault("EIF_PATH", "/home/ec2-user/app/server/enclave.eif"),
		pollInterval: 5 * time.Second,
		debug:        strings.EqualFold(envOrDefault("DEBUG_MODE", "false"), "true"),
	}
	var err error
	l.cpuCount, err = strconv.Atoi(envOrDefault("CPU_COUNT", "2"))
	if err != nil {
		return nil, fmt.Errorf("invalid CPU_COUNT: %w", err)
	}
	l.memoryMiB, err = strconv.Atoi(envOrDefault("MEMORY_MIB", "4320"))
	if err != nil {
		return nil, fmt.Errorf("invalid MEMORY_MIB: %w", err)
	}
	l.enclaveCID, err = strconv.Atoi(envOrDefault("ENCLAVE_CID", "16"))
	if err != nil {
		return nil, fmt.Errorf("invalid ENCLAVE_CID: %w", err)
	}
	if v := envOrDefault("POLL_INTERVAL_SECONDS", ""); v != "" {
		d, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid POLL_INTERVAL_SECONDS: %w", err)
		}
		l.pollInterval = time.Duration(d) * time.Second
	}
	return l, nil
}

func (l *Lifecycle) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /start", l.handleStart)
	mux.HandleFunc("POST /stop", l.handleStop)
}

// Run auto-launches the enclave and supervises it until ctx is cancelled.
// ENCLAVE_START_CMD / ENCLAVE_STOP_CMD let the integration test harness
// substitute QEMU + boot-qemu.sh; if neither nitro-cli nor an override is
// present, the enclave is assumed externally managed and we just poll
// ENCLAVE_URL/health.
func (l *Lifecycle) Run(ctx context.Context) error {
	if os.Getenv("ENCLAVE_START_CMD") == "" {
		if _, err := exec.LookPath("nitro-cli"); err != nil {
			slog.Warn("nitro-cli not on PATH and no ENCLAVE_START_CMD override — "+
				"watchdog will not auto-launch; enclave assumed externally managed",
				"error", err)
		}
	}

	if err := l.StartOnce(ctx); err != nil {
		slog.Error("initial enclave start failed", "error", err)
		// Fall through; restart logic will retry.
	}

	backoff := time.Second
	const maxBackoff = 30 * time.Second
	// 12 misses × 5s pollInterval = 60s boot grace. Long enough for QEMU +
	// nitriding TLS cold boot; short enough to catch real crashes quickly.
	const deadThreshold = 12
	consecutiveMisses := 0
	ticker := time.NewTicker(l.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if err := l.terminateEnclave(); err != nil {
				slog.Warn("enclave termination on shutdown failed", "error", err)
			}
			return nil
		case <-ticker.C:
		}

		l.mu.Lock()
		stopped := l.stopped
		l.mu.Unlock()
		if stopped {
			consecutiveMisses = 0
			continue
		}

		running, err := l.isRunning()
		if err != nil {
			slog.Debug("isRunning probe failed", "error", err)
			continue
		}
		if running {
			consecutiveMisses = 0
			backoff = time.Second
			l.setRunning(true)
			continue
		}

		consecutiveMisses++
		if consecutiveMisses < deadThreshold {
			slog.Debug("enclave not responding yet, waiting",
				"misses", consecutiveMisses, "threshold", deadThreshold)
			continue
		}
		l.setRunning(false)
		slog.Warn("enclave not running, restarting",
			"consecutive_misses", consecutiveMisses, "backoff", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		// Terminate before restarting: the enclave may be alive but
		// unreachable (e.g. wedged networking), in which case start paths
		// guarded by liveness checks (nitro-cli, test harness PID guard)
		// would no-op forever.
		if err := l.terminateEnclave(); err != nil {
			slog.Warn("enclave termination before restart failed", "error", err)
		}
		if err := l.startEnclave(ctx); err != nil {
			slog.Error("enclave restart failed", "error", err)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		consecutiveMisses = 0
		backoff = time.Second
	}
}

// Start clears the stopped-latch and launches the enclave. overrideCmd
// (when non-empty) replaces the nitro-cli invocation — used by the test
// harness via ENCLAVE_START_CMD.
func (l *Lifecycle) Start(ctx context.Context, overrideCmd string) error {
	if overrideCmd != "" {
		out, err := exec.CommandContext(ctx, "sh", "-c", overrideCmd).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		l.SetStopped(false)
		return nil
	}
	return l.StartOnce(ctx)
}

// Stop terminates the enclave. The stopped-latch is set first so the poll
// loop doesn't race the caller with a spurious restart.
func (l *Lifecycle) Stop(ctx context.Context, overrideCmd string) error {
	if overrideCmd != "" {
		l.SetStopped(true)
		out, err := exec.CommandContext(ctx, "sh", "-c", overrideCmd).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
	return l.StopOnce(ctx)
}

// StartOnce: no-op if already running; otherwise launches and clears the
// stopped-latch.
func (l *Lifecycle) StartOnce(ctx context.Context) error {
	l.mu.Lock()
	l.stopped = false
	l.mu.Unlock()

	running, err := l.isRunning()
	if err == nil && running {
		return nil
	}
	return l.startEnclave(ctx)
}

func (l *Lifecycle) StopOnce(ctx context.Context) error {
	l.mu.Lock()
	l.stopped = true
	l.mu.Unlock()
	return l.terminateEnclave()
}

// SetStopped flips the auto-restart latch without touching the enclave.
// Required when an override command drives the enclave directly so the
// poll loop doesn't race the caller.
func (l *Lifecycle) SetStopped(v bool) {
	l.mu.Lock()
	l.stopped = v
	l.mu.Unlock()
}

// startEnclave launches the enclave. Precedence: ENCLAVE_START_CMD ⇒
// `sh -c` (test harness); otherwise `nitro-cli run-enclave`. With neither
// available, return nil — externally managed; poll loop still watches.
func (l *Lifecycle) startEnclave(ctx context.Context) error {
	if cmd := os.Getenv("ENCLAVE_START_CMD"); cmd != "" {
		slog.Info("launching enclave via ENCLAVE_START_CMD", "cmd", cmd)
		out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ENCLAVE_START_CMD: %w: %s", err, out)
		}
		l.setRunning(true)
		return nil
	}
	if _, err := exec.LookPath("nitro-cli"); err != nil {
		slog.Debug("no nitro-cli and no ENCLAVE_START_CMD — skipping autostart")
		return nil
	}
	args := []string{
		"run-enclave",
		"--cpu-count", strconv.Itoa(l.cpuCount),
		"--memory", strconv.Itoa(l.memoryMiB),
		"--eif-path", l.eifPath,
		"--enclave-cid", strconv.Itoa(l.enclaveCID),
		"--enclave-name", l.enclaveName,
	}
	if l.debug {
		args = append(args, "--debug-mode")
	}
	slog.Info("launching enclave", "name", l.enclaveName, "eif", l.eifPath)
	out, err := exec.CommandContext(ctx, "nitro-cli", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("run-enclave: %w: %s", err, out)
	}
	l.setRunning(true)
	return nil
}

// terminateEnclave stops the enclave. Same override precedence as startEnclave.
func (l *Lifecycle) terminateEnclave() error {
	l.setRunning(false)
	if cmd := os.Getenv("ENCLAVE_STOP_CMD"); cmd != "" {
		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ENCLAVE_STOP_CMD: %w: %s", err, out)
		}
		return nil
	}
	if _, err := exec.LookPath("nitro-cli"); err != nil {
		return nil
	}
	out, err := exec.Command("nitro-cli", "terminate-enclave", "--enclave-name", l.enclaveName).CombinedOutput()
	if err != nil {
		// nitro-cli exits non-zero on no-running-enclave — treat as success.
		if strings.Contains(string(out), "There is no enclave") {
			return nil
		}
		return fmt.Errorf("terminate-enclave: %w: %s", err, out)
	}
	return nil
}

// isRunning queries nitro-cli describe-enclaves; falls back to polling
// ENCLAVE_URL/health in test/dev where nitro-cli isn't installed.
func (l *Lifecycle) isRunning() (bool, error) {
	if _, err := exec.LookPath("nitro-cli"); err == nil {
		enclaves, err := describeEnclaves()
		if err != nil {
			return false, err
		}
		for _, e := range enclaves {
			if strings.EqualFold(e.State, "RUNNING") && e.EnclaveName == l.enclaveName {
				return true, nil
			}
		}
		return false, nil
	}
	url := os.Getenv("ENCLAVE_URL")
	if url == "" {
		// Can't tell; assume running so the poll loop doesn't thrash.
		return true, nil
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			// Liveness probe against an attestation-pinned self-signed cert;
			// verifying against a trust store is impossible by design. This
			// branch is unreachable in production.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	resp, err := client.Get(url + "/health")
	if err != nil {
		return false, nil
	}
	_ = resp.Body.Close()
	return true, nil
}

func (l *Lifecycle) setRunning(v bool) {
	l.mu.Lock()
	l.running = v
	l.mu.Unlock()
}

type enclaveActionResponse struct {
	Action  string `json:"action"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// handleStart returns 409 if the enclave is already running; otherwise
// launches via Lifecycle.Start.
func (l *Lifecycle) handleStart(w http.ResponseWriter, r *http.Request) {
	if enclaves, err := describeEnclaves(); err == nil {
		for _, enc := range enclaves {
			if strings.EqualFold(enc.State, "RUNNING") {
				writeJSON(w, http.StatusConflict, enclaveActionResponse{
					Action:  "start",
					Status:  "already_running",
					Message: fmt.Sprintf("Enclave %s is already running", enc.EnclaveName),
				})
				return
			}
		}
	}

	if err := l.Start(r.Context(), os.Getenv("ENCLAVE_START_CMD")); err != nil {
		slog.Error("start enclave failed", "error", err)
		http.Error(w, fmt.Sprintf("failed to start enclave: %v", err), http.StatusInternalServerError)
		return
	}

	slog.Info("enclave started")
	writeJSON(w, http.StatusOK, enclaveActionResponse{
		Action:  "start",
		Status:  "started",
		Message: "enclave started",
	})
}

func (l *Lifecycle) handleStop(w http.ResponseWriter, r *http.Request) {
	if enclaves, err := describeEnclaves(); err == nil {
		running := false
		for _, enc := range enclaves {
			if strings.EqualFold(enc.State, "RUNNING") {
				running = true
				break
			}
		}
		if !running {
			writeJSON(w, http.StatusOK, enclaveActionResponse{
				Action:  "stop",
				Status:  "already_stopped",
				Message: "no enclave is running",
			})
			return
		}
	}

	if err := l.Stop(r.Context(), os.Getenv("ENCLAVE_STOP_CMD")); err != nil {
		slog.Error("stop enclave failed", "error", err)
		http.Error(w, fmt.Sprintf("failed to stop enclave: %v", err), http.StatusInternalServerError)
		return
	}

	slog.Info("enclave stopped")
	writeJSON(w, http.StatusOK, enclaveActionResponse{
		Action:  "stop",
		Status:  "stopped",
		Message: "enclave terminated",
	})
}
