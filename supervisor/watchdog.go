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

// Watchdog owns the enclave lifecycle. It runs `nitro-cli run-enclave` on
// supervisor startup, polls `describe-enclaves` to detect unexpected exits,
// and restarts with bounded backoff. On supervisor shutdown it terminates
// the enclave gracefully.
//
// Replaces the former enclave-watchdog.service + enclave_init.sh pair.
type Watchdog struct {
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

func newWatchdog() (*Watchdog, error) {
	w := &Watchdog{
		enclaveName:  envOrDefault("ENCLAVE_NAME", "app"),
		eifPath:      envOrDefault("EIF_PATH", "/home/ec2-user/app/server/enclave.eif"),
		pollInterval: 5 * time.Second,
		debug:        strings.EqualFold(envOrDefault("DEBUG_MODE", "false"), "true"),
	}
	var err error
	w.cpuCount, err = strconv.Atoi(envOrDefault("CPU_COUNT", "2"))
	if err != nil {
		return nil, fmt.Errorf("invalid CPU_COUNT: %w", err)
	}
	w.memoryMiB, err = strconv.Atoi(envOrDefault("MEMORY_MIB", "4320"))
	if err != nil {
		return nil, fmt.Errorf("invalid MEMORY_MIB: %w", err)
	}
	w.enclaveCID, err = strconv.Atoi(envOrDefault("ENCLAVE_CID", "16"))
	if err != nil {
		return nil, fmt.Errorf("invalid ENCLAVE_CID: %w", err)
	}
	if v := envOrDefault("POLL_INTERVAL_SECONDS", ""); v != "" {
		d, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid POLL_INTERVAL_SECONDS: %w", err)
		}
		w.pollInterval = time.Duration(d) * time.Second
	}
	return w, nil
}

// Run auto-launches the enclave and supervises it until ctx is cancelled.
// Returns nil on graceful shutdown.
//
// In production the watchdog drives `nitro-cli run-enclave`. The
// ENCLAVE_START_CMD / ENCLAVE_STOP_CMD env overrides let the integration
// test harness substitute QEMU + boot-qemu.sh without the supervisor
// needing to know it's in a test. If neither nitro-cli nor an override
// is present, we log a warning and fall through to the poll loop — the
// enclave is assumed to be started externally; we still watch it via
// ENCLAVE_URL/health.
func (w *Watchdog) Run(ctx context.Context) error {
	if os.Getenv("ENCLAVE_START_CMD") == "" {
		if _, err := exec.LookPath("nitro-cli"); err != nil {
			slog.Warn("nitro-cli not on PATH and no ENCLAVE_START_CMD override — "+
				"watchdog will not auto-launch; enclave assumed externally managed",
				"error", err)
		}
	}

	if err := w.startEnclave(ctx); err != nil {
		slog.Error("initial enclave start failed", "error", err)
		// Fall through to the poll loop; restart logic will retry.
	}

	backoff := time.Second
	const maxBackoff = 30 * time.Second
	// Boot grace: require N consecutive "not running" observations before
	// declaring the enclave dead and restarting. Must exceed the worst-case
	// cold boot time — nitro-cli comes up in seconds, but QEMU + nitriding
	// TLS can need close to a minute. With pollInterval=5s and N=12 we give
	// 60s of grace, absorbing both native and test-harness boot windows
	// while still detecting real crashes quickly. The counter resets as
	// soon as the enclave reports healthy.
	const deadThreshold = 12
	consecutiveMisses := 0
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if err := w.terminateEnclave(); err != nil {
				slog.Warn("enclave termination on shutdown failed", "error", err)
			}
			return nil
		case <-ticker.C:
		}

		w.mu.Lock()
		stopped := w.stopped
		w.mu.Unlock()
		if stopped {
			consecutiveMisses = 0
			continue
		}

		running, err := w.isRunning()
		if err != nil {
			slog.Debug("isRunning probe failed", "error", err)
			continue
		}
		if running {
			consecutiveMisses = 0
			backoff = time.Second
			w.setRunning(true)
			continue
		}

		consecutiveMisses++
		if consecutiveMisses < deadThreshold {
			slog.Debug("enclave not responding yet, waiting",
				"misses", consecutiveMisses, "threshold", deadThreshold)
			continue
		}
		w.setRunning(false)
		slog.Warn("enclave not running, restarting",
			"consecutive_misses", consecutiveMisses, "backoff", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if err := w.startEnclave(ctx); err != nil {
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

// StartOnce is the reconciliation entry point for the /start handler and
// migration flows. If the enclave is already running, it's a no-op. If the
// operator previously invoked StopOnce, this clears that latch and relaunches.
func (w *Watchdog) StartOnce(ctx context.Context) error {
	w.mu.Lock()
	w.stopped = false
	w.mu.Unlock()

	running, err := w.isRunning()
	if err == nil && running {
		return nil
	}
	return w.startEnclave(ctx)
}

// StopOnce terminates the enclave and latches the watchdog so the poll loop
// won't auto-restart it. Clear the latch by calling StartOnce.
func (w *Watchdog) StopOnce(ctx context.Context) error {
	w.mu.Lock()
	w.stopped = true
	w.mu.Unlock()
	return w.terminateEnclave()
}

// SetStopped flips the poll-loop latch without touching the enclave. Used by
// lifecycleStop/lifecycleStart when an override command (ENCLAVE_STOP_CMD /
// ENCLAVE_START_CMD) drives the enclave directly — we still need the latch
// so the poll loop doesn't race the caller with a spurious restart.
func (w *Watchdog) SetStopped(v bool) {
	w.mu.Lock()
	w.stopped = v
	w.mu.Unlock()
}

// startEnclave launches the enclave. Precedence:
//  1. If ENCLAVE_START_CMD is set, run it via `sh -c` (test harness path —
//     value is usually `./boot-qemu.sh …`).
//  2. Otherwise exec `nitro-cli run-enclave` with the configured args.
// If neither nitro-cli is available nor an override is set, return nil
// (the enclave is assumed externally managed; poll loop still watches).
func (w *Watchdog) startEnclave(ctx context.Context) error {
	if cmd := os.Getenv("ENCLAVE_START_CMD"); cmd != "" {
		slog.Info("launching enclave via ENCLAVE_START_CMD", "cmd", cmd)
		out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ENCLAVE_START_CMD: %w: %s", err, out)
		}
		w.setRunning(true)
		return nil
	}
	if _, err := exec.LookPath("nitro-cli"); err != nil {
		slog.Debug("no nitro-cli and no ENCLAVE_START_CMD — skipping autostart")
		return nil
	}
	args := []string{
		"run-enclave",
		"--cpu-count", strconv.Itoa(w.cpuCount),
		"--memory", strconv.Itoa(w.memoryMiB),
		"--eif-path", w.eifPath,
		"--enclave-cid", strconv.Itoa(w.enclaveCID),
		"--enclave-name", w.enclaveName,
	}
	if w.debug {
		args = append(args, "--debug-mode")
	}
	slog.Info("launching enclave", "name", w.enclaveName, "eif", w.eifPath)
	out, err := exec.CommandContext(ctx, "nitro-cli", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("run-enclave: %w: %s", err, out)
	}
	w.setRunning(true)
	return nil
}

// terminateEnclave stops the enclave. Same override precedence as startEnclave.
func (w *Watchdog) terminateEnclave() error {
	w.setRunning(false)
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
	out, err := exec.Command("nitro-cli", "terminate-enclave", "--enclave-name", w.enclaveName).CombinedOutput()
	if err != nil {
		// If no enclave is running, nitro-cli exits non-zero — treat as success.
		if strings.Contains(string(out), "There is no enclave") {
			return nil
		}
		return fmt.Errorf("terminate-enclave: %w: %s", err, out)
	}
	return nil
}

// isRunning checks whether the enclave is up. On a real Nitro host this
// queries nitro-cli describe-enclaves. In test (or any non-nitro-cli
// environment) it falls back to polling ENCLAVE_URL/health — if the
// enclave's TLS endpoint responds at all (200 or 503), it's alive.
//
// Production safety: the nitro-cli branch is the only path taken on a real
// Nitro EC2 host (nitro-cli ships with the AL2023 nitro-enclaves-cli
// package installed by user_data). The TLS-probe branch only triggers in
// test/dev when nitro-cli is absent (e.g. the QEMU integration harness).
// See the InsecureSkipVerify discussion below.
func (w *Watchdog) isRunning() (bool, error) {
	if _, err := exec.LookPath("nitro-cli"); err == nil {
		enclaves, err := describeEnclaves()
		if err != nil {
			return false, err
		}
		for _, e := range enclaves {
			if strings.EqualFold(e.State, "RUNNING") && e.EnclaveName == w.enclaveName {
				return true, nil
			}
		}
		return false, nil
	}
	// No nitro-cli on PATH — test/dev fallback only.
	url := os.Getenv("ENCLAVE_URL")
	if url == "" {
		// Can't tell; assume running so the poll loop doesn't thrash.
		return true, nil
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			// Liveness probe only — the enclave serves a self-signed cert
			// (attestation-pinned, not registered with any CA). Verifying
			// against a trust store is impossible by design. This branch is
			// unreachable in production (nitro-cli is the path there).
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

func (w *Watchdog) setRunning(v bool) {
	w.mu.Lock()
	w.running = v
	w.mu.Unlock()
}
