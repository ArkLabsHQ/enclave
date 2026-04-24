package supervisor

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

type enclaveActionResponse struct {
	Action  string `json:"action"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// handleStart is the reconciliation endpoint for the in-process watchdog.
// If an enclave is already running, returns 409 without touching lifecycle.
// Otherwise asks the watchdog (or ENCLAVE_START_CMD override in tests) to
// launch one.
func (s *server) handleStart(w http.ResponseWriter, r *http.Request) {
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

	if err := s.lifecycleStart(r.Context(), os.Getenv("ENCLAVE_START_CMD")); err != nil {
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

// handleStop tells the watchdog (or ENCLAVE_STOP_CMD override in tests) to
// terminate the enclave.
func (s *server) handleStop(w http.ResponseWriter, r *http.Request) {
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

	if err := s.lifecycleStop(r.Context(), os.Getenv("ENCLAVE_STOP_CMD")); err != nil {
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
