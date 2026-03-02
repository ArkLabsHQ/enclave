package main

import (
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
)

type enclaveActionResponse struct {
	Action  string `json:"action"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// handleStart starts the enclave by enabling and starting the watchdog service.
// The watchdog runs enclave_init.sh which calls nitro-cli run-enclave and polls.
// Restart=always in the watchdog handles crash recovery.
func (s *server) handleStart(w http.ResponseWriter, r *http.Request) {
	// Check if already running.
	enclaves, err := describeEnclaves()
	if err == nil {
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

	cmd := exec.Command("systemctl", "start", "enclave-watchdog")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("start enclave: %v: %s", err, output)
		http.Error(w, fmt.Sprintf("failed to start enclave-watchdog: %v\n%s", err, output), http.StatusInternalServerError)
		return
	}

	log.Printf("start enclave: watchdog started")
	writeJSON(w, http.StatusOK, enclaveActionResponse{
		Action:  "start",
		Status:  "started",
		Message: "enclave-watchdog service started",
	})
}

// handleStop stops the enclave by stopping the watchdog service.
// The watchdog's ExecStop calls nitro-cli terminate-enclave.
func (s *server) handleStop(w http.ResponseWriter, r *http.Request) {
	// Check if already stopped.
	enclaves, err := describeEnclaves()
	if err == nil {
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

	cmd := exec.Command("systemctl", "stop", "enclave-watchdog")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("stop enclave: %v: %s", err, output)
		http.Error(w, fmt.Sprintf("failed to stop enclave-watchdog: %v\n%s", err, output), http.StatusInternalServerError)
		return
	}

	log.Printf("stop enclave: watchdog stopped")
	writeJSON(w, http.StatusOK, enclaveActionResponse{
		Action:  "stop",
		Status:  "stopped",
		Message: "enclave-watchdog service stopped",
	})
}
