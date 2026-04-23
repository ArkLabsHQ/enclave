package main

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// enclaveStatus is the JSON structure returned by nitro-cli describe-enclaves.
type enclaveStatus struct {
	EnclaveID   string `json:"EnclaveID"`
	EnclaveCID  int    `json:"EnclaveCID"`
	CPUCount    int    `json:"NumberOfCPUs"`
	MemoryMiB   int    `json:"MemoryMiB"`
	State       string `json:"State"`
	ProcessID   int    `json:"ProcessID"`
	CPUIDs      []int  `json:"CPUIDs"`
	EnclaveName string `json:"EnclaveName"`
}

type healthResponse struct {
	Status     string `json:"status"`
	EnclaveID  string `json:"enclave_id,omitempty"`
	EnclaveCID int    `json:"enclave_cid,omitempty"`
	CPUCount   int    `json:"cpu_count,omitempty"`
	MemoryMiB  int    `json:"memory_mib,omitempty"`
	State      string `json:"state,omitempty"`
	Timestamp  string `json:"timestamp"`
	Deployment string `json:"deployment"`
	AppName    string `json:"app_name"`
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := healthResponse{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Deployment: s.deployment,
		AppName:    s.appName,
	}

	enclaves, err := describeEnclaves()
	if err != nil {
		resp.Status = "error"
		writeJSON(w, http.StatusOK, resp)
		return
	}

	if len(enclaves) == 0 {
		resp.Status = "stopped"
		writeJSON(w, http.StatusOK, resp)
		return
	}

	enc := enclaves[0]
	resp.Status = "running"
	resp.EnclaveID = enc.EnclaveID
	resp.EnclaveCID = enc.EnclaveCID
	resp.CPUCount = enc.CPUCount
	resp.MemoryMiB = enc.MemoryMiB
	resp.State = enc.State

	writeJSON(w, http.StatusOK, resp)
}

// mgmtHealthResponse reports the mgmt server's own readiness, distinct from
// enclave status. Used by the atomic mgmt binary self-update flow to confirm
// the new binary is functional before deleting the backup.
type mgmtHealthResponse struct {
	Status    string            `json:"status"` // "ok" or "error"
	Checks    map[string]string `json:"checks"`
	Timestamp string            `json:"timestamp"`
}

// handleMgmtHealth verifies mgmt's own readiness: AWS auth, SSM reachability,
// enclave reachability, no in-progress migration. Returns 200 only when all
// checks pass; 503 otherwise.
func (s *server) handleMgmtHealth(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	allOK := true

	// Check 1: AWS credentials valid.
	ctx := r.Context()
	if _, err := s.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		checks["aws_auth"] = "fail: " + err.Error()
		allOK = false
	} else {
		checks["aws_auth"] = "ok"
	}

	// Check 2: SSM reachable (can read a known param).
	if _, err := s.getParam(ctx, "KMSKeyID"); err != nil {
		checks["ssm"] = "fail: " + err.Error()
		allOK = false
	} else {
		checks["ssm"] = "ok"
	}

	// Check 3: Enclave HTTP reachable (non-fatal for this check — enclave may
	// legitimately be stopped or restarting). Used only as informational.
	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(enclaveURL + "/health")
	if err != nil {
		checks["enclave"] = "unreachable: " + err.Error()
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			checks["enclave"] = "ok"
		} else {
			checks["enclave"] = "unhealthy (status " + http.StatusText(resp.StatusCode) + ")"
		}
	}

	// Check 4: migrateMu not held by a long-running operation (best effort).
	if !s.migrateMu.TryLock() {
		checks["migration_lock"] = "held (migration in progress)"
		allOK = false
	} else {
		s.migrateMu.Unlock()
		checks["migration_lock"] = "free"
	}

	status := http.StatusOK
	statusStr := "ok"
	if !allOK {
		status = http.StatusServiceUnavailable
		statusStr = "error"
	}

	writeJSON(w, status, mgmtHealthResponse{
		Status:    statusStr,
		Checks:    checks,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// describeEnclaves runs nitro-cli describe-enclaves and parses the output.
func describeEnclaves() ([]enclaveStatus, error) {
	out, err := exec.Command("nitro-cli", "describe-enclaves").Output()
	if err != nil {
		return nil, err
	}

	var enclaves []enclaveStatus
	if err := json.Unmarshal(out, &enclaves); err != nil {
		return nil, err
	}
	return enclaves, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
