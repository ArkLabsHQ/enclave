package supervisor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Health serves /health (enclave status) and /supervisor/health
// (supervisor self-readiness, used by the self-update flow).
// migrationInProgress is a callback to avoid a *Migration back-reference.
type Health struct {
	aws                 *AWSClient
	migrationInProgress func() bool
}

func NewHealth(aws *AWSClient, migrationInProgress func() bool) *Health {
	return &Health{aws: aws, migrationInProgress: migrationInProgress}
}

func (h *Health) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.handleHealth)
	mux.HandleFunc("GET /supervisor/health", h.handleSupervisorHealth)
}

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

func (h *Health) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := healthResponse{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Deployment: getDeployment(),
		AppName:    getAppName(),
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

type supervisorHealthResponse struct {
	Status    string            `json:"status"` // "ok" or "error"
	Checks    map[string]string `json:"checks"`
	Timestamp string            `json:"timestamp"`
}

// handleSupervisorHealth: 200 iff AWS auth + SSM reachable + no migration
// in progress; 503 otherwise. Enclave reachability is informational only
// (the enclave may be stopped or restarting).
func (h *Health) handleSupervisorHealth(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	allOK := true

	ctx := r.Context()
	if _, err := h.aws.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		checks["aws_auth"] = "fail: " + err.Error()
		allOK = false
	} else {
		checks["aws_auth"] = "ok"
	}

	if _, err := h.aws.SSM.GetParameter(ctx, &ssm.GetParameterInput{
		Name: aws.String(kmsSubtreeParamPath("KMSKeyID")),
	}); err != nil {
		checks["ssm"] = "fail: " + err.Error()
		allOK = false
	} else {
		checks["ssm"] = "ok"
	}

	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
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

	if h.migrationInProgress != nil && h.migrationInProgress() {
		checks["migration_lock"] = "held (migration in progress)"
		allOK = false
	} else {
		checks["migration_lock"] = "free"
	}

	status := http.StatusOK
	statusStr := "ok"
	if !allOK {
		status = http.StatusServiceUnavailable
		statusStr = "error"
	}

	writeJSON(w, status, supervisorHealthResponse{
		Status:    statusStr,
		Checks:    checks,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// describeEnclaves runs nitro-cli describe-enclaves and parses the output.
// Also called from Observability and Lifecycle.
func describeEnclaves() ([]enclaveStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), lifecycleCommandTimeout)
	defer cancel()
	return describeEnclavesContext(ctx)
}

func describeEnclavesContext(ctx context.Context) ([]enclaveStatus, error) {
	out, err := exec.CommandContext(ctx, "nitro-cli", "describe-enclaves").Output()
	if err != nil {
		return nil, err
	}

	var enclaves []enclaveStatus
	if err := json.Unmarshal(out, &enclaves); err != nil {
		return nil, err
	}
	return enclaves, nil
}
