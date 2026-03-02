package main

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"time"
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
	Status      string `json:"status"`
	EnclaveID   string `json:"enclave_id,omitempty"`
	EnclaveCID  int    `json:"enclave_cid,omitempty"`
	CPUCount    int    `json:"cpu_count,omitempty"`
	MemoryMiB   int    `json:"memory_mib,omitempty"`
	State       string `json:"state,omitempty"`
	Timestamp   string `json:"timestamp"`
	Deployment  string `json:"deployment"`
	AppName     string `json:"app_name"`
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
	json.NewEncoder(w).Encode(v)
}
