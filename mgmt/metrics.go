package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

const nitridingMetricsURL = "http://localhost:9090/metrics"

func (s *server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Proxy nitriding's Prometheus metrics.
	resp, err := http.Get(nitridingMetricsURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			io.Copy(w, resp.Body)
		}
	}

	// Append host-level enclave metrics.
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# HELP enclave_host_up Whether the enclave is running (1) or stopped (0).")
	fmt.Fprintln(w, "# TYPE enclave_host_up gauge")

	enclaves, err := describeEnclaves()
	if err != nil || len(enclaves) == 0 {
		fmt.Fprintln(w, "enclave_host_up 0")
		return
	}

	enc := enclaves[0]
	running := 0
	if strings.EqualFold(enc.State, "RUNNING") {
		running = 1
	}

	fmt.Fprintf(w, "enclave_host_up %d\n", running)

	fmt.Fprintln(w, "# HELP enclave_host_memory_mib Memory allocated to the enclave in MiB.")
	fmt.Fprintln(w, "# TYPE enclave_host_memory_mib gauge")
	fmt.Fprintf(w, "enclave_host_memory_mib %d\n", enc.MemoryMiB)

	fmt.Fprintln(w, "# HELP enclave_host_cpu_count Number of vCPUs allocated to the enclave.")
	fmt.Fprintln(w, "# TYPE enclave_host_cpu_count gauge")
	fmt.Fprintf(w, "enclave_host_cpu_count %d\n", enc.CPUCount)
}
