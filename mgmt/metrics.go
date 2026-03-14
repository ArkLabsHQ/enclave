package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const nitridingMetricsURL = "http://localhost:9090/metrics"

// enclaveMetricsClient is a shared HTTP client for fetching metrics from the enclave.
// InsecureSkipVerify is used because the enclave's TLS cert is self-signed by nitriding.
var enclaveMetricsClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

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

	// Proxy enclave application metrics (Prometheus format from supervisor).
	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	appResp, err := enclaveMetricsClient.Get(enclaveURL + "/v1/metrics")
	if err == nil {
		defer appResp.Body.Close()
		if appResp.StatusCode == http.StatusOK {
			fmt.Fprintln(w)
			io.Copy(w, appResp.Body)
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
