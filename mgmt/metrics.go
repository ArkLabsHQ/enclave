package main

import (
	"crypto/tls"
	"encoding/json"
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
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
			_, _ = io.Copy(w, resp.Body)
		}
	}

	// Proxy enclave application metrics (JSON from supervisor, converted to Prometheus text).
	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	appResp, err := enclaveMetricsClient.Get(enclaveURL + "/v1/enclave-metrics")
	if err == nil {
		body, _ := io.ReadAll(appResp.Body)
		_ = appResp.Body.Close()
		if appResp.StatusCode == http.StatusOK && len(body) > 0 {
			_, _ = fmt.Fprintln(w)
			// Convert JSON metrics to Prometheus text format.
			var snapshot map[string]any
			if json.Unmarshal(body, &snapshot) == nil {
				writePrometheusFromSnapshot(w, snapshot)
			}
		}
	}

	// Append host-level enclave metrics.
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "# HELP enclave_host_up Whether the enclave is running (1) or stopped (0).")
	_, _ = fmt.Fprintln(w, "# TYPE enclave_host_up gauge")

	enclaves, err := describeEnclaves()
	if err != nil || len(enclaves) == 0 {
		_, _ = fmt.Fprintln(w, "enclave_host_up 0")
		return
	}

	enc := enclaves[0]
	running := 0
	if strings.EqualFold(enc.State, "RUNNING") {
		running = 1
	}

	_, _ = fmt.Fprintf(w, "enclave_host_up %d\n", running)

	_, _ = fmt.Fprintln(w, "# HELP enclave_host_memory_mib Memory allocated to the enclave in MiB.")
	_, _ = fmt.Fprintln(w, "# TYPE enclave_host_memory_mib gauge")
	_, _ = fmt.Fprintf(w, "enclave_host_memory_mib %d\n", enc.MemoryMiB)

	_, _ = fmt.Fprintln(w, "# HELP enclave_host_cpu_count Number of vCPUs allocated to the enclave.")
	_, _ = fmt.Fprintln(w, "# TYPE enclave_host_cpu_count gauge")
	_, _ = fmt.Fprintf(w, "enclave_host_cpu_count %d\n", enc.CPUCount)
}

// writePrometheusFromSnapshot converts a JSON metric snapshot to Prometheus text format.
func writePrometheusFromSnapshot(w http.ResponseWriter, snapshot map[string]any) {
	for section, metrics := range snapshot {
		switch m := metrics.(type) {
		case map[string]any:
			for name, val := range m {
				metricName := fmt.Sprintf("enclave_%s_%s", section, name)
				metricName = strings.ReplaceAll(metricName, ".", "_")
				_, _ = fmt.Fprintf(w, "# TYPE %s gauge\n", metricName)
				_, _ = fmt.Fprintf(w, "%s %v\n", metricName, val)
			}
		}
	}
}
