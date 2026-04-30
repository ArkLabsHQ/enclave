package supervisor

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

const nitridingMetricsURL = "http://localhost:9090/metrics"

// Observability serves the four read-only telemetry endpoints. The
// shared HTTP client uses InsecureSkipVerify because the enclave's TLS
// cert is attestation-pinned, not CA-issued — verification is impossible
// by design.
type Observability struct {
	aws    *AWSClient
	client *http.Client
}

func NewObservability(aws *AWSClient) *Observability {
	return &Observability{
		aws: aws,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		},
	}
}

func (o *Observability) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /metrics", o.handleMetrics)
	mux.HandleFunc("GET /enclave-metrics", o.handleEnclaveMetrics)
	mux.HandleFunc("GET /enclave-logs", o.handleLogs)
	mux.HandleFunc("GET /enclave-traces", o.handleTraces)
}

// handleMetrics serves Prometheus text: nitriding metrics + enclave-app
// metrics (JSON → text) + host-side gauges.
func (o *Observability) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	resp, err := http.Get(nitridingMetricsURL)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
			_, _ = io.Copy(w, resp.Body)
		}
	}

	// Proxy enclave application metrics (JSON → Prometheus text).
	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	appResp, err := o.client.Get(enclaveURL + "/v1/enclave-metrics")
	if err == nil {
		body, _ := io.ReadAll(appResp.Body)
		_ = appResp.Body.Close()
		if appResp.StatusCode == http.StatusOK && len(body) > 0 {
			_, _ = fmt.Fprintln(w)
			var snapshot map[string]any
			if json.Unmarshal(body, &snapshot) == nil {
				writePrometheusFromSnapshot(w, snapshot)
			}
		}
	}

	// Host-level enclave metrics.
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

func (o *Observability) handleEnclaveMetrics(w http.ResponseWriter, r *http.Request) {
	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	u, err := url.Parse(enclaveURL + "/v1/enclave-metrics")
	if err != nil {
		http.Error(w, `{"error":"bad enclave URL"}`, http.StatusInternalServerError)
		return
	}
	u.RawQuery = r.URL.RawQuery

	resp, err := o.client.Get(u.String())
	if err != nil {
		http.Error(w, `{"error":"enclave unreachable"}`, http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// handleLogs serves a live proxy of the enclave's /v1/enclave-logs by
// default, or queries CloudWatch Logs when ?history=true.
func (o *Observability) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("history") == "true" {
		o.handleLogsHistory(w, r)
		return
	}

	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	u, err := url.Parse(enclaveURL + "/v1/enclave-logs")
	if err != nil {
		http.Error(w, `{"error":"bad enclave URL"}`, http.StatusInternalServerError)
		return
	}
	u.RawQuery = r.URL.RawQuery

	resp, err := o.client.Get(u.String())
	if err != nil {
		http.Error(w, `{"error":"enclave unreachable"}`, http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func (o *Observability) handleLogsHistory(w http.ResponseWriter, r *http.Request) {
	logGroup := fmt.Sprintf("/enclave/%s/%s/logs", getDeployment(), getAppName())

	var startTime *int64
	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339Nano, since); err == nil {
			startTime = aws.Int64(t.UnixMilli())
		} else if t, err := time.Parse(time.RFC3339, since); err == nil {
			startTime = aws.Int64(t.UnixMilli())
		}
	}

	limit := int32(100)
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 10000 {
			limit = int32(n)
		}
	}

	level := strings.ToLower(r.URL.Query().Get("level"))

	// Filter on level field; include the requested level and above.
	var filterPattern *string
	if level != "" {
		levels := levelAndAbove(level)
		if len(levels) > 0 {
			parts := make([]string, len(levels))
			for i, l := range levels {
				parts[i] = fmt.Sprintf(`$.level = %q`, l)
			}
			pattern := "{ " + strings.Join(parts, " || ") + " }"
			filterPattern = aws.String(pattern)
		}
	}

	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(logGroup),
		Limit:        aws.Int32(limit),
	}
	if startTime != nil {
		input.StartTime = startTime
	}
	if filterPattern != nil {
		input.FilterPattern = filterPattern
	}

	result, err := o.aws.CWL.FilterLogEvents(r.Context(), input)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"cloudwatch query failed: %s"}`, err), http.StatusInternalServerError)
		return
	}

	entries := make([]json.RawMessage, 0, len(result.Events))
	for _, event := range result.Events {
		if event.Message != nil {
			entries = append(entries, json.RawMessage(*event.Message))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

// levelAndAbove: nil for unknown levels.
func levelAndAbove(level string) []string {
	order := []string{"debug", "info", "warn", "error"}
	idx := -1
	for i, l := range order {
		if l == level {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	return order[idx:]
}

// handleTraces: live proxy of /v1/enclave-traces, or CloudWatch history
// when ?history=true.
func (o *Observability) handleTraces(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("history") == "true" {
		o.handleTracesHistory(w, r)
		return
	}

	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	u, err := url.Parse(enclaveURL + "/v1/enclave-traces")
	if err != nil {
		http.Error(w, `{"error":"bad enclave URL"}`, http.StatusInternalServerError)
		return
	}
	u.RawQuery = r.URL.RawQuery

	resp, err := o.client.Get(u.String())
	if err != nil {
		http.Error(w, `{"error":"enclave unreachable"}`, http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func (o *Observability) handleTracesHistory(w http.ResponseWriter, r *http.Request) {
	logGroup := fmt.Sprintf("/enclave/%s/%s/traces", getDeployment(), getAppName())

	var startTime *int64
	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339Nano, since); err == nil {
			startTime = aws.Int64(t.UnixMilli())
		} else if t, err := time.Parse(time.RFC3339, since); err == nil {
			startTime = aws.Int64(t.UnixMilli())
		}
	}

	limit := int32(100)
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 10000 {
			limit = int32(n)
		}
	}

	service := strings.ToLower(r.URL.Query().Get("service"))

	var filterPattern *string
	if service != "" {
		pattern := fmt.Sprintf(`{ $.source = %q }`, service)
		filterPattern = aws.String(pattern)
	}

	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(logGroup),
		Limit:        aws.Int32(limit),
	}
	if startTime != nil {
		input.StartTime = startTime
	}
	if filterPattern != nil {
		input.FilterPattern = filterPattern
	}

	result, err := o.aws.CWL.FilterLogEvents(r.Context(), input)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"cloudwatch query failed: %s"}`, err), http.StatusInternalServerError)
		return
	}

	entries := make([]json.RawMessage, 0, len(result.Events))
	for _, event := range result.Events {
		if event.Message != nil {
			entries = append(entries, json.RawMessage(*event.Message))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}
