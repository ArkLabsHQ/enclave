package sdk

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metrics holds OTEL metric instruments for the enclave supervisor.
type Metrics struct {
	// Supervisor counters.
	HTTPRequests   metric.Int64Counter
	HTTPErrors     metric.Int64Counter
	KMSOperations  metric.Int64Counter
	KMSErrors      metric.Int64Counter
	StorageReads   metric.Int64Counter
	StorageWrites  metric.Int64Counter
	StorageDeletes metric.Int64Counter
	StorageErrors  metric.Int64Counter
	SecretReads    metric.Int64Counter
	SecretWrites   metric.Int64Counter
	SecretDeletes  metric.Int64Counter
	LogEntries     metric.Int64Counter

	// Snapshot state: accumulated values for JSON export.
	mu       sync.Mutex
	counters map[string]int64

	// App metrics received via OTLP.
	appMu      sync.Mutex
	appMetrics map[string]float64

	// Runtime/proc metrics (updated periodically).
	runtimeMu      sync.Mutex
	runtimeMetrics map[string]float64
}

// enclaveMetrics is the global metrics instance.
var enclaveMetrics Metrics

// GetMetrics returns the global metrics instance.
func GetMetrics() *Metrics {
	return &enclaveMetrics
}

// InitMetrics initializes OTEL metric instruments and starts the runtime collector.
func InitMetrics() {
	meter := otel.Meter("enclave-supervisor")

	enclaveMetrics.counters = make(map[string]int64)
	enclaveMetrics.appMetrics = make(map[string]float64)
	enclaveMetrics.runtimeMetrics = make(map[string]float64)

	enclaveMetrics.HTTPRequests = newCounter(meter, "enclave_http_requests_total", "Total HTTP requests handled by the enclave supervisor.")
	enclaveMetrics.HTTPErrors = newCounter(meter, "enclave_http_errors_total", "Total HTTP responses with status 4xx or 5xx.")
	enclaveMetrics.KMSOperations = newCounter(meter, "enclave_kms_operations_total", "Total KMS Decrypt operations attempted.")
	enclaveMetrics.KMSErrors = newCounter(meter, "enclave_kms_errors_total", "Total failed KMS operations.")
	enclaveMetrics.StorageReads = newCounter(meter, "enclave_storage_reads_total", "Total encrypted storage read operations.")
	enclaveMetrics.StorageWrites = newCounter(meter, "enclave_storage_writes_total", "Total encrypted storage write operations.")
	enclaveMetrics.StorageDeletes = newCounter(meter, "enclave_storage_deletes_total", "Total encrypted storage delete operations.")
	enclaveMetrics.StorageErrors = newCounter(meter, "enclave_storage_errors_total", "Total failed storage operations.")
	enclaveMetrics.SecretReads = newCounter(meter, "enclave_secret_reads_total", "Total dynamic secret read operations.")
	enclaveMetrics.SecretWrites = newCounter(meter, "enclave_secret_writes_total", "Total dynamic secret write operations.")
	enclaveMetrics.SecretDeletes = newCounter(meter, "enclave_secret_deletes_total", "Total dynamic secret delete operations.")
	enclaveMetrics.LogEntries = newCounter(meter, "enclave_log_entries_total", "Total log entries accepted.")

	go enclaveMetrics.collectRuntime()
}

// newCounter creates and registers an OTEL counter, wrapping it to also track
// in our local counters map for snapshot export.
func newCounter(meter metric.Meter, name, desc string) metric.Int64Counter {
	c, err := meter.Int64Counter(name, metric.WithDescription(desc))
	if err != nil {
		slog.Warn("failed to create metric counter", "name", name, "error", err)
		c, _ = meter.Int64Counter(name) // fallback
	}
	return c
}

// Inc increments a counter by 1 and tracks it in the snapshot map.
func (m *Metrics) Inc(c metric.Int64Counter, name string) {
	c.Add(context.Background(), 1, metric.WithAttributes(attribute.String("source", "supervisor")))
	m.mu.Lock()
	m.counters[name]++
	m.mu.Unlock()
}

// IncBy increments a counter by n and tracks it in the snapshot map.
func (m *Metrics) IncBy(c metric.Int64Counter, name string, n int64) {
	c.Add(context.Background(), n, metric.WithAttributes(attribute.String("source", "supervisor")))
	m.mu.Lock()
	m.counters[name] += n
	m.mu.Unlock()
}

// MetricsSnapshot returns a structured snapshot of all metrics.
func (m *Metrics) MetricsSnapshot() map[string]any {
	m.mu.Lock()
	supervisor := make(map[string]int64, len(m.counters))
	for k, v := range m.counters {
		supervisor[k] = v
	}
	m.mu.Unlock()

	m.appMu.Lock()
	app := make(map[string]float64, len(m.appMetrics))
	for k, v := range m.appMetrics {
		app[k] = v
	}
	m.appMu.Unlock()

	m.runtimeMu.Lock()
	rt := make(map[string]float64, len(m.runtimeMetrics))
	for k, v := range m.runtimeMetrics {
		rt[k] = v
	}
	m.runtimeMu.Unlock()

	return map[string]any{
		"supervisor": supervisor,
		"app":        app,
		"runtime":    rt,
	}
}

// SetAppMetric stores a metric value received from the app via OTLP.
func (m *Metrics) SetAppMetric(name string, value float64) {
	m.appMu.Lock()
	m.appMetrics[name] = value
	m.appMu.Unlock()
}

// collectRuntime periodically collects Go runtime and /proc metrics.
func (m *Metrics) collectRuntime() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)

		m.runtimeMu.Lock()
		m.runtimeMetrics["goroutines"] = float64(runtime.NumGoroutine())
		m.runtimeMetrics["num_cpu"] = float64(runtime.NumCPU())
		m.runtimeMetrics["heap_alloc_bytes"] = float64(ms.HeapAlloc)
		m.runtimeMetrics["heap_sys_bytes"] = float64(ms.HeapSys)
		m.runtimeMetrics["gc_pause_total_ns"] = float64(ms.PauseTotalNs)
		m.runtimeMetrics["gc_num_gc"] = float64(ms.NumGC)
		m.runtimeMetrics["sys_bytes"] = float64(ms.Sys)

		// /proc metrics (graceful fallback if unavailable).
		if cpu, err := readProcCPU(); err == nil {
			for k, v := range cpu {
				m.runtimeMetrics[k] = v
			}
		}
		if mem, err := readProcMeminfo(); err == nil {
			for k, v := range mem {
				m.runtimeMetrics[k] = v
			}
		}
		m.runtimeMu.Unlock()
	}
}

// readProcCPU reads /proc/stat for CPU usage.
func readProcCPU() (map[string]float64, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return nil, fmt.Errorf("empty /proc/stat")
	}
	line := scanner.Text()
	if !strings.HasPrefix(line, "cpu ") {
		return nil, fmt.Errorf("unexpected /proc/stat format")
	}

	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil, fmt.Errorf("too few fields in /proc/stat")
	}

	result := make(map[string]float64)
	names := []string{"cpu_user", "cpu_nice", "cpu_system", "cpu_idle"}
	for i, name := range names {
		if v, err := strconv.ParseFloat(fields[i+1], 64); err == nil {
			result[name] = v
		}
	}
	return result, nil
}

// readProcMeminfo reads /proc/meminfo for memory info.
func readProcMeminfo() (map[string]float64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	result := make(map[string]float64)
	wanted := map[string]string{
		"MemTotal:":     "mem_total_kb",
		"MemFree:":      "mem_free_kb",
		"MemAvailable:": "mem_available_kb",
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for prefix, name := range wanted {
			if strings.HasPrefix(line, prefix) {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if v, err := strconv.ParseFloat(fields[1], 64); err == nil {
						result[name] = v
					}
				}
			}
		}
	}
	return result, nil
}

// handleMetricGet returns a JSON snapshot of all metrics.
// GET /v1/enclave-metrics
func (e *Enclave) handleMetricGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enclaveMetrics.MetricsSnapshot())
}

// handleMetricPost accepts OTLP metrics from the app.
// POST /v1/enclave-metrics (Content-Type: application/x-protobuf)
func (e *Enclave) handleMetricPost(w http.ResponseWriter, r *http.Request) {
	if !e.checkMgmtToken(w, r) {
		return
	}

	body := http.MaxBytesReader(w, r.Body, 1<<20)
	defer func() { _ = body.Close() }()

	data, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, `{"error":"read body failed"}`, http.StatusBadRequest)
		return
	}

	count, err := parseOTLPMetrics(data)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"parse OTLP metrics: %s"}`, err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]int{"accepted": count})
}
