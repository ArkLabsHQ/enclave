package runtime

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
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

// Metrics holds OTEL metric instruments for the enclave supervisor.
type Metrics struct {
	// Supervisor counters.
	HTTPRequests       metric.Int64Counter
	HTTPErrors         metric.Int64Counter
	AppProxiedRequests metric.Int64Counter // requests forwarded to the user app via revProxy
	AppProxiedErrors   metric.Int64Counter // failures dialing or talking to the user app
	KMSOperations      metric.Int64Counter
	KMSErrors          metric.Int64Counter
	LogEntries         metric.Int64Counter

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

// enclaveMetrics is the package-level pointer set by InitMetrics() / NewMetrics().
// Phase-B1 migration step: converted from a value-typed global into a pointer
// initialised by a constructor. Phase-C subsystems take *Metrics by injection
// instead of reading this var, after which it is removed.
var enclaveMetrics *Metrics

// GetMetrics returns the package-level metrics instance.
func GetMetrics() *Metrics {
	return enclaveMetrics
}

// NewMetrics builds a fresh Metrics instance with all OTEL counters
// registered and the runtime/proc collector started in the background.
func NewMetrics() *Metrics {
	m := &Metrics{
		counters:       make(map[string]int64),
		appMetrics:     make(map[string]float64),
		runtimeMetrics: make(map[string]float64),
	}
	meter := otel.Meter("runtime")
	m.HTTPRequests = newCounter(meter, "enclave_http_requests_total", "Total HTTP requests handled by the enclave supervisor.")
	m.HTTPErrors = newCounter(meter, "enclave_http_errors_total", "Total HTTP responses with status 4xx or 5xx.")
	m.AppProxiedRequests = newCounter(meter, "enclave_app_proxied_requests_total", "Total requests forwarded to the user app via the reverse proxy.")
	m.AppProxiedErrors = newCounter(meter, "enclave_app_proxied_errors_total", "Total failures forwarding requests to the user app (dial / connect errors).")
	m.KMSOperations = newCounter(meter, "enclave_kms_operations_total", "Total KMS Decrypt operations attempted.")
	m.KMSErrors = newCounter(meter, "enclave_kms_errors_total", "Total failed KMS operations.")
	m.LogEntries = newCounter(meter, "enclave_log_entries_total", "Total log entries accepted.")
	go m.collectRuntime()
	return m
}

// InitMetrics initializes the package-level singleton. Kept for the legacy
// cmd/runtime/main.go entry point that calls it before runtime.New().
func InitMetrics() {
	enclaveMetrics = NewMetrics()
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
func (e *Runtime) handleMetricGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enclaveMetrics.MetricsSnapshot())
}

// handleMetricPost accepts OTLP metrics from the app.
// POST /v1/metrics (Content-Type: application/x-protobuf)
func (e *Runtime) handleMetricPost(w http.ResponseWriter, r *http.Request) {
	if !e.checkRuntimeToken(w, r) {
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

// parseOTLPMetrics parses an OTLP ExportMetricsServiceRequest and stores
// the metric values in the global enclaveMetrics.appMetrics map.
// Returns the number of data points processed.
func parseOTLPMetrics(body []byte) (int, error) {
	var req colmetricspb.ExportMetricsServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		return 0, fmt.Errorf("unmarshal OTLP metrics: %w", err)
	}

	count := 0
	for _, rm := range req.ResourceMetrics {
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				name := m.Name
				switch data := m.Data.(type) {
				case *metricspb.Metric_Sum:
					for _, dp := range data.Sum.DataPoints {
						val := dataPointValue(dp)
						enclaveMetrics.SetAppMetric(name, val)
						count++
					}
				case *metricspb.Metric_Gauge:
					for _, dp := range data.Gauge.DataPoints {
						val := dataPointValue(dp)
						enclaveMetrics.SetAppMetric(name, val)
						count++
					}
				case *metricspb.Metric_Histogram:
					for _, dp := range data.Histogram.DataPoints {
						if dp.Sum != nil {
							enclaveMetrics.SetAppMetric(name+"_sum", *dp.Sum)
						}
						enclaveMetrics.SetAppMetric(name+"_count", float64(dp.Count))
						count++
					}
				}
			}
		}
	}
	return count, nil
}

// dataPointValue extracts the numeric value from a NumberDataPoint.
func dataPointValue(dp *metricspb.NumberDataPoint) float64 {
	switch v := dp.Value.(type) {
	case *metricspb.NumberDataPoint_AsInt:
		return float64(v.AsInt)
	case *metricspb.NumberDataPoint_AsDouble:
		return v.AsDouble
	default:
		return 0
	}
}
