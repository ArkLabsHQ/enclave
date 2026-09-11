package runtime

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

// Metrics collects the enclave's own counters, the app's OTLP metrics and the
// process's own /proc readings into the snapshot that ships to CloudWatch.
//
// No OTel meter: the runtime never configures a MeterProvider, so instruments
// created here would write to the no-op default while the map below is what
// actually ships. The OTLP protos are still used to decode what the app sends.
type Metrics struct {
	// The enclave's own counters, accumulated for the snapshot.
	mu       sync.Mutex
	counters map[string]int64

	// App metrics received via OTLP, each keeping the semantics it arrived with.
	appMu      sync.Mutex
	appMetrics map[string]appMetricValue

	// Runtime/proc metrics (updated periodically).
	runtimeMu      sync.Mutex
	runtimeMetrics map[string]float64

	// Baselines for the per-interval deltas shipped to CloudWatch.
	deltas *deltaTracker
}

// Enclave counter names, as they appear in the snapshot.
const (
	metricHTTPRequests       = "enclave_http_requests_total"
	metricHTTPErrors         = "enclave_http_errors_total"
	metricAppProxiedRequests = "enclave_app_proxied_requests_total"
	metricAppProxiedErrors   = "enclave_app_proxied_errors_total"
	metricLogEntries         = "enclave_log_entries_total"
)

// NewMetrics starts runtime collection.
func NewMetrics() *Metrics {
	m := &Metrics{
		counters:       make(map[string]int64),
		appMetrics:     make(map[string]appMetricValue),
		runtimeMetrics: make(map[string]float64),
		deltas:         newDeltaTracker(),
	}
	go m.collectRuntime()
	return m
}

// Inc increments an enclave counter by 1.
func (m *Metrics) Inc(name string) { m.IncBy(name, 1) }

// IncBy increments an enclave counter by n.
func (m *Metrics) IncBy(name string, n int64) {
	m.mu.Lock()
	m.counters[name] += n
	m.mu.Unlock()
}

func (m *Metrics) Counter(name string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[name]
}

// MetricsSnapshot returns a structured snapshot of all metrics.
func (m *Metrics) MetricsSnapshot() map[string]any {
	m.mu.Lock()
	enclave := make(map[string]int64, len(m.counters))
	for k, v := range m.counters {
		enclave[k] = v
	}
	m.mu.Unlock()

	m.appMu.Lock()
	app := make(map[string]float64, len(m.appMetrics))
	for k, v := range m.appMetrics {
		app[k] = v.value
	}
	m.appMu.Unlock()

	m.runtimeMu.Lock()
	rt := make(map[string]float64, len(m.runtimeMetrics))
	for k, v := range m.runtimeMetrics {
		rt[k] = v
	}
	m.runtimeMu.Unlock()

	return map[string]any{
		"enclave": enclave,
		"app":     app,
		"runtime": rt,
	}
}

// SetAppMetric stores a sampled metric value received from the app.
func (m *Metrics) SetAppMetric(name string, value float64) {
	m.setAppMetric(name, value, appMetricValue{kind: kindGauge})
}

// setAppMetric stores an app reading under the semantics it arrived with.
// Pre-aggregated values accumulate across posts because each one reports a
// separate slice of time; everything else reports a level and overwrites.
func (m *Metrics) setAppMetric(name string, value float64, semantics appMetricValue) {
	m.appMu.Lock()
	defer m.appMu.Unlock()

	semantics.value = value
	if semantics.preAggregated {
		semantics.value += m.appMetrics[name].value
	}
	m.appMetrics[name] = semantics
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

// updateFromOTLPMetrics stores OTLP datapoints in m.appMetrics.
// Returns the number of data points processed.
func (m *Metrics) updateFromOTLPMetrics(body []byte) (int, error) {
	var req colmetricspb.ExportMetricsServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		return 0, fmt.Errorf("unmarshal OTLP metrics: %w", err)
	}

	count := 0
	for _, rm := range req.ResourceMetrics {
		for _, sm := range rm.ScopeMetrics {
			for _, metric := range sm.Metrics {
				name := metric.Name
				switch data := metric.Data.(type) {
				case *metricspb.Metric_Sum:
					// Only a monotonic sum is a counter. An up-down counter
					// reports a level, so it is sampled like a gauge.
					semantics := appMetricValue{kind: kindGauge}
					if data.Sum.IsMonotonic {
						semantics = sumSemantics(data.Sum.AggregationTemporality)
					}
					for _, dp := range data.Sum.DataPoints {
						m.setAppMetric(name, dataPointValue(dp), semantics)
						count++
					}
				case *metricspb.Metric_Gauge:
					for _, dp := range data.Gauge.DataPoints {
						m.setAppMetric(
							name, dataPointValue(dp), appMetricValue{kind: kindGauge},
						)
						count++
					}
				case *metricspb.Metric_Histogram:
					semantics := sumSemantics(data.Histogram.AggregationTemporality)
					for _, dp := range data.Histogram.DataPoints {
						if dp.Sum != nil {
							m.setAppMetric(name+"_sum", *dp.Sum, semantics)
						}
						m.setAppMetric(name+"_count", float64(dp.Count), semantics)
						count++
					}
				}
			}
		}
	}
	return count, nil
}

// readProcCPU reads CPU counters from /proc/stat.
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
	return parseProcCPU(scanner.Text())
}

// procCPUFields names the aggregate "cpu" line in order. Every one of them is a
// slice of elapsed time, so utilisation is only correct when all are summed.
// guest and guest_nice follow steal but are deliberately absent: the kernel
// already counts them inside user and nice, and reading them would double up.
var procCPUFields = []string{
	"cpu_user", "cpu_nice", "cpu_system", "cpu_idle",
	"cpu_iowait", "cpu_irq", "cpu_softirq", "cpu_steal",
}

// parseProcCPU reads the aggregate CPU line of /proc/stat. It takes however
// many counters the running kernel publishes, so an older one reporting fewer
// still yields what it has.
func parseProcCPU(line string) (map[string]float64, error) {
	if !strings.HasPrefix(line, "cpu ") {
		return nil, fmt.Errorf("unexpected /proc/stat format")
	}

	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil, fmt.Errorf("too few fields in /proc/stat")
	}

	result := make(map[string]float64, len(procCPUFields))
	for i, name := range procCPUFields {
		if i+1 >= len(fields) {
			break
		}
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

// HandleMetricPost accepts OTLP protobuf metrics.
func HandleMetricPost(metrics *Metrics) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := http.MaxBytesReader(w, r.Body, 1<<20)
		defer func() { _ = body.Close() }()

		data, err := io.ReadAll(body)
		if err != nil {
			http.Error(w, `{"error":"read body failed"}`, http.StatusBadRequest)
			return
		}

		count, err := metrics.updateFromOTLPMetrics(data)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf(`{"error":"parse OTLP metrics: %s"}`, err),
				http.StatusBadRequest,
			)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": count})
	}
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
