package sdk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

func init() {
	// Initialize OTEL metrics for tests.
	InitMetrics()
}

// --- Inc / IncBy tests ---

func TestMetrics_Inc(t *testing.T) {
	// Reset counters for this test.
	enclaveMetrics.mu.Lock()
	enclaveMetrics.counters = make(map[string]int64)
	enclaveMetrics.mu.Unlock()

	enclaveMetrics.Inc(enclaveMetrics.HTTPRequests, "http_requests_total")
	enclaveMetrics.Inc(enclaveMetrics.HTTPRequests, "http_requests_total")

	snap := enclaveMetrics.MetricsSnapshot()
	sup, ok := snap["supervisor"].(map[string]int64)
	if !ok {
		t.Fatal("expected supervisor section")
	}
	if sup["http_requests_total"] != 2 {
		t.Fatalf("expected 2, got %d", sup["http_requests_total"])
	}
}

func TestMetrics_IncBy(t *testing.T) {
	enclaveMetrics.mu.Lock()
	enclaveMetrics.counters = make(map[string]int64)
	enclaveMetrics.mu.Unlock()

	enclaveMetrics.IncBy(enclaveMetrics.LogEntries, "log_entries_total", 5)

	snap := enclaveMetrics.MetricsSnapshot()
	sup := snap["supervisor"].(map[string]int64)
	if sup["log_entries_total"] != 5 {
		t.Fatalf("expected 5, got %d", sup["log_entries_total"])
	}
}

func TestMetrics_Inc_Concurrent(t *testing.T) {
	enclaveMetrics.mu.Lock()
	enclaveMetrics.counters = make(map[string]int64)
	enclaveMetrics.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			enclaveMetrics.Inc(enclaveMetrics.HTTPRequests, "http_requests_total")
		}()
	}
	wg.Wait()

	snap := enclaveMetrics.MetricsSnapshot()
	sup := snap["supervisor"].(map[string]int64)
	if sup["http_requests_total"] != 100 {
		t.Fatalf("expected 100, got %d", sup["http_requests_total"])
	}
}

// --- MetricsSnapshot tests ---

func TestMetricsSnapshot_Structure(t *testing.T) {
	snap := enclaveMetrics.MetricsSnapshot()

	if _, ok := snap["supervisor"]; !ok {
		t.Fatal("missing supervisor section")
	}
	if _, ok := snap["app"]; !ok {
		t.Fatal("missing app section")
	}
	if _, ok := snap["runtime"]; !ok {
		t.Fatal("missing runtime section")
	}
}

// --- SetAppMetric tests ---

func TestSetAppMetric(t *testing.T) {
	enclaveMetrics.appMu.Lock()
	enclaveMetrics.appMetrics = make(map[string]float64)
	enclaveMetrics.appMu.Unlock()

	enclaveMetrics.SetAppMetric("custom_counter", 42.0)
	enclaveMetrics.SetAppMetric("custom_counter", 99.0) // overwrite

	snap := enclaveMetrics.MetricsSnapshot()
	app := snap["app"].(map[string]float64)
	if app["custom_counter"] != 99.0 {
		t.Fatalf("expected 99, got %v", app["custom_counter"])
	}
}

// --- parseOTLPMetrics tests ---

func buildOTLPMetricRequest(name string, value int64) []byte {
	req := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: &resourcepb.Resource{},
			ScopeMetrics: []*metricspb.ScopeMetrics{{
				Metrics: []*metricspb.Metric{{
					Name: name,
					Data: &metricspb.Metric_Sum{
						Sum: &metricspb.Sum{
							DataPoints: []*metricspb.NumberDataPoint{{
								Value: &metricspb.NumberDataPoint_AsInt{AsInt: value},
							}},
						},
					},
				}},
			}},
		}},
	}
	data, _ := proto.Marshal(req)
	return data
}

func TestParseOTLPMetrics_Sum(t *testing.T) {
	enclaveMetrics.appMu.Lock()
	enclaveMetrics.appMetrics = make(map[string]float64)
	enclaveMetrics.appMu.Unlock()

	data := buildOTLPMetricRequest("test_counter", 42)
	count, err := parseOTLPMetrics(data)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 data point, got %d", count)
	}

	snap := enclaveMetrics.MetricsSnapshot()
	app := snap["app"].(map[string]float64)
	if app["test_counter"] != 42.0 {
		t.Fatalf("expected 42, got %v", app["test_counter"])
	}
}

func TestParseOTLPMetrics_Gauge(t *testing.T) {
	enclaveMetrics.appMu.Lock()
	enclaveMetrics.appMetrics = make(map[string]float64)
	enclaveMetrics.appMu.Unlock()

	req := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			ScopeMetrics: []*metricspb.ScopeMetrics{{
				Metrics: []*metricspb.Metric{{
					Name: "test_gauge",
					Data: &metricspb.Metric_Gauge{
						Gauge: &metricspb.Gauge{
							DataPoints: []*metricspb.NumberDataPoint{{
								Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: 3.14},
							}},
						},
					},
				}},
			}},
		}},
	}
	data, _ := proto.Marshal(req)
	count, err := parseOTLPMetrics(data)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1, got %d", count)
	}

	snap := enclaveMetrics.MetricsSnapshot()
	app := snap["app"].(map[string]float64)
	if app["test_gauge"] != 3.14 {
		t.Fatalf("expected 3.14, got %v", app["test_gauge"])
	}
}

func TestParseOTLPMetrics_InvalidProtobuf(t *testing.T) {
	_, err := parseOTLPMetrics([]byte("bad data"))
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- HTTP handler tests ---

func TestHandleMetricGet(t *testing.T) {
	enc := newTestEnclave(t)
	req := httptest.NewRequest("GET", "/v1/enclave-metrics", nil)
	w := httptest.NewRecorder()
	enc.handleMetricGet(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var snap map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if _, ok := snap["supervisor"]; !ok {
		t.Fatal("missing supervisor section")
	}
}

func TestHandleMetricPost_NoAuth(t *testing.T) {
	enc := newTestEnclave(t)
	body := buildOTLPMetricRequest("test", 1)
	req := httptest.NewRequest("POST", "/v1/enclave-metrics", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()
	enc.handleMetricPost(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleMetricPost_Valid(t *testing.T) {
	enc := newTestEnclave(t)
	body := buildOTLPMetricRequest("posted_metric", 77)
	req := httptest.NewRequest("POST", "/v1/enclave-metrics", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer "+enc.MgmtToken())
	w := httptest.NewRecorder()
	enc.handleMetricPost(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- /proc parsing tests ---

func TestReadProcCPU(t *testing.T) {
	result, err := readProcCPU()
	if err != nil {
		t.Skipf("skipping (no /proc/stat): %v", err)
	}
	if _, ok := result["cpu_user"]; !ok {
		t.Fatal("missing cpu_user")
	}
	if _, ok := result["cpu_idle"]; !ok {
		t.Fatal("missing cpu_idle")
	}
}

func TestReadProcMeminfo(t *testing.T) {
	result, err := readProcMeminfo()
	if err != nil {
		t.Skipf("skipping (no /proc/meminfo): %v", err)
	}
	if _, ok := result["mem_total_kb"]; !ok {
		t.Fatal("missing mem_total_kb")
	}
}
