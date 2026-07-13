package runtime

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

func TestMetricsCounters(t *testing.T) {
	t.Run("inc", func(t *testing.T) {
		metrics := NewMetrics()

		metrics.Inc(metrics.HTTPRequests, "http_requests_total")
		metrics.Inc(metrics.HTTPRequests, "http_requests_total")

		supervisor := metrics.MetricsSnapshot()["supervisor"].(map[string]int64)
		require.Equal(t, int64(2), supervisor["http_requests_total"])
	})

	t.Run("inc by", func(t *testing.T) {
		metrics := NewMetrics()

		metrics.IncBy(metrics.LogEntries, "log_entries_total", 5)

		supervisor := metrics.MetricsSnapshot()["supervisor"].(map[string]int64)
		require.Equal(t, int64(5), supervisor["log_entries_total"])
	})

	t.Run("concurrent inc", func(t *testing.T) {
		metrics := NewMetrics()
		var wg sync.WaitGroup

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				metrics.Inc(metrics.HTTPRequests, "http_requests_total")
			}()
		}
		wg.Wait()

		supervisor := metrics.MetricsSnapshot()["supervisor"].(map[string]int64)
		require.Equal(t, int64(100), supervisor["http_requests_total"])
	})
}

func TestMetricsSnapshot(t *testing.T) {
	snap := NewMetrics().MetricsSnapshot()

	require.IsType(t, map[string]int64{}, snap["supervisor"])
	require.IsType(t, map[string]float64{}, snap["app"])
	require.IsType(t, map[string]float64{}, snap["runtime"])
}

func TestMetricsAppMetrics(t *testing.T) {
	metrics := NewMetrics()

	metrics.SetAppMetric("custom_counter", 42)
	metrics.SetAppMetric("custom_counter", 99)

	app := metrics.MetricsSnapshot()["app"].(map[string]float64)
	require.Equal(t, 99.0, app["custom_counter"])
}

func TestMetricsUpdateFromOTLP(t *testing.T) {
	t.Run("sum int", func(t *testing.T) {
		metrics := NewMetrics()

		count, err := metrics.updateFromOTLPMetrics(buildOTLPSumMetric(t, "requests", 42))

		require.NoError(t, err)
		require.Equal(t, 1, count)
		app := metrics.MetricsSnapshot()["app"].(map[string]float64)
		require.Equal(t, 42.0, app["requests"])
	})

	t.Run("gauge double", func(t *testing.T) {
		metrics := NewMetrics()

		count, err := metrics.updateFromOTLPMetrics(buildOTLPGaugeMetric(t, "temperature", 3.14))

		require.NoError(t, err)
		require.Equal(t, 1, count)
		app := metrics.MetricsSnapshot()["app"].(map[string]float64)
		require.Equal(t, 3.14, app["temperature"])
	})

	t.Run("histogram sum count", func(t *testing.T) {
		metrics := NewMetrics()

		count, err := metrics.updateFromOTLPMetrics(buildOTLPHistogramMetric(t, "latency", 7.5, 3))

		require.NoError(t, err)
		require.Equal(t, 1, count)
		app := metrics.MetricsSnapshot()["app"].(map[string]float64)
		require.Equal(t, 7.5, app["latency_sum"])
		require.Equal(t, 3.0, app["latency_count"])
	})

	t.Run("invalid protobuf", func(t *testing.T) {
		metrics := NewMetrics()

		_, err := metrics.updateFromOTLPMetrics([]byte{0xff})

		require.Error(t, err)
	})
}

func TestMetricHandlers(t *testing.T) {
	t.Run("get returns snapshot", func(t *testing.T) {
		metrics := NewMetrics()
		metrics.Inc(metrics.HTTPRequests, "http_requests_total")
		metrics.SetAppMetric("custom", 2)
		w := httptest.NewRecorder()

		HandleMetricGet(metrics)(w, httptest.NewRequest(http.MethodGet, "/v1/enclave-metrics", nil))

		require.Equal(t, http.StatusOK, w.Code)
		require.JSONEq(t, `{
			"supervisor":{"http_requests_total":1},
			"app":{"custom":2},
			"runtime":{}
		}`, w.Body.String())
	})

	t.Run("post accepts otlp", func(t *testing.T) {
		metrics := NewMetrics()
		req := httptest.NewRequest(
			http.MethodPost,
			"/v1/metrics",
			bytes.NewReader(buildOTLPSumMetric(t, "posted_metric", 77)),
		)
		w := httptest.NewRecorder()

		HandleMetricPost(metrics)(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.JSONEq(t, `{"accepted":1}`, w.Body.String())
		app := metrics.MetricsSnapshot()["app"].(map[string]float64)
		require.Equal(t, 77.0, app["posted_metric"])
	})

	t.Run("post rejects invalid protobuf", func(t *testing.T) {
		metrics := NewMetrics()
		req := httptest.NewRequest(http.MethodPost, "/v1/metrics", bytes.NewReader([]byte{0xff}))
		w := httptest.NewRecorder()

		HandleMetricPost(metrics)(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestReadProcCPU(t *testing.T) {
	if _, err := os.Stat("/proc/stat"); err != nil {
		t.Skipf("/proc/stat unavailable: %v", err)
	}

	result, err := readProcCPU()

	require.NoError(t, err)
	require.Contains(t, result, "cpu_user")
	require.Contains(t, result, "cpu_idle")
}

func TestReadProcMeminfo(t *testing.T) {
	if _, err := os.Stat("/proc/meminfo"); err != nil {
		t.Skipf("/proc/meminfo unavailable: %v", err)
	}

	result, err := readProcMeminfo()

	require.NoError(t, err)
	require.Contains(t, result, "mem_total_kb")
}

func buildOTLPSumMetric(t *testing.T, name string, value int64) []byte {
	t.Helper()
	return buildOTLPMetricRequest(t, &metricspb.Metric{
		Name: name,
		Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{
			DataPoints: []*metricspb.NumberDataPoint{{
				Value: &metricspb.NumberDataPoint_AsInt{AsInt: value},
			}},
		}},
	})
}

func buildOTLPGaugeMetric(t *testing.T, name string, value float64) []byte {
	t.Helper()
	return buildOTLPMetricRequest(t, &metricspb.Metric{
		Name: name,
		Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{
			DataPoints: []*metricspb.NumberDataPoint{{
				Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: value},
			}},
		}},
	})
}

func buildOTLPHistogramMetric(t *testing.T, name string, sum float64, count uint64) []byte {
	t.Helper()
	return buildOTLPMetricRequest(t, &metricspb.Metric{
		Name: name,
		Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{
			DataPoints: []*metricspb.HistogramDataPoint{{
				Count: count,
				Sum:   &sum,
			}},
		}},
	})
}

func buildOTLPMetricRequest(t *testing.T, metric *metricspb.Metric) []byte {
	t.Helper()
	req := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			ScopeMetrics: []*metricspb.ScopeMetrics{{
				Metrics: []*metricspb.Metric{metric},
			}},
		}},
	}

	data, err := proto.Marshal(req)
	require.NoError(t, err)
	return data
}
