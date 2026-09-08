package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

		metrics.Inc(metricHTTPRequests)
		metrics.Inc(metricHTTPRequests)

		enclave := metrics.MetricsSnapshot()["enclave"].(map[string]int64)
		require.Equal(t, int64(2), enclave[metricHTTPRequests])
	})

	t.Run("inc by", func(t *testing.T) {
		metrics := NewMetrics()

		metrics.IncBy(metricLogEntries, 5)

		enclave := metrics.MetricsSnapshot()["enclave"].(map[string]int64)
		require.Equal(t, int64(5), enclave[metricLogEntries])
	})

	t.Run("concurrent inc", func(t *testing.T) {
		metrics := NewMetrics()
		var wg sync.WaitGroup

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				metrics.Inc(metricHTTPRequests)
			}()
		}
		wg.Wait()

		enclave := metrics.MetricsSnapshot()["enclave"].(map[string]int64)
		require.Equal(t, int64(100), enclave[metricHTTPRequests])
	})
}

func TestMetricsSnapshot(t *testing.T) {
	snap := NewMetrics().MetricsSnapshot()

	require.IsType(t, map[string]int64{}, snap["enclave"])
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

func fillAppMetrics(m *Metrics, nameLen int) int {
	stored := 0
	for i := 0; i < 100000; i++ {
		name := fmt.Sprintf("%0*d", nameLen, i)
		m.SetAppMetric(name, -1.7976931348623157e+308)
		if _, ok := m.MetricsSnapshot()["app"].(map[string]float64)[name]; ok {
			stored++
		} else {
			break
		}
	}
	return stored
}

func TestSetAppMetricBoundsRetainedNames(t *testing.T) {
	// The snapshot ships as one CloudWatch event, so the budget has to hold at
	// every name length, not just the short ones.
	t.Run("snapshot fits one event at every name length", func(t *testing.T) {
		for _, nameLen := range []int{8, 20, 40, 64, 128, 256, 4096} {
			m := NewMetrics()
			stored := fillAppMetrics(m, nameLen)

			raw, err := json.Marshal(m.MetricsSnapshot())
			require.NoError(t, err)
			require.Less(t, len(raw)+eventOverhead, maxEventBytes,
				"nameLen=%d stored=%d produced a %d byte snapshot", nameLen, stored, len(raw))
			require.Positive(t, m.Counter(metricAppMetricsDropped),
				"nameLen=%d never reached the budget", nameLen)
			t.Logf("nameLen=%-3d stored=%-5d snapshot=%.1f KiB",
				nameLen, stored, float64(len(raw))/1024)
		}
	})

	// json escaping expands < > & and control characters sixfold, so a budget
	// charging raw name length would ship a snapshot several times the limit.
	t.Run("charges names what they serialize to", func(t *testing.T) {
		for _, ch := range []string{"a", "<", `"`, "\x01", "\u00e9"} {
			m := NewMetrics()
			for i := 0; i < 20000; i++ {
				m.SetAppMetric(strings.Repeat(ch, 64)+fmt.Sprintf("%08d", i),
					-math.MaxFloat64)
			}

			raw, err := json.Marshal(m.MetricsSnapshot())
			require.NoError(t, err)
			require.Less(t, len(raw)+eventOverhead, maxEventBytes,
				"names of %q produced a %d byte snapshot", ch, len(raw))
		}
	})

	t.Run("short names buy more of them", func(t *testing.T) {
		short, long := NewMetrics(), NewMetrics()

		require.Greater(t, fillAppMetrics(short, 20), fillAppMetrics(long, 256),
			"the budget is serialized bytes, so short names must admit more entries")
	})

	t.Run("keeps updating names already stored", func(t *testing.T) {
		m := NewMetrics()
		fillAppMetrics(m, 20)
		first := fmt.Sprintf("%020d", 0)

		m.SetAppMetric(first, 42)
		m.SetAppMetric("displaced_by_the_budget", 1)

		app := m.MetricsSnapshot()["app"].(map[string]float64)
		require.Equal(t, float64(42), app[first],
			"a full budget must not stop existing metrics from reporting")
		require.NotContains(t, app, "displaced_by_the_budget")
	})

	t.Run("refuses a name larger than the whole budget", func(t *testing.T) {
		m := NewMetrics()
		m.SetAppMetric(strings.Repeat("n", maxAppMetricBytes+1), 1)
		m.SetAppMetric("app_requests_total", 1)

		app := m.MetricsSnapshot()["app"].(map[string]float64)
		require.Len(t, app, 1, "the budget alone must refuse a name it cannot afford")
		require.Contains(t, app, "app_requests_total")
		require.Equal(t, int64(1), m.Counter(metricAppMetricsDropped))
	})

	t.Run("stays bounded under concurrent ingestion", func(t *testing.T) {
		m := NewMetrics()
		var wg sync.WaitGroup
		for w := 0; w < 8; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := 0; i < 20000; i++ {
					m.SetAppMetric(fmt.Sprintf("w%d_metric_%06d", w, i), float64(i))
				}
			}(w)
		}
		wg.Wait()

		raw, err := json.Marshal(m.MetricsSnapshot())
		require.NoError(t, err)
		require.Less(t, len(raw)+eventOverhead, maxEventBytes)
	})
}
