package runtime

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
)

func TestDeltaTracker(t *testing.T) {
	t.Run("zero-based counter emits its full value on the first interval", func(t *testing.T) {
		d := newDeltaTracker()

		got, emit := d.delta("enclave_http_requests_total", 7, seedZero)

		require.True(t, emit)
		require.Equal(t, float64(7), got)
	})

	t.Run("later intervals emit only the change since the last reading", func(t *testing.T) {
		d := newDeltaTracker()

		d.delta("enclave_http_requests_total", 7, seedZero)
		got, emit := d.delta("enclave_http_requests_total", 10, seedZero)

		require.True(t, emit)
		require.Equal(t, float64(3), got)
	})

	t.Run("a quiet interval emits zero, not the running total", func(t *testing.T) {
		d := newDeltaTracker()

		d.delta("enclave_http_requests_total", 7, seedZero)
		got, emit := d.delta("enclave_http_requests_total", 7, seedZero)

		require.True(t, emit)
		require.Equal(t, float64(0), got)
	})

	t.Run("a counter reset emits the new value instead of a negative delta", func(t *testing.T) {
		d := newDeltaTracker()

		d.delta("app_requests_total", 100, seedZero)
		got, emit := d.delta("app_requests_total", 4, seedZero)

		require.True(t, emit)
		require.Equal(t, float64(4), got)
	})

	t.Run("a series of unknown origin ships nothing on its first observation", func(t *testing.T) {
		d := newDeltaTracker()

		got, emit := d.delta("app_requests_total", 5_000, seedObserved)

		require.False(t, emit, "first observation must only seed the baseline")
		require.Equal(t, float64(0), got)
	})

	t.Run("a series of unknown origin ships deltas once seeded", func(t *testing.T) {
		d := newDeltaTracker()

		d.delta("app_requests_total", 5_000, seedObserved)
		got, emit := d.delta("app_requests_total", 5_012, seedObserved)

		require.True(t, emit)
		require.Equal(t, float64(12), got)
	})

	t.Run("series are tracked independently", func(t *testing.T) {
		d := newDeltaTracker()

		d.delta("a", 10, seedZero)
		d.delta("b", 100, seedZero)
		gotA, _ := d.delta("a", 15, seedZero)
		gotB, _ := d.delta("b", 250, seedZero)

		require.Equal(t, float64(5), gotA)
		require.Equal(t, float64(150), gotB)
	})
}

func TestRuntimeKind(t *testing.T) {
	counters := []string{
		"gc_pause_total_ns", "gc_num_gc",
		"cpu_user", "cpu_nice", "cpu_system", "cpu_idle",
	}
	for _, name := range counters {
		t.Run(name+" accumulates", func(t *testing.T) {
			require.Equal(t, kindCounter, runtimeKind(name))
		})
	}

	gauges := []string{
		"goroutines", "num_cpu", "heap_alloc_bytes", "heap_sys_bytes",
		"sys_bytes", "mem_total_kb", "mem_free_kb", "mem_available_kb",
	}
	for _, name := range gauges {
		t.Run(name+" is sampled", func(t *testing.T) {
			require.Equal(t, kindGauge, runtimeKind(name))
		})
	}

	t.Run("an unrecognised reading defaults to gauge", func(t *testing.T) {
		// Passing a counter through as a gauge is recoverable. Differencing a
		// gauge produces nonsense, so gauge is the safe default.
		require.Equal(t, kindGauge, runtimeKind("something_new"))
	})
}

func TestCloudWatchUnit(t *testing.T) {
	cases := map[string]struct {
		kind metricKind
		want string
	}{
		"heap_alloc_bytes":            {kindGauge, "Bytes"},
		"mem_free_kb":                 {kindGauge, "Kilobytes"},
		"enclave_http_requests_total": {kindCounter, "Count"},
		"gc_num_gc":                   {kindCounter, "Count"},
		"goroutines":                  {kindGauge, "None"},
		// CloudWatch has no Nanoseconds unit, so the suffix must win over the
		// counter rule rather than mislabel the value as a Count.
		"gc_pause_total_ns": {kindCounter, "None"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, cloudWatchUnit(name, tc.kind))
		})
	}
}

func TestSanitizeMetricName(t *testing.T) {
	t.Run("dots become underscores so OTLP names are valid EMF targets", func(t *testing.T) {
		require.Equal(t, "http_server_duration", sanitizeMetricName("http.server.duration"))
	})

	t.Run("an already-valid name is untouched", func(t *testing.T) {
		require.Equal(t, "enclave_http_requests_total", sanitizeMetricName("enclave_http_requests_total"))
	})
}

// directive digs out the single MetricDirective an EMF document carries.
func directive(t *testing.T, event map[string]any) map[string]any {
	t.Helper()
	meta, ok := event["_aws"].(map[string]any)
	require.True(t, ok, "_aws must be an object")
	directives, ok := meta["CloudWatchMetrics"].([]map[string]any)
	require.True(t, ok, "CloudWatchMetrics must be an array")
	require.Len(t, directives, 1)
	return directives[0]
}

func TestBuildEMFEvents(t *testing.T) {
	dims := map[string]string{"Deployment": "prod", "AppName": "arkd"}

	t.Run("builds a document matching the EMF schema", func(t *testing.T) {
		events := buildEMFEvents("Enclave", dims, []emfMetric{
			{Name: "enclave_http_requests_total", Unit: "Count", Value: 3},
		}, 1574109732004)

		require.Len(t, events, 1)
		d := directive(t, events[0])

		require.Equal(t, "Enclave", d["Namespace"])
		require.Equal(t, int64(1574109732004), events[0]["_aws"].(map[string]any)["Timestamp"])
		require.Equal(t, []map[string]any{
			{"Name": "enclave_http_requests_total", "Unit": "Count", "StorageResolution": 60},
		}, d["Metrics"])
	})

	t.Run("every metric name resolves to a numeric root member", func(t *testing.T) {
		events := buildEMFEvents("Enclave", dims, []emfMetric{
			{Name: "enclave_http_requests_total", Unit: "Count", Value: 3},
			{Name: "runtime_goroutines", Unit: "None", Value: 42},
		}, 1)

		require.Len(t, events, 1)
		require.Equal(t, float64(3), events[0]["enclave_http_requests_total"])
		require.Equal(t, float64(42), events[0]["runtime_goroutines"])
	})

	t.Run("every dimension key is declared and present as a string root member", func(t *testing.T) {
		events := buildEMFEvents("Enclave", dims, []emfMetric{
			{Name: "a", Unit: "Count", Value: 1},
		}, 1)

		d := directive(t, events[0])
		sets, ok := d["Dimensions"].([][]string)
		require.True(t, ok, "Dimensions must be an array of DimensionSets")
		require.Len(t, sets, 1)
		require.ElementsMatch(t, []string{"AppName", "Deployment"}, sets[0])

		for _, key := range sets[0] {
			require.Equal(t, dims[key], events[0][key], "dimension %s must be a string root member", key)
		}
	})

	t.Run("dimension keys are ordered so documents are stable", func(t *testing.T) {
		first := directive(t, buildEMFEvents("Enclave", dims, []emfMetric{{Name: "a"}}, 1)[0])
		second := directive(t, buildEMFEvents("Enclave", dims, []emfMetric{{Name: "a"}}, 1)[0])

		require.Equal(t, first["Dimensions"], second["Dimensions"])
		require.Equal(t, []string{"AppName", "Deployment"}, first["Dimensions"].([][]string)[0])
	})

	t.Run("more than 100 metrics split across documents", func(t *testing.T) {
		many := make([]emfMetric, 250)
		for i := range many {
			many[i] = emfMetric{Name: fmt.Sprintf("m_%03d", i), Unit: "Count", Value: float64(i)}
		}

		events := buildEMFEvents("Enclave", dims, many, 99)

		require.Len(t, events, 3, "250 metrics must split into 100+100+50")
		total := 0
		for _, event := range events {
			d := directive(t, event)
			count := len(d["Metrics"].([]map[string]any))
			require.LessOrEqual(t, count, 100)
			total += count
			// Every chunk must stand alone as a valid document.
			require.Equal(t, int64(99), event["_aws"].(map[string]any)["Timestamp"])
			require.Equal(t, "prod", event["Deployment"])
		}
		require.Equal(t, 250, total, "no metric may be dropped when splitting")
	})

	t.Run("a chunk carries only its own metric values", func(t *testing.T) {
		many := make([]emfMetric, 150)
		for i := range many {
			many[i] = emfMetric{Name: fmt.Sprintf("m_%03d", i), Unit: "Count", Value: float64(i)}
		}

		events := buildEMFEvents("Enclave", dims, many, 1)

		require.Len(t, events, 2)
		require.NotContains(t, events[0], "m_149")
		require.Contains(t, events[1], "m_149")
	})

	t.Run("no metrics produces no document", func(t *testing.T) {
		require.Empty(t, buildEMFEvents("Enclave", dims, nil, 1))
	})
}

func findMetric(metrics []emfMetric, name string) (emfMetric, bool) {
	for _, metric := range metrics {
		if metric.Name == name {
			return metric, true
		}
	}
	return emfMetric{}, false
}

func TestEMFMetricsEnclaveCounters(t *testing.T) {
	t.Run("counters ship as per-interval deltas", func(t *testing.T) {
		metrics := NewMetrics()
		metrics.IncBy(metricHTTPRequests, 7)

		first, ok := findMetric(metrics.emfMetrics(), metricHTTPRequests)
		require.True(t, ok)
		require.Equal(t, float64(7), first.Value)
		require.Equal(t, "Count", first.Unit)

		metrics.IncBy(metricHTTPRequests, 3)
		second, ok := findMetric(metrics.emfMetrics(), metricHTTPRequests)
		require.True(t, ok)
		require.Equal(t, float64(3), second.Value, "must be the change, not the running total")
	})

	t.Run("a quiet interval still ships a zero", func(t *testing.T) {
		metrics := NewMetrics()
		metrics.IncBy(metricHTTPRequests, 5)
		metrics.emfMetrics()

		quiet, ok := findMetric(metrics.emfMetrics(), metricHTTPRequests)
		require.True(t, ok)
		require.Equal(t, float64(0), quiet.Value)
	})
}

func TestEMFMetricsRuntime(t *testing.T) {
	t.Run("sampled readings pass through untouched every interval", func(t *testing.T) {
		metrics := NewMetrics()
		metrics.runtimeMu.Lock()
		metrics.runtimeMetrics["heap_alloc_bytes"] = 2048
		metrics.runtimeMu.Unlock()

		for i := 0; i < 2; i++ {
			got, ok := findMetric(metrics.emfMetrics(), "runtime_heap_alloc_bytes")
			require.True(t, ok)
			require.Equal(t, float64(2048), got.Value, "a gauge must never be differenced")
			require.Equal(t, "Bytes", got.Unit)
		}
	})

	t.Run("accumulating readings are differenced", func(t *testing.T) {
		metrics := NewMetrics()
		metrics.runtimeMu.Lock()
		metrics.runtimeMetrics["cpu_user"] = 100
		metrics.runtimeMu.Unlock()
		metrics.emfMetrics()

		metrics.runtimeMu.Lock()
		metrics.runtimeMetrics["cpu_user"] = 130
		metrics.runtimeMu.Unlock()

		got, ok := findMetric(metrics.emfMetrics(), "runtime_cpu_user")
		require.True(t, ok)
		require.Equal(t, float64(30), got.Value)
	})
}

func TestEMFMetricsApp(t *testing.T) {
	t.Run("a cumulative counter seeds silently then ships deltas", func(t *testing.T) {
		metrics := NewMetrics()
		_, err := metrics.updateFromOTLPMetrics(
			buildOTLPSum(t, "requests", 5000, monotonic, cumulative))
		require.NoError(t, err)

		_, found := findMetric(metrics.emfMetrics(), "app_requests")
		require.False(t, found, "the first observation must not ship its lifetime total")

		_, err = metrics.updateFromOTLPMetrics(
			buildOTLPSum(t, "requests", 5012, monotonic, cumulative))
		require.NoError(t, err)

		got, ok := findMetric(metrics.emfMetrics(), "app_requests")
		require.True(t, ok)
		require.Equal(t, float64(12), got.Value)
	})

	t.Run("a delta counter accumulates within the interval and resets after", func(t *testing.T) {
		metrics := NewMetrics()
		for _, v := range []int64{3, 4, 5} {
			_, err := metrics.updateFromOTLPMetrics(
				buildOTLPSum(t, "requests", v, monotonic, deltaTemporality))
			require.NoError(t, err)
		}

		got, ok := findMetric(metrics.emfMetrics(), "app_requests")
		require.True(t, ok)
		require.Equal(t, float64(12), got.Value, "posts within an interval must sum, not overwrite")

		next, ok := findMetric(metrics.emfMetrics(), "app_requests")
		require.True(t, ok)
		require.Equal(t, float64(0), next.Value, "the bucket must reset once shipped")
	})

	t.Run("a gauge passes through every interval", func(t *testing.T) {
		metrics := NewMetrics()
		_, err := metrics.updateFromOTLPMetrics(buildOTLPGaugeMetric(t, "temperature", 3.5))
		require.NoError(t, err)

		for i := 0; i < 2; i++ {
			got, ok := findMetric(metrics.emfMetrics(), "app_temperature")
			require.True(t, ok)
			require.Equal(t, 3.5, got.Value)
		}
	})

	t.Run("a non-monotonic sum is treated as a gauge", func(t *testing.T) {
		metrics := NewMetrics()
		_, err := metrics.updateFromOTLPMetrics(
			buildOTLPSum(t, "queue_depth", 9, upDown, cumulative))
		require.NoError(t, err)

		got, ok := findMetric(metrics.emfMetrics(), "app_queue_depth")
		require.True(t, ok, "an up-down counter is sampled, so it ships immediately")
		require.Equal(t, float64(9), got.Value)
	})

	t.Run("OTLP dots become underscores", func(t *testing.T) {
		metrics := NewMetrics()
		_, err := metrics.updateFromOTLPMetrics(buildOTLPGaugeMetric(t, "http.server.active", 2))
		require.NoError(t, err)

		_, ok := findMetric(metrics.emfMetrics(), "app_http_server_active")
		require.True(t, ok)
	})
}

func TestEMFMetricsOrdering(t *testing.T) {
	t.Run("output is sorted so documents stay stable", func(t *testing.T) {
		metrics := NewMetrics()
		metrics.IncBy(metricHTTPRequests, 1)
		metrics.IncBy(metricLogEntries, 1)

		got := metrics.emfMetrics()

		names := make([]string, len(got))
		for i, metric := range got {
			names[i] = metric.Name
		}
		require.True(t, sort.StringsAreSorted(names), "got %v", names)
	})
}

const (
	monotonic        = true
	upDown           = false
	cumulative       = metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE
	deltaTemporality = metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA
)

func buildOTLPSum(
	t *testing.T,
	name string,
	value int64,
	isMonotonic bool,
	temporality metricspb.AggregationTemporality,
) []byte {
	t.Helper()
	return buildOTLPMetricRequest(t, &metricspb.Metric{
		Name: name,
		Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{
			IsMonotonic:            isMonotonic,
			AggregationTemporality: temporality,
			DataPoints: []*metricspb.NumberDataPoint{{
				Value: &metricspb.NumberDataPoint_AsInt{AsInt: value},
			}},
		}},
	})
}
