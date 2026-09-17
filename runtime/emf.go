package runtime

import (
	"sort"
	"strings"
	"sync"

	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
)

const (
	// emfMaxMetricsPerDocument is the MetricDefinition ceiling one EMF
	// MetricDirective may carry. Past it the snapshot splits across documents.
	emfMaxMetricsPerDocument = 100
	// emfStorageResolution keeps metrics at standard 1-minute resolution. The
	// shipper runs faster than that, so several deltas land in one bucket and
	// SUM over the bucket gives the per-minute total.
	emfStorageResolution = 60
)

// emfMetric is one value and its declaration, ready to be placed in a document.
type emfMetric struct {
	Name  string
	Unit  string
	Value float64
}

// Prefixes keeping the three metric groups in one flat EMF namespace. EMF
// targets must sit on the document root, so the grouping that used to be JSON
// nesting becomes part of the name.
const (
	runtimeMetricPrefix = "runtime_"
	appMetricPrefix     = "app_"
)

// appMetricValue is an app reading plus the OTLP semantics needed to ship it.
type appMetricValue struct {
	value float64
	kind  metricKind
	// preAggregated marks a value the app already reduced to a delta. It
	// accumulates across posts within an interval and resets once shipped,
	// rather than being differenced again here.
	preAggregated bool
}

// sumSemantics maps an OTLP temporality onto how the value must be handled.
// Unspecified temporality is treated as cumulative, matching the default of
// the OpenTelemetry SDKs that post here.
func sumSemantics(temporality metricspb.AggregationTemporality) appMetricValue {
	return appMetricValue{
		kind: kindCounter,
		preAggregated: temporality ==
			metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
	}
}

// emfMetrics reduces the current readings to the values one shipping interval
// should carry. Counters are differenced against the previous call, so it
// advances the baselines and must run once per interval.
func (m *Metrics) emfMetrics() []emfMetric {
	var out []emfMetric

	add := func(name string, kind metricKind, value float64) {
		out = append(out, emfMetric{
			Name: name, Unit: cloudWatchUnit(name, kind), Value: value,
		})
	}
	// Counters that provably start at zero, so the first interval is already a
	// delta and ships in full.
	addCounter := func(name string, value float64) {
		if delta, emit := m.deltas.delta(name, value, seedZero); emit {
			add(name, kindCounter, delta)
		}
	}

	m.mu.Lock()
	enclave := make(map[string]int64, len(m.counters))
	for name, value := range m.counters {
		enclave[name] = value
	}
	m.mu.Unlock()
	for name, value := range enclave {
		addCounter(name, float64(value))
	}

	m.runtimeMu.Lock()
	runtimeReadings := make(map[string]float64, len(m.runtimeMetrics))
	for name, value := range m.runtimeMetrics {
		runtimeReadings[name] = value
	}
	m.runtimeMu.Unlock()
	for name, value := range runtimeReadings {
		prefixed := runtimeMetricPrefix + name
		if runtimeKind(name) == kindGauge {
			add(prefixed, kindGauge, value)
			continue
		}
		addCounter(prefixed, value)
	}

	// Draining and resetting the pre-aggregated buckets happens under one lock
	// so a post landing mid-drain is counted in exactly one interval.
	m.appMu.Lock()
	app := make(map[string]appMetricValue, len(m.appMetrics))
	for name, reading := range m.appMetrics {
		app[name] = reading
		if reading.preAggregated {
			reading.value = 0
			m.appMetrics[name] = reading
		}
	}
	m.appMu.Unlock()

	for name, reading := range app {
		prefixed := appMetricPrefix + sanitizeMetricName(name)
		// A gauge reports a level and a pre-aggregated counter is already a
		// delta. Only a cumulative counter needs differencing, and its origin
		// is unknown, so its first observation only seeds the baseline.
		if reading.kind == kindGauge || reading.preAggregated {
			add(prefixed, reading.kind, reading.value)
			continue
		}
		if delta, emit := m.deltas.delta(prefixed, reading.value, seedObserved); emit {
			add(prefixed, kindCounter, delta)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// buildEMFEvents renders a snapshot as CloudWatch embedded metric format
// documents. Each document stands alone: it repeats the timestamp and the
// dimension set and carries only the values it declares.
func buildEMFEvents(
	namespace string, dims map[string]string, metrics []emfMetric, tsMillis int64,
) []map[string]any {
	if len(metrics) == 0 {
		return nil
	}

	// Sorted so a document's shape depends only on its content.
	keys := make([]string, 0, len(dims))
	for key := range dims {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var events []map[string]any
	for start := 0; start < len(metrics); start += emfMaxMetricsPerDocument {
		end := start + emfMaxMetricsPerDocument
		if end > len(metrics) {
			end = len(metrics)
		}
		chunk := metrics[start:end]

		event := make(map[string]any, len(chunk)+len(keys)+1)
		defs := make([]map[string]any, 0, len(chunk))
		for _, metric := range chunk {
			def := map[string]any{
				"Name":              metric.Name,
				"StorageResolution": emfStorageResolution,
			}
			// An empty unit is omitted rather than sent, because the schema
			// validates Unit against a fixed enum that has no empty member.
			if metric.Unit != "" {
				def["Unit"] = metric.Unit
			}
			defs = append(defs, def)
			event[metric.Name] = metric.Value
		}
		for _, key := range keys {
			event[key] = dims[key]
		}
		event["_aws"] = map[string]any{
			"Timestamp": tsMillis,
			"CloudWatchMetrics": []map[string]any{{
				"Namespace":  namespace,
				"Dimensions": [][]string{keys},
				"Metrics":    defs,
			}},
		}
		events = append(events, event)
	}
	return events
}

// metricKind says whether a series accumulates over the process lifetime or is
// sampled fresh each collection. Only counters are differenced.
type metricKind int

const (
	kindGauge metricKind = iota
	kindCounter
)

// runtimeCounters are the readings in Metrics.runtimeMetrics that accumulate.
// Everything else collected there is a point-in-time sample.
var runtimeCounters = map[string]bool{
	"gc_pause_total_ns": true,
	"gc_num_gc":         true,
	"cpu_user":          true,
	"cpu_nice":          true,
	"cpu_system":        true,
	"cpu_idle":          true,
	"cpu_iowait":        true,
	"cpu_irq":           true,
	"cpu_softirq":       true,
	"cpu_steal":         true,
}

// runtimeKind classifies a runtime or /proc reading. Unknown names default to
// gauge: shipping a counter as a gauge is recoverable, but differencing a gauge
// is not.
func runtimeKind(name string) metricKind {
	if runtimeCounters[name] {
		return kindCounter
	}
	return kindGauge
}

// unitBySuffix maps a name suffix to a CloudWatch unit. Checked before the
// counter rule so a nanosecond total is not mislabelled as a Count.
var unitBySuffix = []struct {
	suffix string
	unit   string
}{
	{"_bytes", "Bytes"},
	{"_kb", "Kilobytes"},
	// CloudWatch has no Nanoseconds unit, so the value ships unlabelled rather
	// than renamed or misdeclared.
	{"_ns", "None"},
}

// cloudWatchUnit infers a unit accepted by the EMF schema. Anything it cannot
// place is None, which the specification treats as the default.
func cloudWatchUnit(name string, kind metricKind) string {
	for _, s := range unitBySuffix {
		if strings.HasSuffix(name, s.suffix) {
			return s.unit
		}
	}
	if kind == kindCounter {
		return "Count"
	}
	return "None"
}

// sanitizeMetricName rewrites a name into a valid EMF target member. Dots are
// replaced because OTLP names use them freely and they read as nesting.
func sanitizeMetricName(name string) string {
	return strings.ReplaceAll(name, ".", "_")
}

// seeding tells deltaTracker how to treat the first observation of a series.
type seeding bool

const (
	// seedZero marks a series known to start at zero, so its first observation
	// is already the delta and ships immediately.
	seedZero seeding = true
	// seedObserved marks a series of unknown origin. Its first observation only
	// establishes the baseline and ships nothing, so a late-connecting app does
	// not dump its lifetime total as one spike.
	seedObserved seeding = false
)

// deltaTracker converts cumulative counter readings into per-interval deltas.
type deltaTracker struct {
	mu   sync.Mutex
	prev map[string]float64
}

func newDeltaTracker() *deltaTracker {
	return &deltaTracker{prev: make(map[string]float64)}
}

// delta returns the change in a cumulative series since the last call and
// whether that change should be shipped. It advances the baseline, so each
// reading is reported exactly once.
func (d *deltaTracker) delta(name string, cur float64, seed seeding) (float64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	prev, known := d.prev[name]
	d.prev[name] = cur
	if !known && seed == seedObserved {
		return 0, false
	}
	// A drop means the source restarted its count, so the current reading is
	// itself the delta.
	if cur < prev {
		return cur, true
	}
	return cur - prev, true
}
