package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestEverySignalHasAUniqueName(t *testing.T) {
	seen := make(map[string]bool, signalCount)
	for sig := signal(0); sig < signalCount; sig++ {
		name := sig.String()
		require.NotEmpty(t, name, "signal %d has no name", int(sig))
		require.NotEqual(t, "unknown", name, "signal %d has no name", int(sig))
		require.False(t, seen[name], "signal name %q is used twice", name)
		seen[name] = true
	}
	require.Equal(t, "unknown", signalCount.String(), "the sentinel must not name a stream")
}

func TestJSONErrorEncodesTheMessage(t *testing.T) {
	body := jsonError(`quote " backslash \ and <angle>`)

	var decoded map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &decoded))
	require.Equal(t, `quote " backslash \ and <angle>`, decoded["error"])
}

func TestStartFailsWithoutAnInstanceID(t *testing.T) {
	before := slog.Default()
	t.Cleanup(func() { slog.SetDefault(before) })

	cfg := *testCfg
	cfg.InstanceID = ""
	cw := newFakeCloudWatchLogs()
	up := newFakeOTLPEndpoints(t)

	err := NewTelemetry(&cfg, testAWS(t, cw, up.URL)).Start(context.Background())

	require.ErrorContains(t, err, "no instance ID from IMDS")
	require.Empty(t, cw.groups, "an unusable stream name must fail before any group is created")
	require.Empty(t, up.calls)
	require.Same(t, before, slog.Default())
}

func TestTelemetryLeavesSlogAloneWhenStartFails(t *testing.T) {
	before := slog.Default()
	t.Cleanup(func() { slog.SetDefault(before) })

	sentinel := errors.New("create group failed")
	cw := newFakeCloudWatchLogs()
	cw.createLogGroupErr = sentinel
	up := newFakeOTLPEndpoints(t)

	err := NewTelemetry(testCfg, testAWS(t, cw, up.URL)).Start(context.Background())

	require.ErrorIs(t, err, sentinel)
	require.ErrorContains(t, err, "cloudwatch export")
	require.Same(t, before, slog.Default())
}

func TestStartCreatesTwoGroupsAndProbesTheLogsEndpoint(t *testing.T) {
	cw := newFakeCloudWatchLogs()
	up := newFakeOTLPEndpoints(t)
	telemetry := NewTelemetry(testConfigWithLogShipInterval(time.Hour), testAWS(t, cw, up.URL))

	startTelemetry(t, context.Background(), telemetry)

	require.ElementsMatch(t, []string{
		"/prod/enclave/logs/app",
		"/prod/enclave/logs/supervisor",
	}, cw.groups)
	require.Equal(t, []int32{30, 30}, cw.retentionDays)
	require.Equal(t, []string{"i-0e2ce2ce2ce2ce2ce", "i-0e2ce2ce2ce2ce2ce"}, cw.streams)

	probes := up.callsTo("/v1/logs")
	require.Len(t, probes, 1, "one startup write, nothing else before the app runs")
	require.Equal(t, "/prod/enclave/logs/supervisor", probes[0].header.Get("x-aws-log-group"))
	require.Equal(t, "i-0e2ce2ce2ce2ce2ce", probes[0].header.Get("x-aws-log-stream"))
	require.Equal(t, "logs", signedFor(probes[0]))
	require.Equal(t, "application/x-protobuf", probes[0].header.Get("Content-Type"))

	req := decodeLogs(t, probes[0].body)
	require.Len(t, req.ResourceLogs, 1)
	require.Equal(t, runtimeService,
		resourceAttribute(req.ResourceLogs[0].Resource, "service.name"))
	require.Equal(t, "i-0e2ce2ce2ce2ce2ce",
		resourceAttribute(req.ResourceLogs[0].Resource, "host.id"))
	records := req.ResourceLogs[0].ScopeLogs[0].LogRecords
	require.Len(t, records, 1)
	require.Equal(t, "telemetry started", records[0].Body.GetStringValue())
	require.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_INFO, records[0].SeverityNumber)
}

func TestStartFailsWhenTheLogsEndpointRefusesTheProbe(t *testing.T) {
	before := slog.Default()
	t.Cleanup(func() { slog.SetDefault(before) })

	up := newFakeOTLPEndpoints(t)
	up.fail("/v1/logs", http.StatusForbidden)
	up.reply["/v1/logs"] = `{"message":"not authorized to perform logs:PutLogEvents"}`
	telemetry := NewTelemetry(testCfg, testAWS(t, newFakeCloudWatchLogs(), up.URL))

	err := telemetry.Start(context.Background())

	require.ErrorContains(t, err, "write to log stream /prod/enclave/logs/supervisor via OTLP")
	require.ErrorContains(t, err, "HTTP 403")
	require.ErrorContains(t, err, "logs:PutLogEvents")
	require.Nil(t, telemetry.lp, "no exporter may start once the probe has failed")
	require.Same(t, before, slog.Default())
}

func TestSupervisorLogsArriveAsOTLP(t *testing.T) {
	up := newFakeOTLPEndpoints(t)
	telemetry := NewTelemetry(
		testConfigWithLogShipInterval(time.Hour),
		testAWS(t, newFakeCloudWatchLogs(), up.URL),
	)
	var stderr bytes.Buffer
	telemetry.stderr = &stderr
	startTelemetry(t, context.Background(), telemetry)

	slog.With("component", "test").Warn("test message", "key", "value")
	telemetry.Shutdown()

	require.Contains(t, stderr.String(), `"msg":"test message"`)
	require.Contains(t, stderr.String(), `"component":"test"`)

	var found *logspb.LogRecord
	for _, call := range up.callsTo("/v1/logs")[1:] { // [0] is the startup probe
		require.Equal(t, "/prod/enclave/logs/supervisor", call.header.Get("x-aws-log-group"),
			"the runtime's own records must never land in the app group")
		require.Equal(t, "i-0e2ce2ce2ce2ce2ce", call.header.Get("x-aws-log-stream"))
		require.Equal(t, "logs", signedFor(call))
		for _, rl := range decodeLogs(t, call.body).ResourceLogs {
			require.Equal(t, runtimeService, resourceAttribute(rl.Resource, "service.name"))
			for _, sl := range rl.ScopeLogs {
				for _, rec := range sl.LogRecords {
					if rec.Body.GetStringValue() == "test message" {
						found = rec
					}
				}
			}
		}
	}
	require.NotNil(t, found, "the record must be exported by Shutdown at the latest")
	require.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_WARN, found.SeverityNumber)
	attrs := map[string]string{}
	for _, kv := range found.Attributes {
		attrs[kv.Key] = kv.Value.GetStringValue()
	}
	require.Equal(t, "value", attrs["key"])
	require.Equal(t, "test", attrs["component"])
}

func TestSlogHandlerWithoutAProviderWritesStderrOnly(t *testing.T) {
	var stderr bytes.Buffer
	logger := slog.New(newSlogHandler(&stderr, nil))

	logger.Info("stderr only", "k", "v")
	logger.Debug("filtered")

	require.Contains(t, stderr.String(), `"msg":"stderr only"`)
	require.NotContains(t, stderr.String(), "filtered", "debug stays below the threshold")
}

func TestInitSpanArrivesAsOTLP(t *testing.T) {
	up := newFakeOTLPEndpoints(t)
	telemetry := NewTelemetry(
		testConfigWithLogShipInterval(time.Hour),
		testAWS(t, newFakeCloudWatchLogs(), up.URL),
	)
	startTelemetry(t, context.Background(), telemetry)

	_, span := otel.Tracer(runtimeService).Start(context.Background(), "init")
	span.End()
	telemetry.Shutdown()

	calls := up.callsTo("/v1/traces")
	require.NotEmpty(t, calls, "Shutdown must flush the batcher")
	require.Equal(t, "xray", signedFor(calls[0]))
	require.Empty(t, calls[0].header.Get("x-aws-log-group"), "spans go to X-Ray, not a log group")
	req := decodeTraces(t, calls[0].body)
	require.Len(t, req.ResourceSpans, 1)
	require.Equal(t, runtimeService,
		resourceAttribute(req.ResourceSpans[0].Resource, "service.name"))
	require.Equal(t, "init", req.ResourceSpans[0].ScopeSpans[0].Spans[0].Name)
}

func TestCountersArriveAsOTLPMetrics(t *testing.T) {
	up := newFakeOTLPEndpoints(t)
	telemetry := NewTelemetry(
		testConfigWithLogShipInterval(time.Hour),
		testAWS(t, newFakeCloudWatchLogs(), up.URL),
	)
	startTelemetry(t, context.Background(), telemetry)

	telemetry.Inc(metricHTTPRequests)
	telemetry.Shutdown()

	calls := up.callsTo("/v1/metrics")
	require.NotEmpty(t, calls, "Shutdown must collect and export once")
	require.Equal(t, "monitoring", signedFor(calls[0]))
	req := decodeMetrics(t, calls[0].body)
	require.Len(t, req.ResourceMetrics, 1)
	require.Equal(t, runtimeService,
		resourceAttribute(req.ResourceMetrics[0].Resource, "service.name"))

	values := map[string]*metricspb.Metric{}
	for _, sm := range req.ResourceMetrics[0].ScopeMetrics {
		for _, m := range sm.Metrics {
			values[m.Name] = m
		}
	}
	requests := values[metricHTTPRequests]
	require.NotNil(t, requests)
	require.Equal(t, int64(1), requests.GetSum().DataPoints[0].GetAsInt())
	require.True(t, requests.GetSum().IsMonotonic)
	require.Contains(t, values, runtimeMetricPrefix+"goroutines")
	require.Positive(
		t,
		values[runtimeMetricPrefix+"goroutines"].GetGauge().DataPoints[0].GetAsDouble(),
	)
}

func TestTracesAndMetricsExportFailuresAreNotFatal(t *testing.T) {
	up := newFakeOTLPEndpoints(t)
	up.fail("/v1/traces", http.StatusInternalServerError)
	up.fail("/v1/metrics", http.StatusInternalServerError)
	telemetry := NewTelemetry(
		testConfigWithLogShipInterval(time.Hour),
		testAWS(t, newFakeCloudWatchLogs(), up.URL),
	)
	var stderr bytes.Buffer
	telemetry.stderr = &stderr
	telemetry.stderrLog = slog.New(newSlogHandler(&stderr, nil))
	reader := testMetrics(t, telemetry)
	startTelemetry(t, context.Background(), telemetry)

	_, span := otel.Tracer(runtimeService).Start(context.Background(), "init")
	span.End()
	telemetry.Shutdown()

	require.GreaterOrEqual(t, counterValue(t, reader, metricTelemetryExportErrors), int64(2))
	require.Contains(t, stderr.String(), "telemetry export failed")
	require.Equal(t, 1, bytes.Count(stderr.Bytes(), []byte("telemetry export failed")),
		"repeated failures inside the interval must not repeat the line")
}

func TestShutdownIsSafeBeforeStartAndTwice(t *testing.T) {
	telemetry := NewTelemetry(testCfg, nil)
	require.NotPanics(t, func() {
		telemetry.Shutdown()
		telemetry.Shutdown()
	})
}

func TestTelemetryReadEndpointsAreGone(t *testing.T) {
	sm := http.NewServeMux()
	telemetry := NewTelemetry(
		testCfg,
		testAWS(t, newFakeCloudWatchLogs(), "http://127.0.0.1:1"),
	)
	registerRuntimeV1Handlers(sm, "/v1/", telemetry, "")

	for _, path := range []string{
		"/v1/enclave-metrics", "/v1/enclave-logs", "/v1/enclave-traces",
		"/v1/metrics", "/v1/logs", "/v1/traces",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			sm.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			require.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, w.Code)
		})
	}
}

func TestEnclaveInfoCarriesNoMetrics(t *testing.T) {
	var info map[string]any
	raw, err := json.Marshal(RuntimeInfo{Version: Version})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &info))

	_, present := info["metrics"]
	require.False(t, present, "metrics live in CloudWatch, not in enclave-info")
}

func testMetrics(t *testing.T, telemetry *Telemetry) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	counters, err := newCounters(provider.Meter("test"))
	require.NoError(t, err)
	telemetry.counters = counters
	return reader
}

func counterValue(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	var collected metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &collected))
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok && m.Name == name {
				require.True(t, sum.IsMonotonic, name)
				return sum.DataPoints[0].Value
			}
		}
	}
	return 0
}

func testAWS(t *testing.T, cw CloudWatchLogsAPI, base string) *AWSClient {
	t.Helper()
	for _, name := range []string{
		"AWS_ENDPOINT_URL_LOGS", "AWS_ENDPOINT_URL_XRAY", "AWS_ENDPOINT_URL_MONITORING",
	} {
		t.Setenv(name, base)
	}
	return &AWSClient{
		CWL:  cw,
		OTLP: newOTLPEndpoints(aws.Config{Region: "eu-west-1", Credentials: testCredentials}),
	}
}

func startTelemetry(t *testing.T, ctx context.Context, telemetry *Telemetry) {
	t.Helper()
	before := slog.Default()
	t.Cleanup(func() {
		telemetry.Shutdown()
		slog.SetDefault(before)
	})
	done := make(chan error, 1)
	go func() { done <- telemetry.Start(ctx) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "Telemetry.Start did not return")
	}
}

type otlpCall struct {
	path   string
	header http.Header
	body   []byte
}

type fakeOTLPEndpoints struct {
	*httptest.Server

	mu         sync.Mutex
	calls      []otlpCall
	status     map[string]int
	reply      map[string]string
	retryAfter string
}

func newFakeOTLPEndpoints(t *testing.T) *fakeOTLPEndpoints {
	t.Helper()
	f := &fakeOTLPEndpoints{status: map[string]int{}, reply: map[string]string{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls = append(f.calls, otlpCall{path: r.URL.Path, header: r.Header.Clone(), body: body})
		status, scripted := f.status[r.URL.Path]
		reply, retryAfter := f.reply[r.URL.Path], f.retryAfter
		f.mu.Unlock()
		if !scripted {
			status = http.StatusOK
		}
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Header().Set("X-Amzn-Requestid", "req-1")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeOTLPEndpoints) callsTo(path string) []otlpCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []otlpCall
	for _, c := range f.calls {
		if c.path == path {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeOTLPEndpoints) fail(path string, status int) {
	f.mu.Lock()
	f.status[path] = status
	f.mu.Unlock()
}

func signedFor(c otlpCall) string {
	auth := c.header.Get("Authorization")
	_, after, ok := strings.Cut(auth, "/eu-west-1/")
	if !ok {
		return ""
	}
	service, _, _ := strings.Cut(after, "/")
	return service
}

func decodeLogs(t *testing.T, body []byte) *collogspb.ExportLogsServiceRequest {
	t.Helper()
	var req collogspb.ExportLogsServiceRequest
	require.NoError(t, proto.Unmarshal(body, &req))
	return &req
}

func decodeTraces(t *testing.T, body []byte) *coltracepb.ExportTraceServiceRequest {
	t.Helper()
	var req coltracepb.ExportTraceServiceRequest
	require.NoError(t, proto.Unmarshal(body, &req))
	return &req
}

func decodeMetrics(t *testing.T, body []byte) *colmetricspb.ExportMetricsServiceRequest {
	t.Helper()
	var req colmetricspb.ExportMetricsServiceRequest
	require.NoError(t, proto.Unmarshal(body, &req))
	return &req
}

func resourceAttribute(res *resourcepb.Resource, key string) string {
	if res == nil {
		return ""
	}
	for _, kv := range res.Attributes {
		if kv.Key == key {
			return kv.Value.GetStringValue()
		}
	}
	return ""
}

func forwardRequest(t *testing.T, telemetry *Telemetry, route otlpRoute, body []byte,
	contentType string,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, route.path, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	telemetry.forwardHandler(route)(w, req)
	return w
}

func TestForwardRelaysUpstreamResponse(t *testing.T) {
	const protobuf = "application/x-protobuf"

	t.Run("success and its headers come back", func(t *testing.T) {
		up := newFakeOTLPEndpoints(t)
		up.reply["/v1/logs"] = "ok-body"
		telemetry := NewTelemetry(testCfg, testAWS(t, newFakeCloudWatchLogs(), up.URL))
		reader := testMetrics(t, telemetry)
		body := buildOTLPLogRequest(t, logspb.SeverityNumber_SEVERITY_NUMBER_INFO, "hi", "k", "v")

		w := forwardRequest(t, telemetry, otlpLogs, body, protobuf)

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "ok-body", w.Body.String())
		require.Equal(t, protobuf, w.Header().Get("Content-Type"))
		require.Equal(t, "req-1", w.Header().Get("X-Amzn-Requestid"))
		calls := up.callsTo("/v1/logs")
		require.Len(t, calls, 1)
		require.Equal(t, body, calls[0].body, "the upload must be forwarded byte for byte")
		require.Equal(t, protobuf, calls[0].header.Get("Content-Type"))
		require.Equal(t, int64(1), counterValue(t, reader, otlpLogs.metricForwarded))
		require.Zero(t, counterValue(t, reader, otlpLogs.metricErrors))
	})

	t.Run("a rejection comes back with its body", func(t *testing.T) {
		up := newFakeOTLPEndpoints(t)
		up.fail("/v1/traces", http.StatusBadRequest)
		up.reply["/v1/traces"] = `{"message":"too many spans"}`
		telemetry := NewTelemetry(testCfg, testAWS(t, newFakeCloudWatchLogs(), up.URL))
		reader := testMetrics(t, telemetry)

		w := forwardRequest(t, telemetry, otlpTraces,
			buildOTLPTraceRequest(t, "s", tracepb.Status_STATUS_CODE_OK), protobuf)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, `{"message":"too many spans"}`, w.Body.String())
		require.Zero(t, counterValue(t, reader, otlpTraces.metricErrors),
			"a 400 is the app's problem, not an upstream failure")
	})

	t.Run("throttling keeps Retry-After", func(t *testing.T) {
		up := newFakeOTLPEndpoints(t)
		up.fail("/v1/metrics", http.StatusTooManyRequests)
		up.retryAfter = "7"
		telemetry := NewTelemetry(testCfg, testAWS(t, newFakeCloudWatchLogs(), up.URL))
		reader := testMetrics(t, telemetry)

		w := forwardRequest(t, telemetry, otlpMetrics,
			buildOTLPSumMetric(t, "requests", 1), protobuf)

		require.Equal(t, http.StatusTooManyRequests, w.Code)
		require.Equal(t, "7", w.Header().Get("Retry-After"),
			"the app's exporter honours Retry-After, so it must see it")
		require.Equal(t, int64(1), counterValue(t, reader, otlpMetrics.metricErrors))
	})

	t.Run("an unreachable endpoint is a bad gateway", func(t *testing.T) {
		up := newFakeOTLPEndpoints(t)
		up.Close()
		telemetry := NewTelemetry(testCfg, testAWS(t, newFakeCloudWatchLogs(), up.URL))
		reader := testMetrics(t, telemetry)

		w := forwardRequest(t, telemetry, otlpLogs,
			buildOTLPLogRequest(t, logspb.SeverityNumber_SEVERITY_NUMBER_INFO, "hi", "k", "v"),
			protobuf)

		require.Equal(t, http.StatusBadGateway, w.Code)
		require.Contains(t, w.Body.String(), "upstream logs")
		require.Equal(t, int64(1), counterValue(t, reader, otlpLogs.metricErrors))
	})

	t.Run("json is the other OTLP encoding", func(t *testing.T) {
		up := newFakeOTLPEndpoints(t)
		telemetry := NewTelemetry(testCfg, testAWS(t, newFakeCloudWatchLogs(), up.URL))

		w := forwardRequest(t, telemetry, otlpLogs, []byte(`{"resourceLogs":[]}`),
			"application/json; charset=utf-8")

		require.Equal(t, http.StatusOK, w.Code)
		require.Len(t, up.callsTo("/v1/logs"), 1)
	})

	t.Run("anything else is refused before AWS sees it", func(t *testing.T) {
		up := newFakeOTLPEndpoints(t)
		telemetry := NewTelemetry(testCfg, testAWS(t, newFakeCloudWatchLogs(), up.URL))

		w := forwardRequest(t, telemetry, otlpLogs, []byte("hello"), "text/plain")

		require.Equal(t, http.StatusUnsupportedMediaType, w.Code)
		require.Empty(t, up.callsTo("/v1/logs"))
	})

	for _, tc := range []struct {
		route otlpRoute
		limit int
	}{
		{route: otlpLogs, limit: 1 << 20},
		{route: otlpTraces, limit: 5 << 20},
		{route: otlpMetrics, limit: 1 << 20},
	} {
		t.Run(tc.route.name+" rejects a body over its relay limit", func(t *testing.T) {
			up := newFakeOTLPEndpoints(t)
			telemetry := NewTelemetry(testCfg, testAWS(t, newFakeCloudWatchLogs(), up.URL))
			require.Equal(t, int64(tc.limit), tc.route.maxBody)

			w := forwardRequest(t, telemetry, tc.route,
				bytes.Repeat([]byte("x"), tc.limit+1), protobuf)

			require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
			require.Empty(t, up.callsTo(tc.route.path))
		})
	}

	t.Run("compressed uploads stay compressed", func(t *testing.T) {
		up := newFakeOTLPEndpoints(t)
		telemetry := NewTelemetry(testCfg, testAWS(t, newFakeCloudWatchLogs(), up.URL))
		body := []byte("pretend gzip bytes")
		req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(body))
		req.Header.Set("Content-Type", protobuf)
		req.Header.Set("Content-Encoding", "gzip")
		w := httptest.NewRecorder()

		telemetry.forwardHandler(otlpLogs)(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		calls := up.callsTo("/v1/logs")
		require.Len(t, calls, 1)
		require.Equal(t, "gzip", calls[0].header.Get("Content-Encoding"))
		require.Equal(t, body, calls[0].body)
	})
}

func TestForwardAddsLogHeadersOnlyForLogs(t *testing.T) {
	up := newFakeOTLPEndpoints(t)
	telemetry := NewTelemetry(testCfg, testAWS(t, newFakeCloudWatchLogs(), up.URL))
	const protobuf = "application/x-protobuf"

	forwardRequest(
		t,
		telemetry,
		otlpLogs,
		buildOTLPLogRequest(
			t,
			logspb.SeverityNumber_SEVERITY_NUMBER_INFO,
			"hi",
			"k",
			"v",
		),
		protobuf,
	)
	forwardRequest(t, telemetry, otlpTraces,
		buildOTLPTraceRequest(t, "s", tracepb.Status_STATUS_CODE_OK), protobuf)
	forwardRequest(t, telemetry, otlpMetrics, buildOTLPSumMetric(t, "m", 1), protobuf)

	logs := up.callsTo("/v1/logs")
	require.Len(t, logs, 1)
	require.Equal(t, "/prod/enclave/logs/app", logs[0].header.Get("x-aws-log-group"))
	require.Equal(t, "i-0e2ce2ce2ce2ce2ce", logs[0].header.Get("x-aws-log-stream"))
	require.Equal(t, "logs", signedFor(logs[0]))

	traces := up.callsTo("/v1/traces")
	require.Len(t, traces, 1)
	require.Empty(t, traces[0].header.Get("x-aws-log-group"))
	require.Empty(t, traces[0].header.Get("x-aws-log-stream"))
	require.Equal(t, "xray", signedFor(traces[0]))

	metrics := up.callsTo("/v1/metrics")
	require.Len(t, metrics, 1)
	require.Empty(t, metrics[0].header.Get("x-aws-log-group"))
	require.Equal(t, "monitoring", signedFor(metrics[0]))
}

func TestForwardHonoursTheCallerDeadline(t *testing.T) {
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer stalled.Close()
	telemetry := NewTelemetry(
		testCfg,
		testAWS(t, newFakeCloudWatchLogs(), stalled.URL),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader("x")).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()

	telemetry.forwardHandler(otlpLogs)(w, req)

	require.Equal(t, http.StatusBadGateway, w.Code,
		"an app exporter that gives up must not leave the forwarder waiting")
}

func buildOTLPTraceRequest(t *testing.T, name string, statusCode tracepb.Status_StatusCode) []byte {
	t.Helper()
	req := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			Resource: &resourcepb.Resource{
				Attributes: []*commonpb.KeyValue{{
					Key:   "service.name",
					Value: stringValue("test-svc"),
				}},
			},
			ScopeSpans: []*tracepb.ScopeSpans{{
				Spans: []*tracepb.Span{
					{
						TraceId: []byte{
							1,
							2,
							3,
							4,
							5,
							6,
							7,
							8,
							9,
							10,
							11,
							12,
							13,
							14,
							15,
							16,
						},
						SpanId:            []byte{1, 2, 3, 4, 5, 6, 7, 8},
						ParentSpanId:      []byte{0, 0, 0, 0, 0, 0, 0, 0},
						Name:              name,
						StartTimeUnixNano: uint64(time.Now().UnixNano()),
						EndTimeUnixNano:   uint64(time.Now().Add(time.Second).UnixNano()),
						Status:            &tracepb.Status{Code: statusCode},
						Attributes: []*commonpb.KeyValue{{
							Key:   "test.attr",
							Value: stringValue("val"),
						}},
					},
				},
			}},
		}},
	}
	data, err := proto.Marshal(req)
	require.NoError(t, err)
	return data
}

func buildOTLPLogRequest(
	t *testing.T,
	severity logspb.SeverityNumber,
	body, attrKey, attrVal string,
) []byte {
	t.Helper()
	req := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: &resourcepb.Resource{
				Attributes: []*commonpb.KeyValue{{
					Key:   "service.name",
					Value: stringValue("test"),
				}},
			},
			ScopeLogs: []*logspb.ScopeLogs{{
				LogRecords: []*logspb.LogRecord{{
					TimeUnixNano:   uint64(time.Now().UnixNano()),
					SeverityNumber: severity,
					Body:           stringValue(body),
					Attributes: []*commonpb.KeyValue{{
						Key:   attrKey,
						Value: stringValue(attrVal),
					}},
				}},
			}},
		}},
	}
	data, err := proto.Marshal(req)
	require.NoError(t, err)
	return data
}

func TestMetricsCounters(t *testing.T) {
	t.Run("inc", func(t *testing.T) {
		telemetry := NewTelemetry(testCfg, nil)
		reader := testMetrics(t, telemetry)

		telemetry.Inc(metricHTTPRequests)
		telemetry.Inc(metricHTTPRequests)

		require.Equal(t, int64(2), counterValue(t, reader, metricHTTPRequests))
		require.Zero(t, counterValue(t, reader, metricHTTPErrors))
	})

	t.Run("concurrent inc", func(t *testing.T) {
		telemetry := NewTelemetry(testCfg, nil)
		reader := testMetrics(t, telemetry)
		var wg sync.WaitGroup

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				telemetry.Inc(metricHTTPRequests)
			}()
		}
		wg.Wait()

		require.Equal(t, int64(100), counterValue(t, reader, metricHTTPRequests))
	})

	t.Run("before Start there is nothing to count into", func(t *testing.T) {
		telemetry := NewTelemetry(testCfg, nil)
		require.Nil(t, telemetry.counters)
		require.NotPanics(t, func() { telemetry.Inc(metricHTTPRequests) })
	})
}

func TestRegisterMetricsObservesRuntimeReadings(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	telemetry := NewTelemetry(testCfg, nil)

	require.NoError(t, telemetry.registerMetrics(provider.Meter("test")))
	var collected metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &collected))

	gauges := map[string]float64{}
	totals := map[string]float64{}
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Sum[float64]:
				require.True(t, data.IsMonotonic, m.Name)
				totals[m.Name] = data.DataPoints[0].Value
			case metricdata.Gauge[float64]:
				gauges[m.Name] = data.DataPoints[0].Value
			}
		}
	}

	require.Positive(t, gauges[runtimeMetricPrefix+"goroutines"])
	require.Positive(t, gauges[runtimeMetricPrefix+"heap_alloc_bytes"])
	require.Contains(t, totals, runtimeMetricPrefix+"gc_num_gc")
	if _, err := os.Stat("/proc/stat"); err == nil {
		require.Contains(t, totals, runtimeMetricPrefix+"cpu_user")
		require.Contains(t, gauges, runtimeMetricPrefix+"mem_total_kb")
	}
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
