package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

type signal int

const (
	signalAppLogs signal = iota
	signalSupervisorLogs
	signalCount
)

type otlpRequest struct {
	contentType     string
	contentEncoding string
	group           string
	body            []byte
}

type otlpEndpoint uint8

const (
	otlpEndpointInvalid otlpEndpoint = iota
	otlpEndpointLogs
	otlpEndpointTraces
	otlpEndpointMetrics
	otlpEndpointCount
)

type otlpRoute struct {
	name     string
	service  string
	path     string
	maxBody  int64
	endpoint otlpEndpoint

	metricForwarded string
	metricErrors    string
}

var (
	otlpLogs = otlpRoute{
		name: "logs", service: "logs", path: "/v1/logs", maxBody: 1 << 20,
		endpoint:        otlpEndpointLogs,
		metricForwarded: "enclave_otlp_logs_forwarded_total",
		metricErrors:    "enclave_otlp_logs_upstream_errors_total",
	}
	otlpTraces = otlpRoute{
		name: "traces", service: "xray", path: "/v1/traces", maxBody: 5 << 20,
		endpoint:        otlpEndpointTraces,
		metricForwarded: "enclave_otlp_traces_forwarded_total",
		metricErrors:    "enclave_otlp_traces_upstream_errors_total",
	}
	otlpMetrics = otlpRoute{
		name: "metrics", service: "monitoring", path: "/v1/metrics", maxBody: 1 << 20,
		endpoint:        otlpEndpointMetrics,
		metricForwarded: "enclave_otlp_metrics_forwarded_total",
		metricErrors:    "enclave_otlp_metrics_upstream_errors_total",
	}
)

const (
	metricHTTPRequests          = "enclave_http_requests_total"
	metricHTTPErrors            = "enclave_http_errors_total"
	metricAppProxiedRequests    = "enclave_app_proxied_requests_total"
	metricAppProxiedErrors      = "enclave_app_proxied_errors_total"
	metricTelemetryExportErrors = "enclave_telemetry_export_errors_total"
)

const runtimeMetricPrefix = "enclave_runtime_"

var (
	runtimeGauges = []string{
		runtimeMetricGoroutines,
		runtimeMetricNumCPU,
		runtimeMetricHeapAllocBytes,
		runtimeMetricHeapSysBytes,
		runtimeMetricSysBytes,
		runtimeMetricMemTotalKB,
		runtimeMetricMemFreeKB,
		runtimeMetricMemAvailableKB,
	}
	runtimeCounters = []string{
		runtimeMetricGCPauseTotalNS,
		runtimeMetricGCCount,
		runtimeMetricCPUUser,
		runtimeMetricCPUNice,
		runtimeMetricCPUSystem,
		runtimeMetricCPUIdle,
	}
)

const maxRelayBody = 64 << 10

var signalNames = [signalCount]string{
	signalAppLogs:        "logs/app",
	signalSupervisorLogs: "logs/supervisor",
}

func (s signal) String() string {
	if s < 0 || s >= signalCount {
		return "unknown"
	}
	return signalNames[s]
}

const (
	runtimeService = "enclave-runtime"

	shutdownFlushTimeout = 5 * time.Second

	exportErrorLogInterval = 30 * time.Second
)

// Telemetry forwards application and runtime telemetry to AWS.
type Telemetry struct {
	counters map[string]metric.Int64Counter

	cw            CloudWatchLogsAPI
	groups        [signalCount]string
	instanceID    string
	shipInterval  time.Duration
	retentionDays int32
	res           *resource.Resource

	endpoints [otlpEndpointCount]otlpClient

	stderr    io.Writer
	stderrLog *slog.Logger

	lp *sdklog.LoggerProvider
	tp *sdktrace.TracerProvider
	mp *sdkmetric.MeterProvider

	errMu       sync.Mutex
	lastErrorAt time.Time

	shutdownOnce sync.Once
}

func NewTelemetry(cfg *Config, client *AWSClient) *Telemetry {
	t := &Telemetry{
		instanceID:    cfg.InstanceID,
		shipInterval:  cfg.LogShipInterval,
		retentionDays: cfg.LogRetentionDays,
		stderr:        os.Stderr,
		res: resource.NewSchemaless(
			attribute.String("service.name", runtimeService),
			attribute.String("service.version", Version),
			attribute.String("deployment.environment", cfg.Deployment),
			attribute.String("host.id", cfg.InstanceID),
			attribute.String("enclave.app", cfg.AppName),
		),
	}
	if client != nil {
		t.cw = client.CWL
		if client.OTLP != nil {
			t.endpoints[otlpEndpointLogs] = client.OTLP.Logs
			t.endpoints[otlpEndpointTraces] = client.OTLP.Traces
			t.endpoints[otlpEndpointMetrics] = client.OTLP.Metrics
		}
	}
	for sig := signal(0); sig < signalCount; sig++ {
		t.groups[sig] = cfg.logGroup(sig)
	}
	t.stderrLog = slog.New(newSlogHandler(t.stderr, nil))
	return t
}

// Start verifies that the runtime can write logs before starting the exporters.
func (t *Telemetry) Start(ctx context.Context) error {
	if t.cw == nil {
		return fmt.Errorf("telemetry: no CloudWatch Logs client")
	}
	if _, err := t.endpoint(otlpLogs); err != nil {
		return err
	}
	if t.instanceID == "" {
		return fmt.Errorf(
			"telemetry: no instance ID from IMDS: it names every CloudWatch log stream")
	}
	for sig := signal(0); sig < signalCount; sig++ {
		if err := t.ensureGroup(ctx, sig); err != nil {
			return fmt.Errorf("failed to start %s cloudwatch export: %w", sig, err)
		}
	}
	if err := t.probe(ctx); err != nil {
		return fmt.Errorf(
			"failed to start %s cloudwatch export: %w", signalSupervisorLogs, err)
	}
	if err := t.startProviders(ctx); err != nil {
		return fmt.Errorf("start telemetry exporters: %w", err)
	}

	slog.SetDefault(slog.New(newSlogHandler(t.stderr, t.lp)))
	slog.Info("telemetry started",
		"log_groups", t.groups[:], "log_stream", t.instanceID,
		"logs", t.endpoints[otlpEndpointLogs].base,
		"traces", t.endpoints[otlpEndpointTraces].base,
		"metrics", t.endpoints[otlpEndpointMetrics].base)
	return nil
}

func (t *Telemetry) startProviders(ctx context.Context) error {
	logsEndpoint, err := t.endpoint(otlpLogs)
	if err != nil {
		return err
	}
	tracesEndpoint, err := t.endpoint(otlpTraces)
	if err != nil {
		return err
	}
	metricsEndpoint, err := t.endpoint(otlpMetrics)
	if err != nil {
		return err
	}

	logs, err := otlploghttp.New(ctx,
		otlploghttp.WithEndpointURL(logsEndpoint.base+otlpLogs.path),
		otlploghttp.WithHTTPClient(logsEndpoint.client),
		otlploghttp.WithHeaders(map[string]string{
			"x-aws-log-group":  t.groups[signalSupervisorLogs],
			"x-aws-log-stream": t.instanceID,
		}),
	)
	if err != nil {
		return fmt.Errorf("logs exporter: %w", err)
	}
	traces, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(tracesEndpoint.base+otlpTraces.path),
		otlptracehttp.WithHTTPClient(tracesEndpoint.client),
	)
	if err != nil {
		return fmt.Errorf("traces exporter: %w", err)
	}
	metrics, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpointURL(metricsEndpoint.base+otlpMetrics.path),
		otlpmetrichttp.WithHTTPClient(metricsEndpoint.client),
	)
	if err != nil {
		return fmt.Errorf("metrics exporter: %w", err)
	}

	otel.SetErrorHandler(otel.ErrorHandlerFunc(t.exportFailed))
	t.lp = sdklog.NewLoggerProvider(
		sdklog.WithResource(t.res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(
			logs, sdklog.WithExportInterval(t.shipInterval),
		)),
	)
	t.tp = sdktrace.NewTracerProvider(
		sdktrace.WithResource(t.res),
		sdktrace.WithBatcher(traces, sdktrace.WithBatchTimeout(t.shipInterval)),
	)
	t.mp = sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(t.res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(
			metrics, sdkmetric.WithInterval(t.shipInterval),
		)),
	)
	meter := t.mp.Meter(runtimeService)
	if t.counters == nil {
		if t.counters, err = newCounters(meter); err != nil {
			return fmt.Errorf("create runtime counters: %w", err)
		}
	}
	if err := t.registerMetrics(meter); err != nil {
		return fmt.Errorf("register runtime readings: %w", err)
	}
	otel.SetTracerProvider(t.tp)
	otel.SetMeterProvider(t.mp)
	return nil
}

// forward preserves the request body so compressed uploads remain compressed.
func (t *Telemetry) forward(
	ctx context.Context, route otlpRoute, in otlpRequest,
) (*http.Response, error) {
	up, err := t.endpoint(route)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, up.base+route.path, bytes.NewReader(in.body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", in.contentType)
	if in.contentEncoding != "" {
		req.Header.Set("Content-Encoding", in.contentEncoding)
	}
	if route.service == otlpLogs.service {
		req.Header.Set("x-aws-log-group", in.group)
		req.Header.Set("x-aws-log-stream", t.instanceID)
	}
	return up.client.Do(req)
}

func (t *Telemetry) forwardHandler(route otlpRoute) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if !otlpContentType(ct) {
			http.Error(w, jsonError("unsupported Content-Type "+strconv.Quote(ct)+
				": OTLP is application/x-protobuf or application/json"),
				http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, route.maxBody))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, jsonError(fmt.Sprintf("body exceeds %d bytes", route.maxBody)),
					http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, jsonError("read body: "+err.Error()), http.StatusBadRequest)
			return
		}
		t.Inc(route.metricForwarded)

		ctx, cancel := context.WithTimeout(r.Context(), otlpHTTPTimeout)
		defer cancel()
		resp, err := t.forward(ctx, route, otlpRequest{
			contentType:     ct,
			contentEncoding: r.Header.Get("Content-Encoding"),
			group:           t.groups[signalAppLogs],
			body:            body,
		})
		if err != nil {
			t.Inc(route.metricErrors)
			http.Error(w, jsonError("upstream "+route.service+": "+err.Error()),
				http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			t.Inc(route.metricErrors)
		}
		for _, h := range []string{"Content-Type", "Retry-After", "X-Amzn-Requestid"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, maxRelayBody))
	}
}

// probe verifies logs:PutLogEvents before the application starts.
func (t *Telemetry) probe(ctx context.Context) error {
	group := t.groups[signalSupervisorLogs]
	now := uint64(time.Now().UnixNano())
	body, err := proto.Marshal(&collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: t.resourceProto(),
			ScopeLogs: []*logspb.ScopeLogs{{
				Scope: &commonpb.InstrumentationScope{Name: runtimeService},
				LogRecords: []*logspb.LogRecord{{
					TimeUnixNano:         now,
					ObservedTimeUnixNano: now,
					SeverityNumber:       logspb.SeverityNumber_SEVERITY_NUMBER_INFO,
					SeverityText:         "INFO",
					Body:                 stringAnyValue("telemetry started"),
				}},
			}},
		}},
	})
	if err != nil {
		return fmt.Errorf("encode startup record: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, otlpHTTPTimeout)
	defer cancel()
	resp, err := t.forward(ctx, otlpLogs, otlpRequest{
		contentType: "application/x-protobuf", group: group, body: body,
	})
	if err != nil {
		return fmt.Errorf("write to log stream %s via OTLP: %w", group, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("write to log stream %s via OTLP: HTTP %d: %s",
			group, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (t *Telemetry) resourceProto() *resourcepb.Resource {
	attrs := t.res.Attributes()
	out := make([]*commonpb.KeyValue, 0, len(attrs))
	for _, kv := range attrs {
		out = append(out, &commonpb.KeyValue{
			Key: string(kv.Key), Value: stringAnyValue(kv.Value.AsString()),
		})
	}
	return &resourcepb.Resource{Attributes: out}
}

func (t *Telemetry) registerMetrics(meter metric.Meter) error {
	var observables []metric.Observable

	gauges := make(map[string]metric.Float64ObservableGauge)
	for _, name := range runtimeGauges {
		inst, err := meter.Float64ObservableGauge(runtimeMetricPrefix + name)
		if err != nil {
			return err
		}
		gauges[name] = inst
		observables = append(observables, inst)
	}
	totals := make(map[string]metric.Float64ObservableCounter)
	for _, name := range runtimeCounters {
		inst, err := meter.Float64ObservableCounter(runtimeMetricPrefix + name)
		if err != nil {
			return err
		}
		totals[name] = inst
		observables = append(observables, inst)
	}

	_, err := meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		levels := map[string]float64{
			runtimeMetricGoroutines:     float64(runtime.NumGoroutine()),
			runtimeMetricNumCPU:         float64(runtime.NumCPU()),
			runtimeMetricHeapAllocBytes: float64(ms.HeapAlloc),
			runtimeMetricHeapSysBytes:   float64(ms.HeapSys),
			runtimeMetricSysBytes:       float64(ms.Sys),
		}
		growing := map[string]float64{
			runtimeMetricGCPauseTotalNS: float64(ms.PauseTotalNs),
			runtimeMetricGCCount:        float64(ms.NumGC),
		}
		// /proc is best effort: absent outside Linux and in some sandboxes.
		if cpu, err := readProcCPU(); err == nil {
			maps.Copy(growing, cpu)
		}
		if mem, err := readProcMeminfo(); err == nil {
			maps.Copy(levels, mem)
		}
		for name, inst := range gauges {
			if v, ok := levels[name]; ok {
				o.ObserveFloat64(inst, v)
			}
		}
		for name, inst := range totals {
			if v, ok := growing[name]; ok {
				o.ObserveFloat64(inst, v)
			}
		}
		return nil
	}, observables...)
	return err
}

func (t *Telemetry) Inc(name string) {
	if counter, ok := t.counters[name]; ok {
		counter.Add(context.Background(), 1)
	}
}

// exportFailed writes directly to stderr to avoid recursively exporting the error.
func (t *Telemetry) exportFailed(err error) {
	t.Inc(metricTelemetryExportErrors)

	t.errMu.Lock()
	throttled := time.Since(t.lastErrorAt) < exportErrorLogInterval
	if !throttled {
		t.lastErrorAt = time.Now()
	}
	t.errMu.Unlock()
	if throttled {
		return
	}
	t.stderrLog.Warn("telemetry export failed", "error", err)
}

// Shutdown flushes the telemetry providers.
func (t *Telemetry) Shutdown() {
	t.shutdownOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownFlushTimeout)
		defer cancel()
		if t.tp != nil {
			if err := t.tp.Shutdown(ctx); err != nil {
				t.exportFailed(fmt.Errorf("tracer provider shutdown: %w", err))
			}
		}
		if t.mp != nil {
			if err := t.mp.Shutdown(ctx); err != nil {
				t.exportFailed(fmt.Errorf("meter provider shutdown: %w", err))
			}
		}
		if t.lp != nil {
			if err := t.lp.Shutdown(ctx); err != nil {
				t.exportFailed(fmt.Errorf("logger provider shutdown: %w", err))
			}
		}
	})
}

func (t *Telemetry) ensureGroup(ctx context.Context, sig signal) error {
	group := t.groups[sig]

	_, err := t.cw.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(group),
	})
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("create log group %s: %w", group, err)
	}

	_, err = t.cw.PutRetentionPolicy(ctx, &cloudwatchlogs.PutRetentionPolicyInput{
		LogGroupName:    aws.String(group),
		RetentionInDays: aws.Int32(t.retentionDays),
	})
	if err != nil {
		slog.Warn("failed to set log retention", "log_group", group, "error", err)
	}

	_, err = t.cw.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String(group),
		LogStreamName: aws.String(t.instanceID),
	})
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("create log stream %s: %w", t.instanceID, err)
	}
	return nil
}

func isAlreadyExists(err error) bool {
	var exists *cwltypes.ResourceAlreadyExistsException
	return errors.As(err, &exists)
}

func jsonError(msg string) string {
	body, err := json.Marshal(map[string]string{"error": msg})
	if err != nil {
		return `{"error":"internal error"}`
	}
	return string(body)
}

func stringAnyValue(s string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
}

func otlpContentType(ct string) bool {
	return strings.HasPrefix(ct, "application/x-protobuf") ||
		strings.HasPrefix(ct, "application/json")
}

func newCounters(meter metric.Meter) (map[string]metric.Int64Counter, error) {
	counters := make(map[string]metric.Int64Counter)
	for _, name := range counterNames() {
		counter, err := meter.Int64Counter(name)
		if err != nil {
			return nil, err
		}
		counters[name] = counter
	}
	return counters, nil
}

func counterNames() []string {
	return []string{
		metricHTTPRequests, metricHTTPErrors,
		metricAppProxiedRequests, metricAppProxiedErrors,
		metricTelemetryExportErrors,
		otlpLogs.metricForwarded, otlpLogs.metricErrors,
		otlpTraces.metricForwarded, otlpTraces.metricErrors,
		otlpMetrics.metricForwarded, otlpMetrics.metricErrors,
	}
}

func (t *Telemetry) endpoint(r otlpRoute) (otlpClient, error) {
	if r.endpoint <= otlpEndpointInvalid || r.endpoint >= otlpEndpointCount {
		return otlpClient{}, fmt.Errorf("telemetry: invalid %s endpoint", r.name)
	}
	endpoint := t.endpoints[r.endpoint]
	if endpoint.client == nil {
		return otlpClient{}, fmt.Errorf("telemetry: no %s endpoint", r.name)
	}
	return endpoint, nil
}
