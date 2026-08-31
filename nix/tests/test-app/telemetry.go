// OTLP wiring for the test app. It uses the stock OTel exporters rather than
// anything enclave-specific, so a green e2e is evidence that an off-the-shelf
// instrumented application ships telemetry through this runtime unmodified.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otellog "go.opentelemetry.io/otel/log"
	logglobal "go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// telemetry holds the providers so main can flush them on the way out.
type telemetry struct {
	tracer   trace.Tracer
	logger   otellog.Logger
	requests metric.Int64Counter

	shutdown []func(context.Context) error
}

// startTelemetry points the stock exporters at the runtime's ingest endpoints.
// The runtime serves OTLP/HTTP on the loopback proxy port and authenticates with
// the token it puts in the child's environment, so no other configuration is
// needed.
func startTelemetry(ctx context.Context) (*telemetry, error) {
	endpoint := "127.0.0.1:" + envOr("ENCLAVE_PROXY_PORT", "8080")
	token := os.Getenv("ENCLAVE_RUNTIME_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("ENCLAVE_RUNTIME_TOKEN is not set")
	}
	headers := map[string]string{"Authorization": "Bearer " + token}

	// Plain attributes rather than a semconv package: the keys are the contract
	// the runtime reads, and pinning a semconv version here would only add churn.
	res := resource.NewWithAttributes("",
		attribute.String("service.name", envOr("ENCLAVE_APP_NAME", "testapp")),
		attribute.String("deployment.environment", envOr("ENCLAVE_DEPLOYMENT", "dev")),
	)

	t := &telemetry{}

	traceExp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(),
		otlptracehttp.WithHeaders(headers),
	)
	if err != nil {
		return nil, fmt.Errorf("trace exporter: %w", err)
	}
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp, sdktrace.WithBatchTimeout(time.Second)),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)
	t.tracer = tracerProvider.Tracer("testapp")
	t.shutdown = append(t.shutdown, tracerProvider.Shutdown)

	metricExp, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpoint(endpoint),
		otlpmetrichttp.WithInsecure(),
		otlpmetrichttp.WithHeaders(headers),
	)
	if err != nil {
		return nil, fmt.Errorf("metric exporter: %w", err)
	}
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(
			metricExp, sdkmetric.WithInterval(time.Second))),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(meterProvider)
	t.shutdown = append(t.shutdown, meterProvider.Shutdown)

	t.requests, err = meterProvider.Meter("testapp").Int64Counter(
		"testapp_requests_total")
	if err != nil {
		return nil, fmt.Errorf("request counter: %w", err)
	}

	logExp, err := otlploghttp.New(ctx,
		otlploghttp.WithEndpoint(endpoint),
		otlploghttp.WithInsecure(),
		otlploghttp.WithHeaders(headers),
	)
	if err != nil {
		return nil, fmt.Errorf("log exporter: %w", err)
	}
	loggerProvider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(
			logExp, sdklog.WithExportInterval(time.Second))),
		sdklog.WithResource(res),
	)
	logglobal.SetLoggerProvider(loggerProvider)
	t.logger = loggerProvider.Logger("testapp")
	t.shutdown = append(t.shutdown, loggerProvider.Shutdown)

	return t, nil
}

// Log emits one OTLP log record.
func (t *telemetry) Log(ctx context.Context, severity otellog.Severity, body string,
	attrs ...attribute.KeyValue,
) {
	var record otellog.Record
	record.SetTimestamp(time.Now())
	record.SetSeverity(severity)
	record.SetSeverityText(severity.String())
	record.SetBody(attribute.StringValue(body))
	record.AddAttributes(attrs...)
	t.logger.Emit(ctx, record)
}

// Shutdown flushes every provider, so a short-lived request's telemetry is not
// lost when the process exits.
func (t *telemetry) Shutdown(ctx context.Context) {
	for _, fn := range t.shutdown {
		if err := fn(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "testapp: telemetry shutdown: %v\n", err)
		}
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
