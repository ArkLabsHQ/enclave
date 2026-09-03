package runtime

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/require"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestParseOTLPSpans(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		entries, err := parseOTLPSpans(
			buildOTLPTraceRequest(t, "test.span", tracepb.Status_STATUS_CODE_OK),
		)
		require.NoError(t, err)
		require.Len(t, entries, 1)

		entry := entries[0]
		require.Equal(t, "0102030405060708", entry.ID)
		require.Equal(t, "0102030405060708090a0b0c0d0e0f10", entry.TraceID)
		require.Equal(t, "test.span", entry.Name)
		require.Equal(t, "ok", entry.Status)
		require.Equal(t, "app", entry.Source)
		require.Equal(t, "val", entry.Attributes["test.attr"])
		require.Equal(t, "test-svc", entry.Attributes["resource.service.name"])
	})

	t.Run("status", func(t *testing.T) {
		cases := []struct {
			name   string
			code   tracepb.Status_StatusCode
			status string
		}{
			{name: "ok", code: tracepb.Status_STATUS_CODE_OK, status: "ok"},
			{name: "error", code: tracepb.Status_STATUS_CODE_ERROR, status: "error"},
			{name: "unset", code: tracepb.Status_STATUS_CODE_UNSET, status: "unset"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				entries, err := parseOTLPSpans(buildOTLPTraceRequest(t, "span", tc.code))
				require.NoError(t, err)
				require.Equal(t, tc.status, entries[0].Status)
			})
		}
	})

	t.Run("invalid protobuf", func(t *testing.T) {
		_, err := parseOTLPSpans([]byte("garbage"))
		require.Error(t, err)
	})
}

func TestTracingHandlers(t *testing.T) {
	t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "10ms")

	t.Run("post ships otlp", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cw := newFakeCloudWatchLogs()
		telemetry := NewTelemetry(testCfg, cw)
		startTelemetry(t, ctx, telemetry)

		req := httptest.NewRequest(
			http.MethodPost,
			"/v1/traces",
			bytes.NewReader(buildOTLPTraceRequest(t, "test", tracepb.Status_STATUS_CODE_OK)),
		)
		w := httptest.NewRecorder()

		HandleTracingPost(telemetry.Tracing)(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.JSONEq(t, `{"accepted":1}`, w.Body.String())
		put := requireCloudWatchPutTo(t, cw, "/enclave/prod/app/traces")
		require.Equal(t, "/enclave/prod/app/traces", aws.ToString(put.LogGroupName))
		require.Len(t, put.LogEvents, 1)
		require.Contains(t, aws.ToString(put.LogEvents[0].Message), `"name":"test"`)
	})
}

func TestTracingShipsToCloudWatch(t *testing.T) {
	t.Setenv("ENCLAVE_LOG_RETENTION_DAYS", "7")
	t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "10ms")

	t.Run("flushes full batch", func(t *testing.T) {
		// Only the count threshold may flush here, or a slow run splits the batch.
		t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "1h")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cw := newFakeCloudWatchLogs()
		telemetry := NewTelemetry(testCfg, cw)
		startTelemetry(t, ctx, telemetry)

		for i := 0; i < telemetryBatch; i++ {
			start := time.Now().UTC().Add(-time.Duration(i) * time.Second)
			telemetry.Send(signalTraces, start, spanEntry{
				ID:      fmt.Sprintf("span-%03d", i),
				TraceID: fmt.Sprintf("trace-%03d", i),
				Name:    fmt.Sprintf("op-%03d", i),
				Start:   start.Format(time.RFC3339Nano),
				End:     start.Add(time.Second).Format(time.RFC3339Nano),
				Status:  "ok",
				Source:  "app",
			})
		}

		put := requireCloudWatchPutTo(t, cw, "/enclave/prod/app/traces")
		require.Equal(t, "/enclave/prod/app/traces", aws.ToString(put.LogGroupName))
		require.Len(t, put.LogEvents, telemetryBatch)
		// The oldest span was sent last, so ordering put it first.
		require.Contains(t, aws.ToString(put.LogEvents[0].Message),
			fmt.Sprintf(`"name":"op-%03d"`, telemetryBatch-1))
	})

	t.Run("flushes on shutdown", func(t *testing.T) {
		ctx := context.Background()
		cw := newFakeCloudWatchLogs()
		telemetry := NewTelemetry(testCfg, cw)
		startTelemetry(t, ctx, telemetry)

		now := time.Now().UTC()
		telemetry.Send(signalTraces, now, spanEntry{
			ID:      "one",
			TraceID: "trace",
			Name:    "flush me",
			Start:   now.Format(time.RFC3339Nano),
			End:     now.Add(time.Second).Format(time.RFC3339Nano),
			Status:  "error",
			Source:  "app",
		})
		telemetry.Shutdown()

		put := requireCloudWatchPutTo(t, cw, "/enclave/prod/app/traces")
		require.Len(t, put.LogEvents, 1)
		require.Contains(t, aws.ToString(put.LogEvents[0].Message), `"name":"flush me"`)
	})
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
				Spans: []*tracepb.Span{{
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
				}},
			}},
		}},
	}
	data, err := proto.Marshal(req)
	require.NoError(t, err)
	return data
}
