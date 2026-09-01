package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
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

func TestSpanBuffer(t *testing.T) {
	base := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)

	t.Run("evicts oldest", func(t *testing.T) {
		buf := newSpanBuffer(3)
		buf.add(
			spanEntry{Start: base.Add(time.Second).Format(time.RFC3339Nano), Name: "1"},
			spanEntry{Start: base.Add(2 * time.Second).Format(time.RFC3339Nano), Name: "2"},
			spanEntry{Start: base.Add(3 * time.Second).Format(time.RFC3339Nano), Name: "3"},
			spanEntry{Start: base.Add(4 * time.Second).Format(time.RFC3339Nano), Name: "4"},
		)

		entries := buf.query(time.Time{}, "", 0)
		require.Len(t, entries, 3)
		require.Equal(t, "2", entries[0].Name)
		require.Equal(t, "4", entries[2].Name)
	})

	t.Run("filters", func(t *testing.T) {
		buf := newSpanBuffer(10)
		buf.add(
			spanEntry{
				Start:  base.Add(time.Second).Format(time.RFC3339Nano),
				Name:   "old-app",
				Source: "app",
			},
			spanEntry{
				Start:  base.Add(2 * time.Second).Format(time.RFC3339Nano),
				Name:   "supervisor",
				Source: "supervisor",
			},
			spanEntry{
				Start:  base.Add(3 * time.Second).Format(time.RFC3339Nano),
				Name:   "app-1",
				Source: "app",
			},
			spanEntry{
				Start:  base.Add(4 * time.Second).Format(time.RFC3339Nano),
				Name:   "app-2",
				Source: "app",
			},
		)

		entries := buf.query(base.Add(2500*time.Millisecond), "app", 1)
		require.Len(t, entries, 1)
		require.Equal(t, "app-1", entries[0].Name)
	})

	t.Run("empty returns slice", func(t *testing.T) {
		entries := newSpanBuffer(1).query(time.Time{}, "", 0)
		require.NotNil(t, entries)
		require.Empty(t, entries)
	})

	t.Run("concurrent", func(t *testing.T) {
		buf := newSpanBuffer(100)
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					buf.add(spanEntry{Name: "concurrent"})
				}
			}()
		}
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					_ = buf.query(time.Time{}, "", 10)
				}
			}()
		}
		wg.Wait()
		require.Len(t, buf.query(time.Time{}, "", 0), 100)
	})
}

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
	t.Run("get filters buffer", func(t *testing.T) {
		tracing := &Tracing{buf: newSpanBuffer(10)}
		tracing.buf.add(
			spanEntry{
				ID:      "1",
				TraceID: "trace-1",
				Name:    "a",
				Start:   "start",
				End:     "end",
				Status:  "ok",
				Source:  "app",
			},
			spanEntry{
				ID:      "2",
				TraceID: "trace-2",
				Name:    "b",
				Start:   "start",
				End:     "end",
				Status:  "ok",
				Source:  "supervisor",
			},
			spanEntry{
				ID:      "3",
				TraceID: "trace-3",
				Name:    "c",
				Start:   "start",
				End:     "end",
				Status:  "error",
				Source:  "app",
			},
		)

		w := httptest.NewRecorder()
		HandleTracingGet(
			tracing,
		)(
			w,
			httptest.NewRequest(http.MethodGet, "/v1/traces?service=app&limit=1", nil),
		)

		require.Equal(t, http.StatusOK, w.Code)
		require.JSONEq(t, `[{
			"id":"1",
			"trace_id":"trace-1",
			"name":"a",
			"start":"start",
			"end":"end",
			"status":"ok",
			"source":"app"
		}]`, w.Body.String())
	})

	t.Run("get empty", func(t *testing.T) {
		tracing := &Tracing{buf: newSpanBuffer(1)}
		w := httptest.NewRecorder()

		HandleTracingGet(tracing)(w, httptest.NewRequest(http.MethodGet, "/v1/traces", nil))

		require.Equal(t, http.StatusOK, w.Code)
		require.JSONEq(t, `[]`, w.Body.String())
	})

	t.Run("post accepts otlp", func(t *testing.T) {
		tracing := &Tracing{buf: newSpanBuffer(10)}
		req := httptest.NewRequest(
			http.MethodPost,
			"/v1/traces",
			bytes.NewReader(buildOTLPTraceRequest(t, "test", tracepb.Status_STATUS_CODE_OK)),
		)
		w := httptest.NewRecorder()

		HandleTracingPost(tracing)(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.JSONEq(t, `{"accepted":1}`, w.Body.String())
		require.Len(t, tracing.buf.query(time.Time{}, "", 0), 1)
	})
}

func TestTracingStartCloudWatchExport(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_LOG_CLOUDWATCH", "true")
	t.Setenv("ENCLAVE_LOG_RETENTION_DAYS", "7")

	t.Run("disabled noops", func(t *testing.T) {
		cw := newFakeCloudWatchLogs()
		tracing := &Tracing{buf: newSpanBuffer(1), cw: cw}

		require.NoError(t, tracing.StartCloudWatchExport(context.Background()))
		require.Empty(t, cw.groups)
	})

	t.Run("returns setup error", func(t *testing.T) {
		sentinel := errors.New("create group failed")
		cw := newFakeCloudWatchLogs()
		cw.createLogGroupErr = sentinel
		tracing := NewTracing(cw)

		err := tracing.StartCloudWatchExport(context.Background())
		require.ErrorIs(t, err, sentinel)
	})

	t.Run("returns after starting exporter", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		tracing := NewTracing(newFakeCloudWatchLogs())

		startTracingCloudWatchExport(t, ctx, tracing)
	})

	t.Run("flushes full batch", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cw := newFakeCloudWatchLogs()
		tracing := NewTracing(cw)
		startTracingCloudWatchExport(t, ctx, tracing)

		for i := 0; i < 100; i++ {
			start := time.Unix(int64(100-i), 0).UTC()
			tracing.shipCh <- spanEntry{
				ID:      fmt.Sprintf("span-%03d", i),
				TraceID: fmt.Sprintf("trace-%03d", i),
				Name:    fmt.Sprintf("op-%03d", i),
				Start:   start.Format(time.RFC3339Nano),
				End:     start.Add(time.Second).Format(time.RFC3339Nano),
				Status:  "ok",
				Source:  "app",
			}
		}

		put := requireCloudWatchPut(t, cw)
		require.Equal(t, "/enclave/test/app/traces", aws.ToString(put.LogGroupName))
		require.Len(t, put.LogEvents, 100)
		require.JSONEq(t, `{
			"id":"span-099",
			"trace_id":"trace-099",
			"name":"op-099",
			"start":"1970-01-01T00:00:01Z",
			"end":"1970-01-01T00:00:02Z",
			"status":"ok",
			"source":"app"
		}`, aws.ToString(put.LogEvents[0].Message))
	})

	t.Run("flushes on close", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cw := newFakeCloudWatchLogs()
		tracing := NewTracing(cw)
		startTracingCloudWatchExport(t, ctx, tracing)

		tracing.shipCh <- spanEntry{
			ID:      "one",
			TraceID: "trace",
			Name:    "flush me",
			Start:   time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
			End:     time.Unix(2, 0).UTC().Format(time.RFC3339Nano),
			Status:  "error",
			Source:  "app",
		}
		close(tracing.shipCh)

		put := requireCloudWatchPut(t, cw)
		require.Len(t, put.LogEvents, 1)
		require.JSONEq(t, `{
			"id":"one",
			"trace_id":"trace",
			"name":"flush me",
			"start":"1970-01-01T00:00:01Z",
			"end":"1970-01-01T00:00:02Z",
			"status":"error",
			"source":"app"
		}`, aws.ToString(put.LogEvents[0].Message))
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
					StartTimeUnixNano: uint64(time.Unix(1, 0).UnixNano()),
					EndTimeUnixNano:   uint64(time.Unix(2, 0).UnixNano()),
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

func startTracingCloudWatchExport(t *testing.T, ctx context.Context, tracing *Tracing) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- tracing.StartCloudWatchExport(ctx) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		require.FailNow(t, "StartCloudWatchExport did not return")
	}
}
