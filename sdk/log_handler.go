package sdk

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// bufferHandler is a slog.Handler that tees log records to:
// 1. JSON stderr (existing behavior)
// 2. LogBuffer as LogEntry with source="supervisor"
// 3. logShipCh for CloudWatch (nil-safe)
type bufferHandler struct {
	stderr slog.Handler
	buf    *LogBuffer
	shipCh chan LogEntry
	attrs  []slog.Attr
	group  string
}

// NewBufferHandler creates a slog.Handler that writes to both stderr and
// the LogBuffer. Pass nil for shipCh if CloudWatch shipping is disabled;
// the handler checks before sending.
func NewBufferHandler(buf *LogBuffer, shipCh chan LogEntry) slog.Handler {
	return &bufferHandler{
		stderr: slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}),
		buf:    buf,
		shipCh: shipCh,
	}
}

func (h *bufferHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

func (h *bufferHandler) Handle(ctx context.Context, r slog.Record) error {
	// Always write to stderr.
	_ = h.stderr.Handle(ctx, r)

	// Convert to LogEntry.
	entry := LogEntry{
		ID:        generateLogID(),
		Timestamp: r.Time.UTC().Format(time.RFC3339Nano),
		Level:     slogLevelToString(r.Level),
		Message:   r.Message,
		Source:    "supervisor",
	}

	// Collect attributes.
	attrs := make(map[string]any)
	// Include pre-set attrs from WithAttrs.
	for _, a := range h.attrs {
		attrs[a.Key] = a.Value.Any()
	}
	// Include record attrs.
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	if len(attrs) > 0 {
		entry.Attributes = attrs
	}

	// Insert into buffer.
	h.buf.Add(entry)
	enclaveMetrics.LogEntries.Add(1)

	// Forward to CloudWatch shipper if available.
	if h.shipCh != nil {
		select {
		case h.shipCh <- entry:
		default:
		}
	}

	return nil
}

func (h *bufferHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &bufferHandler{
		stderr: h.stderr.WithAttrs(attrs),
		buf:    h.buf,
		shipCh: h.shipCh,
		attrs:  append(h.attrs, attrs...),
		group:  h.group,
	}
}

func (h *bufferHandler) WithGroup(name string) slog.Handler {
	return &bufferHandler{
		stderr: h.stderr.WithGroup(name),
		buf:    h.buf,
		shipCh: h.shipCh,
		attrs:  h.attrs,
		group:  name,
	}
}

// slogLevelToString converts slog.Level to our level strings.
func slogLevelToString(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "error"
	case l >= slog.LevelWarn:
		return "warn"
	case l >= slog.LevelInfo:
		return "info"
	default:
		return "debug"
	}
}
