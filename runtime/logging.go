package runtime

import (
	"context"
	"io"
	"log/slog"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	otellog "go.opentelemetry.io/otel/log"
)

type slogHandler struct {
	stderr slog.Handler
	otlp   slog.Handler
}

func newSlogHandler(stderr io.Writer, provider otellog.LoggerProvider) slog.Handler {
	h := &slogHandler{
		stderr: slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}),
	}
	if provider != nil {
		h.otlp = otelslog.NewHandler(runtimeService,
			otelslog.WithLoggerProvider(provider), otelslog.WithVersion(Version))
	}
	return h
}

func (h *slogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

func (h *slogHandler) Handle(ctx context.Context, r slog.Record) error {
	_ = h.stderr.Handle(ctx, r)
	if h.otlp == nil {
		return nil
	}
	return h.otlp.Handle(ctx, r)
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := &slogHandler{stderr: h.stderr.WithAttrs(attrs)}
	if h.otlp != nil {
		next.otlp = h.otlp.WithAttrs(attrs)
	}
	return next
}

func (h *slogHandler) WithGroup(name string) slog.Handler {
	next := &slogHandler{stderr: h.stderr.WithGroup(name)}
	if h.otlp != nil {
		next.otlp = h.otlp.WithGroup(name)
	}
	return next
}
