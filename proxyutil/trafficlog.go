package proxyutil

import (
	"context"
	"log/slog"
	"strings"
)

type trafficPathHandler struct {
	next  slog.Handler
	fixed TrafficPath
}

func NewTrafficPathHandler(next slog.Handler) slog.Handler {
	return newTrafficPathHandler(next, "")
}

func newTrafficPathHandler(next slog.Handler, fixed TrafficPath) slog.Handler {
	return &trafficPathHandler{next: next, fixed: fixed}
}

func (h *trafficPathHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *trafficPathHandler) Handle(ctx context.Context, record slog.Record) error {
	path := TrafficPathFromContext(ctx)
	if path == "" {
		path = h.fixed
	}
	clean := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key != "network" {
			clean.AddAttrs(attr)
		}
		return true
	})
	clean.AddAttrs(slog.String("network", path.networkLabel()))
	return h.next.Handle(ctx, clean)
}

func (h *trafficPathHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	fixed := h.fixed
	retained := make([]slog.Attr, 0, len(attrs))
	for _, attr := range attrs {
		if attr.Key == "network" {
			fixed = TrafficPath(strings.ToLower(attr.Value.Resolve().String()))
		} else {
			retained = append(retained, attr)
		}
	}
	return newTrafficPathHandler(h.next.WithAttrs(retained), fixed)
}

func (h *trafficPathHandler) WithGroup(name string) slog.Handler {
	return newTrafficPathHandler(h.next.WithGroup(name), h.fixed)
}

func LoggerWithTrafficPath(logger *slog.Logger, path TrafficPath) *slog.Logger {
	return logger.With("network", path.networkLabel())
}
