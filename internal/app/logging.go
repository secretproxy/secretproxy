package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func initLogger(level slog.Level, format string) {
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = newPrettyHandler(os.Stderr, opts)
	}

	slog.SetDefault(slog.New(handler))
}

type prettyHandler struct {
	w      io.Writer
	level  slog.Leveler
	attrs  []slog.Attr
	groups []string
	mu     *sync.Mutex
}

func newPrettyHandler(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
	var level slog.Leveler = slog.LevelInfo
	if opts != nil && opts.Level != nil {
		level = opts.Level
	}
	return &prettyHandler{
		w:     w,
		level: level,
		mu:    &sync.Mutex{},
	}
}

func (h *prettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *prettyHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder

	ts := r.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	b.WriteString(ts.Format("15:04:05"))
	b.WriteByte(' ')
	b.WriteString(prettyLevel(r.Level))
	b.WriteByte(' ')
	b.WriteString(r.Message)

	attrs := make([]slog.Attr, 0, len(h.attrs)+r.NumAttrs())
	attrs = append(attrs, h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	for _, a := range attrs {
		a.Value = a.Value.Resolve()
		if a.Key == "" {
			continue
		}

		key := a.Key
		if len(h.groups) > 0 {
			key = strings.Join(append(append([]string{}, h.groups...), key), ".")
		}

		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(prettyValue(a.Value))
	}
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *prettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &next
}

func (h *prettyHandler) WithGroup(name string) slog.Handler {
	next := *h
	next.groups = append(append([]string{}, h.groups...), name)
	return &next
}

func prettyLevel(level slog.Level) string {
	switch {
	case level <= slog.LevelDebug:
		return "DBG"
	case level < slog.LevelWarn:
		return "INF"
	case level < slog.LevelError:
		return "WRN"
	default:
		return "ERR"
	}
}

func prettyValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindString:
		return quoteIfNeeded(v.String())
	case slog.KindInt64:
		return strconv.FormatInt(v.Int64(), 10)
	case slog.KindUint64:
		return strconv.FormatUint(v.Uint64(), 10)
	case slog.KindFloat64:
		return strconv.FormatFloat(v.Float64(), 'f', -1, 64)
	case slog.KindBool:
		return strconv.FormatBool(v.Bool())
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time().Format(time.RFC3339)
	case slog.KindAny:
		if err, ok := v.Any().(error); ok {
			return quoteIfNeeded(err.Error())
		}
		return quoteIfNeeded(fmt.Sprint(v.Any()))
	default:
		return quoteIfNeeded(v.String())
	}
}

func quoteIfNeeded(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, " \t\n\r\"=") {
		return strconv.Quote(s)
	}
	return s
}

func logStartup(version, addr string) {
	slog.Info("startup", "version", version, "listen", "http://"+addr)
}

func logRoute(slug, target string) {
	slog.Info("route", "slug", slug, "target", shortHost(target))
}

func logDefaultRoute(target string) {
	slog.Info("route", "slug", "*", "target", shortHost(target))
}

func logShutdown() {
	slog.Info("shutdown")
}

func logRequest(method, target string, masked, vault int) {
	attrs := []any{"method", method, "target", target}
	if masked > 0 {
		attrs = append(attrs, "masked", masked)
	}
	if vault > 0 {
		attrs = append(attrs, "vault", vault)
	}
	slog.Info("request", attrs...)
}

func logResponse(target string, status int, kind string, unmasked bool, bytes int) {
	attrs := []any{"target", target, "status", status, "kind", kind}
	if unmasked {
		attrs = append(attrs, "unmasked", true)
	}
	if bytes > 0 {
		attrs = append(attrs, "bytes", bytes)
	}
	slog.Info("response", attrs...)
}

func logWSSession(target string) {
	slog.Info("ws_open", "target", shortHost(target))
}

func logWSMasked(messageIndex, masked, vault int) {
	attrs := []any{"message", messageIndex}
	if masked > 0 {
		attrs = append(attrs, "masked", masked)
	}
	if vault > 0 {
		attrs = append(attrs, "vault", vault)
	}
	slog.Debug("ws_masked", attrs...)
}

func logWSClose(d time.Duration) {
	slog.Info("ws_close", "duration", d.Round(time.Second))
}
