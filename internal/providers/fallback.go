package providers

import "strings"

// Fallback buffers the entire SSE stream, unmasks, and emits at the end.
// Used for unknown SSE formats where we can't stream-unmask safely.
type Fallback struct {
	buf strings.Builder
}

func NewFallback() *Fallback {
	return &Fallback{}
}

func (f *Fallback) Name() string { return "fallback" }

func (f *Fallback) Detect(_ string) bool { return true }

func (f *Fallback) HandleEvent(eventType, eventData string, _ Unmasker) string {
	f.buf.WriteString(formatSSE(eventType, eventData))
	return ""
}

func (f *Fallback) Flush(unmask Unmasker) string {
	return unmask.UnmaskText(f.buf.String())
}
