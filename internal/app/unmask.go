package app

import (
	"bufio"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/secretproxy/secretproxy/internal/providers"
)

// Available SSE providers in priority order.
// First one whose Detect() returns true is used for the entire stream.
var sseProviders = []func() providers.SSEProvider{
	func() providers.SSEProvider { return providers.NewAnthropic() },
	func() providers.SSEProvider { return providers.NewOpenAI() },
	func() providers.SSEProvider { return providers.NewFallback() },
}

// UnmaskSSE reads SSE events, auto-detects the provider format,
// and unmasks [[...]] placeholders in the stream.
func UnmaskSSE(src io.Reader, dst http.ResponseWriter, masker *Masker) {
	flusher, _ := dst.(http.Flusher)
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var eventLines []string
	var provider providers.SSEProvider
	detected := false

	emit := func(s string) {
		if s != "" {
			dst.Write([]byte(s))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			eventLines = append(eventLines, line)
			continue
		}

		raw := strings.Join(eventLines, "\n") + "\n\n"
		eventLines = eventLines[:0]

		eventType, dataLine := parseSSELines(raw)
		if dataLine == "" {
			emit(raw)
			continue
		}

		// Auto-detect provider on first data event
		if !detected {
			for _, create := range sseProviders {
				p := create()
				if p.Detect(dataLine) {
					provider = p
					// detected provider, no need to log every time
					break
				}
			}
			detected = true
		}

		result := provider.HandleEvent(eventType, dataLine, masker)
		emit(result)
	}

	// Flush provider buffers
	if provider != nil {
		emit(provider.Flush(masker))
	}

	if err := scanner.Err(); err != nil {
		slog.Error("sse_stream_error", "err", err)
	}
}

func parseSSELines(raw string) (eventType, data string) {
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
		} else if strings.HasPrefix(line, "event: ") {
			eventType = strings.TrimPrefix(line, "event: ")
		}
	}
	return
}
