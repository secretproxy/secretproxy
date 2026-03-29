// Package providers defines the interface for SSE stream unmask providers.
// Each provider knows how to parse its SSE format and extract text for unmasking.
package providers

// Unmasker replaces [[...]] placeholders with original values.
type Unmasker interface {
	UnmaskText(text string) string
}

// SSEProvider handles streaming unmask for a specific LLM API format.
type SSEProvider interface {
	// Name returns the provider name (for logging).
	Name() string

	// Detect returns true if this provider can handle the given SSE event data.
	Detect(eventData string) bool

	// HandleEvent processes one SSE event. Returns the (possibly modified) event
	// to emit, or "" to suppress it (e.g. buffered for later).
	HandleEvent(eventType, eventData string, unmask Unmasker) string

	// Flush returns any buffered content as SSE events at end of stream.
	Flush(unmask Unmasker) string
}
