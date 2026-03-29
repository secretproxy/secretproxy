package providers

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// mockUnmasker replaces [[PLACEHOLDER:...]] with a fixed value.
type mockUnmasker struct {
	replacements map[string]string
}

func (m *mockUnmasker) UnmaskText(text string) string {
	result := text
	for placeholder, real := range m.replacements {
		result = strings.ReplaceAll(result, placeholder, real)
	}
	return result
}

func newMockUnmasker(pairs ...string) *mockUnmasker {
	m := &mockUnmasker{replacements: make(map[string]string)}
	for i := 0; i+1 < len(pairs); i += 2 {
		m.replacements[pairs[i]] = pairs[i+1]
	}
	return m
}

// ── splitAtPartial ──────────────────────────────

func TestSplitAtPartial(t *testing.T) {
	tests := []struct {
		input       string
		wantSafe    string
		wantPending string
	}{
		{"hello world", "hello world", ""},
		{"hello [[TOKEN:abc123]]", "hello [[TOKEN:abc123]]", ""},
		{"hello [[TOKEN", "hello ", "[[TOKEN"},
		{"hello [", "hello ", "["},
		{"[[FULL:done]] rest", "[[FULL:done]] rest", ""},
		{"", "", ""},
		{"no placeholders at all", "no placeholders at all", ""},
	}
	for _, tt := range tests {
		safe, pending := splitAtPartial(tt.input)
		if safe != tt.wantSafe || pending != tt.wantPending {
			t.Errorf("splitAtPartial(%q) = (%q, %q), want (%q, %q)",
				tt.input, safe, pending, tt.wantSafe, tt.wantPending)
		}
	}
}

// ── OpenAI ──────────────────────────────────────

func TestOpenAI_Detect(t *testing.T) {
	o := NewOpenAI()
	if !o.Detect(`{"choices":[]}`) {
		t.Error("should detect choices")
	}
	if !o.Detect("[DONE]") {
		t.Error("should detect [DONE]")
	}
	if o.Detect(`{"content_block_delta":"text"}`) {
		t.Error("should not detect anthropic format")
	}
}

func TestOpenAI_DonePassthrough(t *testing.T) {
	o := NewOpenAI()
	unmasker := newMockUnmasker()
	result := o.HandleEvent("", "[DONE]", unmasker)
	if !strings.Contains(result, "[DONE]") {
		t.Errorf("[DONE] should pass through, got: %q", result)
	}
}

func TestOpenAI_TextUnmask(t *testing.T) {
	o := NewOpenAI()
	unmasker := newMockUnmasker("[[TOKEN:abc]]", "sk-real-secret")

	// Send chunk with complete placeholder
	chunk := openaiChunk{
		Choices: []openaiChoice{{
			Index: 0,
			Delta: openaiDelta{Content: "key is [[TOKEN:abc]]"},
		}},
	}
	data, _ := json.Marshal(chunk)

	result := o.HandleEvent("", string(data), unmasker)

	if !strings.Contains(result, "sk-real-secret") {
		t.Errorf("expected unmasked secret in output, got: %s", result)
	}
	if strings.Contains(result, "[[TOKEN:abc]]") {
		t.Errorf("placeholder should be replaced, got: %s", result)
	}
}

func TestOpenAI_TextBuffering(t *testing.T) {
	o := NewOpenAI()
	unmasker := newMockUnmasker("[[TOKEN:abc]]", "SECRET")

	// Chunk 1: partial placeholder
	c1 := openaiChunk{Choices: []openaiChoice{{Index: 0, Delta: openaiDelta{Content: "start [[TOK"}}}}
	d1, _ := json.Marshal(c1)
	r1 := o.HandleEvent("", string(d1), unmasker)

	// Should emit "start " and buffer "[[TOK"
	if strings.Contains(r1, "[[TOK") {
		t.Errorf("partial placeholder should be buffered, got: %s", r1)
	}

	// Chunk 2: rest of placeholder
	c2 := openaiChunk{Choices: []openaiChoice{{Index: 0, Delta: openaiDelta{Content: "EN:abc]] end"}}}}
	d2, _ := json.Marshal(c2)
	r2 := o.HandleEvent("", string(d2), unmasker)

	if !strings.Contains(r2, "SECRET") {
		t.Errorf("completed placeholder should be unmasked, got: %s", r2)
	}
}

func TestOpenAI_ToolCallFlushOnFinish(t *testing.T) {
	o := NewOpenAI()
	unmasker := newMockUnmasker("[[KEY:x]]", "real-key")

	// Accumulate tool call arguments
	c1 := openaiChunk{Choices: []openaiChoice{{
		Index: 0,
		Delta: openaiDelta{ToolCalls: []openaiToolCall{{
			ID:       "call_1",
			Function: openaiFunction{Arguments: `{"key":"[[KEY`},
		}}},
	}}}
	d1, _ := json.Marshal(c1)
	o.HandleEvent("", string(d1), unmasker)

	c2 := openaiChunk{Choices: []openaiChoice{{
		Index: 0,
		Delta: openaiDelta{ToolCalls: []openaiToolCall{{
			ID:       "call_1",
			Function: openaiFunction{Arguments: `:x]]"}`},
		}}},
	}}}
	d2, _ := json.Marshal(c2)
	o.HandleEvent("", string(d2), unmasker)

	// Finish reason should flush tool buffers
	c3 := openaiChunk{Choices: []openaiChoice{{
		Index:        0,
		FinishReason: "tool_calls",
		Delta:        openaiDelta{},
	}}}
	d3, _ := json.Marshal(c3)
	r3 := o.HandleEvent("", string(d3), unmasker)

	if !strings.Contains(r3, "real-key") {
		t.Errorf("tool call args should be unmasked on finish_reason, got: %s", r3)
	}

	// Flush should have nothing left
	flushed := o.Flush(unmasker)
	if strings.Contains(flushed, "real-key") {
		t.Errorf("Flush should be empty after finish_reason handled it, got: %s", flushed)
	}
}

// ── Anthropic ───────────────────────────────────

func TestAnthropic_Detect(t *testing.T) {
	a := NewAnthropic()
	if !a.Detect(`{"type":"content_block_delta"}`) {
		t.Error("should detect content_block_delta")
	}
	if !a.Detect(`{"type":"message_start"}`) {
		t.Error("should detect message_start")
	}
	if a.Detect(`{"choices":[]}`) {
		t.Error("should not detect openai format")
	}
}

func TestAnthropic_TextDeltaUnmask(t *testing.T) {
	a := NewAnthropic()
	unmasker := newMockUnmasker("[[SECRET:x]]", "real-value")

	ev := `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"the [[SECRET:x]] here"}}`
	result := a.HandleEvent("content_block_delta", ev, unmasker)

	if !strings.Contains(result, "real-value") {
		t.Errorf("expected unmasked text, got: %s", result)
	}
}

func TestAnthropic_TextBuffering(t *testing.T) {
	a := NewAnthropic()
	unmasker := newMockUnmasker("[[KEY:z]]", "SECRET")

	// Partial placeholder
	ev1 := `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"before [[KEY"}}`
	r1 := a.HandleEvent("content_block_delta", ev1, unmasker)

	// "[[KEY" should be buffered
	if strings.Contains(r1, "[[KEY") {
		t.Errorf("partial should be buffered, got: %s", r1)
	}

	// Complete the placeholder in second delta
	ev2 := `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":":z]] after"}}`
	r2 := a.HandleEvent("content_block_delta", ev2, unmasker)

	if !strings.Contains(r2, "SECRET") {
		t.Errorf("completed placeholder should be unmasked, got: %s", r2)
	}
}

func TestAnthropic_ToolUseBuffering(t *testing.T) {
	a := NewAnthropic()
	unmasker := newMockUnmasker("[[TOK:a]]", "secret-val")

	// Start tool_use block
	start := `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use"}}`
	a.HandleEvent("content_block_start", start, unmasker)

	// JSON deltas should be buffered
	d1 := `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"k\":\"[[TOK:a"}}`
	r1 := a.HandleEvent("content_block_delta", d1, unmasker)
	if r1 != "" {
		t.Errorf("tool use json should be buffered, got: %s", r1)
	}

	d2 := `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"]]\"}"  }}`
	a.HandleEvent("content_block_delta", d2, unmasker)

	// Stop flushes
	stop := `{"type":"content_block_stop","index":1}`
	r3 := a.HandleEvent("content_block_stop", stop, unmasker)

	if !strings.Contains(r3, "secret-val") {
		t.Errorf("tool use flush should unmask, got: %s", r3)
	}
}

// ── Fallback ────────────────────────────────────

func TestFallback_BuffersEverything(t *testing.T) {
	f := NewFallback()
	unmasker := newMockUnmasker("[[X:1]]", "REAL")

	r1 := f.HandleEvent("", "chunk with [[X:1]]", unmasker)
	r2 := f.HandleEvent("", "more data", unmasker)

	if r1 != "" || r2 != "" {
		t.Error("fallback should buffer, not emit")
	}

	flushed := f.Flush(unmasker)
	if !strings.Contains(flushed, "REAL") {
		t.Errorf("flush should unmask, got: %s", flushed)
	}
	if strings.Contains(flushed, "[[X:1]]") {
		t.Errorf("placeholder should be replaced, got: %s", flushed)
	}
}

func TestFallback_DetectsAnything(t *testing.T) {
	f := NewFallback()
	if !f.Detect("anything") {
		t.Error("fallback should detect everything")
	}
}

// ── formatSSE ───────────────────────────────────

func TestFormatSSE(t *testing.T) {
	// With event type
	r := formatSSE("content_block_delta", `{"data":"test"}`)
	if r != "event: content_block_delta\ndata: {\"data\":\"test\"}\n\n" {
		t.Errorf("unexpected SSE format with event: %q", r)
	}

	// Without event type
	r2 := formatSSE("", `{"data":"test"}`)
	if r2 != "data: {\"data\":\"test\"}\n\n" {
		t.Errorf("unexpected SSE format without event: %q", r2)
	}
}

// ── Capture-based tests ─────────────────────────

// replaySSE reads an SSE capture file and replays events through a provider.
// Returns the concatenated output of all HandleEvent + Flush calls.
func replaySSE(t *testing.T, path string, provider SSEProvider, unmasker Unmasker) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var eventLines []string
	var out strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			eventLines = append(eventLines, line)
			continue
		}
		if len(eventLines) == 0 {
			continue
		}

		var eventType, data string
		for _, l := range eventLines {
			if strings.HasPrefix(l, "data: ") {
				data = strings.TrimPrefix(l, "data: ")
			} else if strings.HasPrefix(l, "event: ") {
				eventType = strings.TrimPrefix(l, "event: ")
			}
		}
		eventLines = eventLines[:0]

		if data == "" {
			continue
		}
		result := provider.HandleEvent(eventType, data, unmasker)
		out.WriteString(result)
	}

	out.WriteString(provider.Flush(unmasker))
	return out.String()
}

func TestCapture_AnthropicStream(t *testing.T) {
	provider := NewAnthropic()
	unmasker := newMockUnmasker(
		"[[API_KEY:sk-ant-api03-abc..._f9e1a2b3]]", "sk-ant-api03-realkey123",
	)

	output := replaySSE(t, "testdata/anthropic_stream.txt", provider, unmasker)

	if !strings.Contains(output, "sk-ant-api03-realkey123") {
		t.Error("expected unmasked secret in output")
	}
	if strings.Contains(output, "[[API_KEY:") {
		t.Error("placeholder should be replaced")
	}
	if !strings.Contains(output, "The token") {
		t.Error("non-secret text should pass through")
	}
	if !strings.Contains(output, "content_block_stop") {
		t.Error("stop event should be present")
	}
	if !strings.Contains(output, "message_stop") {
		t.Error("message_stop should be present")
	}
}

func TestCapture_OpenAIStream(t *testing.T) {
	provider := NewOpenAI()
	unmasker := newMockUnmasker(
		"[[OPENAI_API_KEY:sk-proj-abc..._d4e5f6a7]]", "sk-proj-realkey456",
	)

	output := replaySSE(t, "testdata/openai_stream.txt", provider, unmasker)

	if !strings.Contains(output, "sk-proj-realkey456") {
		t.Error("expected unmasked secret in output")
	}
	if strings.Contains(output, "[[OPENAI_API_KEY:") {
		t.Error("placeholder should be replaced")
	}
	if !strings.Contains(output, "Your key") {
		t.Error("non-secret text should pass through")
	}
	if !strings.Contains(output, "[DONE]") {
		t.Error("[DONE] marker should be present")
	}
}

func TestCapture_OpenAIToolCallStream(t *testing.T) {
	provider := NewOpenAI()
	unmasker := newMockUnmasker(
		"[[SECRET:token123_a1b2]]", "real-secret-token",
	)

	output := replaySSE(t, "testdata/openai_tool_call_stream.txt", provider, unmasker)

	if !strings.Contains(output, "real-secret-token") {
		t.Errorf("expected unmasked secret in tool call args, got:\n%s", output)
	}
	if strings.Contains(output, "[[SECRET:") {
		t.Error("placeholder should be replaced in tool call args")
	}
	if !strings.Contains(output, "store_secret") {
		t.Error("function name should be present")
	}
	if !strings.Contains(output, "[DONE]") {
		t.Error("[DONE] marker should be present")
	}
}
