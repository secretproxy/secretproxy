package providers

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Anthropic struct {
	textBuf map[int]string
	jsonBuf map[int]string
	toolUse map[int]bool
}

func NewAnthropic() *Anthropic {
	return &Anthropic{
		textBuf: make(map[int]string),
		jsonBuf: make(map[int]string),
		toolUse: make(map[int]bool),
	}
}

func (a *Anthropic) Name() string { return "anthropic" }

func (a *Anthropic) Detect(eventData string) bool {
	for _, t := range []string{"content_block_start", "content_block_delta", "message_start"} {
		if strings.Contains(eventData, `"`+t+`"`) {
			return true
		}
	}
	return false
}

func (a *Anthropic) HandleEvent(eventType, eventData string, unmask Unmasker) string {
	var ev anthropicEvent
	if err := json.Unmarshal([]byte(eventData), &ev); err != nil {
		return formatSSE(eventType, eventData)
	}

	switch ev.Type {
	case "content_block_start":
		if ev.ContentBlock.Type == "tool_use" {
			a.toolUse[ev.Index] = true
		}
		return formatSSE(eventType, eventData)

	case "content_block_delta":
		return a.handleDelta(eventType, eventData, ev, unmask)

	case "content_block_stop":
		return a.handleStop(eventType, eventData, ev, unmask)

	default:
		return formatSSE(eventType, eventData)
	}
}

func (a *Anthropic) handleDelta(eventType, eventData string, ev anthropicEvent, unmask Unmasker) string {
	switch ev.Delta.Type {
	case "text_delta":
		buf := a.textBuf[ev.Index] + ev.Delta.Text
		safe, pending := splitAtPartial(buf)
		a.textBuf[ev.Index] = pending
		if safe == "" {
			return ""
		}
		// Unmask via string replace on original data — preserves all fields
		unmasked := unmask.UnmaskText(safe)
		result := strings.Replace(eventData, ev.Delta.Text, unmasked, 1)
		return formatSSE(eventType, result)

	case "input_json_delta":
		if a.toolUse[ev.Index] {
			a.jsonBuf[ev.Index] += ev.Delta.PartialJSON
			return ""
		}
		return formatSSE(eventType, eventData)

	default:
		return formatSSE(eventType, eventData)
	}
}

func (a *Anthropic) handleStop(eventType, eventData string, ev anthropicEvent, unmask Unmasker) string {
	var out strings.Builder

	if buf := a.textBuf[ev.Index]; buf != "" {
		flushEv := anthropicEvent{
			Type:  "content_block_delta",
			Index: ev.Index,
			Delta: anthropicDelta{Type: "text_delta", Text: unmask.UnmaskText(buf)},
		}
		data, _ := json.Marshal(flushEv)
		fmt.Fprintf(&out, "event: content_block_delta\ndata: %s\n\n", data)
		delete(a.textBuf, ev.Index)
	}

	if buf := a.jsonBuf[ev.Index]; buf != "" {
		flushEv := anthropicEvent{
			Type:  "content_block_delta",
			Index: ev.Index,
			Delta: anthropicDelta{Type: "input_json_delta", PartialJSON: unmask.UnmaskText(buf)},
		}
		data, _ := json.Marshal(flushEv)
		fmt.Fprintf(&out, "event: content_block_delta\ndata: %s\n\n", data)
		delete(a.jsonBuf, ev.Index)
		delete(a.toolUse, ev.Index)
	}

	out.WriteString(formatSSE(eventType, eventData))
	return out.String()
}

func (a *Anthropic) Flush(unmask Unmasker) string {
	var out strings.Builder
	for idx, buf := range a.textBuf {
		if buf != "" {
			ev := anthropicEvent{
				Type:  "content_block_delta",
				Index: idx,
				Delta: anthropicDelta{Type: "text_delta", Text: unmask.UnmaskText(buf)},
			}
			data, _ := json.Marshal(ev)
			fmt.Fprintf(&out, "event: content_block_delta\ndata: %s\n\n", data)
		}
	}
	for idx, buf := range a.jsonBuf {
		if buf != "" {
			ev := anthropicEvent{
				Type:  "content_block_delta",
				Index: idx,
				Delta: anthropicDelta{Type: "input_json_delta", PartialJSON: unmask.UnmaskText(buf)},
			}
			data, _ := json.Marshal(ev)
			fmt.Fprintf(&out, "event: content_block_delta\ndata: %s\n\n", data)
		}
	}
	return out.String()
}

// ── types ────────────────────────────────────────

type anthropicEvent struct {
	Type         string          `json:"type"`
	Index        int             `json:"index"`
	ContentBlock anthropicBlock  `json:"content_block,omitempty"`
	Delta        anthropicDelta  `json:"delta,omitempty"`
}

type anthropicBlock struct {
	Type string `json:"type"`
}

type anthropicDelta struct {
	Type        string `json:"type,omitempty"`
	Text        string `json:"text,omitempty"`
	PartialJSON string `json:"partial_json,omitempty"`
}

// ── helpers ──────────────────────────────────────

func formatSSE(eventType, data string) string {
	if eventType != "" {
		return fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, data)
	}
	return fmt.Sprintf("data: %s\n\n", data)
}

func splitAtPartial(text string) (string, string) {
	idx := strings.LastIndex(text, "[[")
	if idx == -1 {
		if strings.HasSuffix(text, "[") {
			return text[:len(text)-1], "["
		}
		return text, ""
	}
	if strings.Contains(text[idx:], "]]") {
		return text, ""
	}
	return text[:idx], text[idx:]
}
