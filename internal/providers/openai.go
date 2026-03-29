package providers

import (
	"encoding/json"
	"strings"
)

type OpenAI struct {
	textBuf map[int]string
	toolBuf map[string]string // tool call id -> accumulated arguments
}

func NewOpenAI() *OpenAI {
	return &OpenAI{
		textBuf: make(map[int]string),
		toolBuf: make(map[string]string),
	}
}

func (o *OpenAI) Name() string { return "openai" }

func (o *OpenAI) Detect(eventData string) bool {
	return strings.Contains(eventData, `"choices"`) || eventData == "[DONE]"
}

func (o *OpenAI) HandleEvent(eventType, eventData string, unmask Unmasker) string {
	if eventData == "[DONE]" {
		return formatSSE(eventType, eventData)
	}

	var ev openaiChunk
	if err := json.Unmarshal([]byte(eventData), &ev); err != nil {
		return formatSSE(eventType, eventData)
	}

	changed := false
	for i, choice := range ev.Choices {
		// Text content
		if choice.Delta.Content != "" {
			buf := o.textBuf[choice.Index] + choice.Delta.Content
			safe, pending := splitAtPartial(buf)
			o.textBuf[choice.Index] = pending
			if safe != "" {
				ev.Choices[i].Delta.Content = unmask.UnmaskText(safe)
				changed = true
			} else {
				ev.Choices[i].Delta.Content = ""
			}
		}

		// Tool calls — accumulate arguments
		for j, tc := range choice.Delta.ToolCalls {
			if tc.Function.Arguments != "" {
				key := tc.ID
				if key == "" {
					key = tc.Index
				}
				o.toolBuf[key] += tc.Function.Arguments
				ev.Choices[i].Delta.ToolCalls[j].Function.Arguments = ""
				changed = true
			}
		}

		// Finish reason — flush all buffers before [DONE]
		if choice.FinishReason != "" {
			// Flush text buffer
			if buf := o.textBuf[choice.Index]; buf != "" {
				ev.Choices[i].Delta.Content = unmask.UnmaskText(buf)
				delete(o.textBuf, choice.Index)
				changed = true
			}
			// Flush tool call argument buffers
			for id, args := range o.toolBuf {
				ev.Choices[i].Delta.ToolCalls = append(ev.Choices[i].Delta.ToolCalls, openaiToolCall{
					ID:       id,
					Function: openaiFunction{Arguments: unmask.UnmaskText(args)},
				})
				delete(o.toolBuf, id)
				changed = true
			}
		}
	}

	if !changed {
		return formatSSE(eventType, eventData)
	}

	// Skip empty content deltas (buffered)
	hasContent := false
	for _, c := range ev.Choices {
		if c.Delta.Content != "" || c.FinishReason != "" || len(c.Delta.ToolCalls) > 0 {
			hasContent = true
			break
		}
	}
	if !hasContent {
		return ""
	}

	data, _ := json.Marshal(ev)
	return formatSSE(eventType, string(data))
}

func (o *OpenAI) Flush(unmask Unmasker) string {
	var out strings.Builder

	// Flush text buffers
	for idx, buf := range o.textBuf {
		if buf != "" {
			chunk := openaiChunk{
				Choices: []openaiChoice{{
					Index: idx,
					Delta: openaiDelta{Content: unmask.UnmaskText(buf)},
				}},
			}
			data, _ := json.Marshal(chunk)
			out.WriteString(formatSSE("", string(data)))
		}
	}

	// Flush tool call argument buffers
	for id, args := range o.toolBuf {
		unmasked := unmask.UnmaskText(args)
		chunk := openaiChunk{
			Choices: []openaiChoice{{
				Index: 0,
				Delta: openaiDelta{
					ToolCalls: []openaiToolCall{{
						ID:       id,
						Function: openaiFunction{Arguments: unmasked},
					}},
				},
			}},
		}
		data, _ := json.Marshal(chunk)
		out.WriteString(formatSSE("", string(data)))
	}

	return out.String()
}

// ── types ────────────────────────────────────────

type openaiChunk struct {
	ID      string         `json:"id,omitempty"`
	Object  string         `json:"object,omitempty"`
	Created int64          `json:"created,omitempty"`
	Model   string         `json:"model,omitempty"`
	Choices []openaiChoice `json:"choices"`
}

type openaiChoice struct {
	Index        int         `json:"index"`
	Delta        openaiDelta `json:"delta"`
	FinishReason string      `json:"finish_reason,omitempty"`
}

type openaiDelta struct {
	Role      string           `json:"role,omitempty"`
	Content   string           `json:"content,omitempty"`
	ToolCalls []openaiToolCall `json:"tool_calls,omitempty"`
}

type openaiToolCall struct {
	Index    string         `json:"index,omitempty"`
	ID       string         `json:"id,omitempty"`
	Type     string         `json:"type,omitempty"`
	Function openaiFunction `json:"function"`
}

type openaiFunction struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}
