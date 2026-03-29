package app

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestE2E_MaskAndUnmask simulates full Claude Code flow:
// 1. Client sends prompt with secret
// 2. Proxy masks it
// 3. API generates response with placeholder in tool_use
// 4. Proxy unmasks tool_use input
// 5. Client receives real secret back
func TestE2E_MaskAndUnmask(t *testing.T) {
	m := testMasker()

	// Mock API that echoes masked content back as tool_use
	var receivedBody string
	api := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)

		// Extract the masked content from messages
		var req map[string]json.RawMessage
		json.Unmarshal(body, &req)
		var msgs []map[string]interface{}
		json.Unmarshal(req["messages"], &msgs)
		content := ""
		if len(msgs) > 0 {
			if c, ok := msgs[0]["content"].(string); ok {
				content = c
			}
		}

		// Respond with SSE: text block + tool_use with the masked content
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)

		// message_start
		fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_test\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"test\"}}\n\n")
		flusher.Flush()

		// text block: "Checking key..."
		fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
		flusher.Flush()
		textDelta := fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Checking: %s"}}`, content)
		fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", textDelta)
		flusher.Flush()
		fmt.Fprint(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
		flusher.Flush()

		// tool_use block: curl command with the masked key, split across chunks
		fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tu_1\",\"name\":\"bash\"}}\n\n")
		flusher.Flush()

		// Split the tool input into small chunks (like real API does)
		toolInput := fmt.Sprintf(`{"command":"curl -H \"Authorization: Bearer %s\" https://api.example.com"}`, content)
		chunkSize := 20
		for i := 0; i < len(toolInput); i += chunkSize {
			end := i + chunkSize
			if end > len(toolInput) {
				end = len(toolInput)
			}
			chunk := toolInput[i:end]
			// Escape for JSON string
			escaped := strings.ReplaceAll(chunk, `\`, `\\`)
			escaped = strings.ReplaceAll(escaped, `"`, `\"`)
			delta := fmt.Sprintf(`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"%s"}}`, escaped)
			fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", delta)
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}

		fmt.Fprint(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n")
		flusher.Flush()
		fmt.Fprint(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		flusher.Flush()
	}))
	defer api.Close()

	proxy := &Proxy{
		masker:      m,
		routes:      map[string]string{"api": api.URL},
		client:      &http.Client{Timeout: 5 * time.Second},
		maxBodySize: defaultMaxBody,
	}
	srv := newTestServer(t, proxy)
	defer srv.Close()

	// Send request with real secret
	secret := "sk_live_RealSecretKeyThatMustBeProtected123"
	reqBody := fmt.Sprintf(`{"messages":[{"role":"user","content":"check key %s"}]}`, secret)

	resp, err := http.Post(srv.URL+"/api/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	// Verify: secret was masked before reaching API
	if strings.Contains(receivedBody, secret) {
		t.Error("secret should NOT reach the API")
	}
	if !strings.Contains(receivedBody, "[[STRIPE_ACCESS_TOKEN:") {
		t.Errorf("API should receive placeholder, got: %s", receivedBody[:min(200, len(receivedBody))])
	}

	// Verify: text_delta was unmasked
	if !strings.Contains(text, secret) {
		t.Errorf("text_delta should contain unmasked secret.\nResponse:\n%s", text)
	}

	// Verify: tool_use input_json_delta was unmasked
	if strings.Contains(text, "[[STRIPE_ACCESS_TOKEN:") {
		t.Error("placeholder should NOT remain in response")
	}

	// Verify: tool input contains the real secret
	if !strings.Contains(text, secret) {
		t.Errorf("tool_use input should contain real secret.\nResponse:\n%s", text)
	}
}
