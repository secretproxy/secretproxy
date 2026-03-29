package app

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMaskJSONPreservesThinkingSignature(t *testing.T) {
	m := testMasker()

	// Simulate Claude Code request with thinking signature in assistant message
	body := `{
		"model": "claude-sonnet-4-20250514",
		"system": "you are helpful",
		"messages": [
			{"role": "user", "content": "check key sk_live_abcdef1234567890ab"},
			{"role": "assistant", "content": [
				{"type": "thinking", "thinking": "analyzing...", "signature": "eyJhbGciOiJFZERTQSIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.fakesig1234567890abcdef1234567890ab"},
				{"type": "text", "text": "The key looks like a Stripe key."}
			]},
			{"role": "user", "content": "ok use it"}
		]
	}`

	masked, err := m.MaskJSON([]byte(body))
	if err != nil {
		t.Fatal(err)
	}

	maskedStr := string(masked)

	// User message secret should be masked
	if strings.Contains(maskedStr, "sk_live_abcdef1234567890ab") {
		t.Error("user message secret should be masked")
	}

	// Signature should NOT be masked (it's in assistant message)
	if !strings.Contains(maskedStr, "eyJhbGciOiJFZERTQSIsImtpZCI6IjEyMzQ1Njc4OTAifQ") {
		t.Errorf("thinking signature was corrupted!\nmasked: %s", maskedStr[:min(500, len(maskedStr))])
	}

	// Verify JSON is valid
	var check map[string]json.RawMessage
	if err := json.Unmarshal(masked, &check); err != nil {
		t.Fatalf("masked output is not valid JSON: %v", err)
	}

	// Verify messages structure intact
	var msgs []json.RawMessage
	if err := json.Unmarshal(check["messages"], &msgs); err != nil {
		t.Fatalf("messages not valid: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}
}

func TestMaskBodyDoesNotFallThroughForJSONWithMessages(t *testing.T) {
	m := testMasker()

	// JSON with messages but no secrets in user messages
	body := `{"system":"use key sk_live_SystemSecretThatShouldStay1","messages":[{"role":"user","content":"hello"},{"role":"assistant","content":"world"}]}`

	masked := m.MaskBody([]byte(body), "application/json")
	maskedStr := string(masked)

	// System field should NOT be masked (MaskJSON skips it, MaskBody should not fall through)
	if !strings.Contains(maskedStr, "sk_live_SystemSecretThatShouldStay1") {
		t.Errorf("system field was masked — MaskBody fell through to plain text!\nmasked: %s", maskedStr)
	}
}
