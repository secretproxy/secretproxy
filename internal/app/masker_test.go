package app

import (
	"encoding/json"
	"strings"
	"testing"
)

func testMasker() *Masker {
	return NewMasker(PiiConfig{Enabled: false}, nil, 0, 0, true, "preview")
}

func testMaskerNoUnmask() *Masker {
	return NewMasker(PiiConfig{Enabled: false}, nil, 0, 0, false, "preview")
}

func TestMaskKnownSecrets(t *testing.T) {
	m := testMasker()

	tests := []struct {
		name  string
		input string
	}{
		{"GitLab PAT", "token glpat-xYz12345678901234567"},
		{"Stripe live", "key sk_live_1234567890abcdefghij"},
		{"Stripe test", "key sk_test_1234567890abcdefghij"},
		{"Slack bot", "xoxb-1234567890123-1234567890123-AbCdEfGhIjKl"},
		{"SendGrid", "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"},
		{"Mailchimp", "mailchimp = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-us21"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masked := m.MaskText(tt.input)
			if masked == tt.input {
				t.Errorf("expected masking, got unchanged: %s", tt.input)
			}
			if len(masked) == 0 {
				t.Error("masked result is empty")
			}
		})
	}
}

func TestMaskCustomPatterns(t *testing.T) {
	patterns := []PatternEntry{
		{Label: "OPENROUTER", Regex: `sk-or-v1-[a-zA-Z0-9]{20,}`},
		{Label: "DB_URL", Regex: `(?:postgres|mysql)://[^\s:]+:[^\s@]+@[^\s]+`},
	}
	m := NewMasker(PiiConfig{Enabled: false}, patterns, 0, 0, true, "preview")

	tests := []struct {
		name  string
		input string
	}{
		{"OpenRouter", "export KEY=sk-or-v1-abcdef1234567890abcdef1234567890"},
		{"Postgres URL", "postgres://admin:secret@db.host:5432/mydb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masked := m.MaskText(tt.input)
			if masked == tt.input {
				t.Errorf("expected masking, got unchanged: %s", tt.input)
			}
		})
	}
}

func TestMaskSkipsExistingPlaceholders(t *testing.T) {
	m := testMasker()
	input := "check [[SECRET_KEY_GENERIC:sk-or-v1-e01946fc..._8130b90e5677bd3b]]"

	masked := m.MaskText(input)
	if masked != input {
		t.Fatalf("existing placeholder should not be re-masked:\ninput:  %s\nmasked: %s", input, masked)
	}
	if m.VaultCount() != 0 {
		t.Fatalf("existing placeholder should not populate vault, got %d entries", m.VaultCount())
	}
}

func TestNoFalsePositives(t *testing.T) {
	m := testMasker()

	clean := []struct {
		name  string
		input string
	}{
		{"normal text", "hello world nothing secret here"},
		{"model name", "the model is claude-sonnet-4-20250514"},
		{"URL", "https://api.example.com/v1/users"},
		{"password discussion", "set password policy to require 8+ characters"},
	}

	for _, tt := range clean {
		t.Run(tt.name, func(t *testing.T) {
			masked := m.MaskText(tt.input)
			if masked != tt.input {
				t.Errorf("false positive: %q masked to %q", tt.input, masked)
			}
		})
	}
}

func TestRoundtrip(t *testing.T) {
	m := testMasker()
	input := "key sk_live_abcdef1234567890ab and token glpat-xYz12345678901234567"

	masked := m.MaskText(input)
	if masked == input {
		t.Fatal("nothing was masked")
	}

	unmasked := m.UnmaskText(masked)
	if unmasked != input {
		t.Errorf("roundtrip failed:\n  input:    %s\n  unmasked: %s", input, unmasked)
	}
}

func TestUnmaskSkipsUnknownPlaceholders(t *testing.T) {
	m := testMasker()
	// Mask a secret to populate the vault
	masked := m.MaskText("sk_live_abcdef1234567890ab")
	// masked is now something like [[STRIPE_ACCESS_TOKEN_abcdef1234567890]]
	placeholder := masked

	input := "[[UNKNOWN_1234567890abcdef]] and " + placeholder
	result := m.UnmaskText(input)

	if strings.Contains(result, placeholder) {
		t.Error("known placeholder should be replaced")
	}
	if !strings.Contains(result, "[[UNKNOWN_1234567890abcdef]]") {
		t.Error("unknown placeholder should remain intact")
	}
	if !strings.Contains(result, "sk_live_abcdef1234567890ab") {
		t.Error("known secret should be restored")
	}
}

func TestUnmaskDisabledDoesNotKeepVaultState(t *testing.T) {
	m := NewMasker(PiiConfig{Enabled: false}, nil, 0, 0, false, "preview")

	masked := m.MaskText("token sk_live_abcdef1234567890ab")
	if masked == "token sk_live_abcdef1234567890ab" {
		t.Fatal("expected secret to be masked")
	}
	if m.VaultCount() != 0 {
		t.Fatalf("expected no vault state when unmask is disabled, got %d", m.VaultCount())
	}
	if got := m.UnmaskText(masked); got != masked {
		t.Fatal("unmask should be a no-op when unmask is disabled")
	}
}

func TestMaskerNoUnmaskModeStillMasksText(t *testing.T) {
	m := testMaskerNoUnmask()
	input := "token sk_live_abcdef1234567890ab"

	masked := m.MaskText(input)
	if masked == input {
		t.Fatal("expected masking in no-unmask mode")
	}
	if m.VaultCount() != 0 {
		t.Fatalf("expected no vault entries in no-unmask mode, got %d", m.VaultCount())
	}
}

func TestVaultSizeIsIndependentFromCacheSize(t *testing.T) {
	m := NewMasker(PiiConfig{Enabled: false}, nil, 1, 3, true, "hash")

	inputs := []string{
		"token sk_test_1234567890abcdefghij",
		"token sk_test_abcdefghij1234567890",
		"token sk_test_zyxwvutsrqponmlkjihg",
	}
	for _, input := range inputs {
		m.MaskText(input)
	}

	if got := m.VaultCount(); got != 3 {
		t.Fatalf("expected vault size to follow vault_size, got %d", got)
	}
}

func TestMaskTextHashPlaceholderMode(t *testing.T) {
	m := NewMasker(PiiConfig{Enabled: false}, nil, 0, 0, false, "hash")
	input := "token sk_live_abcdef1234567890ab"

	masked := m.MaskText(input)
	if strings.Contains(masked, "sk_live_abcd") {
		t.Fatalf("hash placeholder mode should not leak secret preview, got %s", masked)
	}
	if !strings.Contains(masked, "[[STRIPE_ACCESS_TOKEN:") {
		t.Fatalf("expected labeled placeholder, got %s", masked)
	}
}

func TestMaskJSONOnlyMessages(t *testing.T) {
	body := map[string]interface{}{
		"model":  "test",
		"system": "You have sk_live_abcdef1234567890ab in system",
		"messages": []interface{}{
			map[string]interface{}{
				"role":    "user",
				"content": "my key is sk_live_abcdef1234567890ab",
			},
		},
		"tools": []interface{}{
			map[string]interface{}{
				"name":        "test",
				"description": "uses sk_live_abcdef1234567890ab",
			},
		},
	}

	raw, _ := json.Marshal(body)
	m := testMasker()
	masked, err := m.MaskJSON(raw)
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]json.RawMessage
	json.Unmarshal(masked, &result)

	// system should NOT be masked
	sys := string(result["system"])
	if !strings.Contains(sys, "sk_live_") {
		t.Error("system should not be masked")
	}

	// tools should NOT be masked
	tools := string(result["tools"])
	if !strings.Contains(tools, "sk_live_") {
		t.Error("tools should not be masked")
	}

	// messages SHOULD be masked (full value gone, only preview in placeholder)
	msgs := string(result["messages"])
	if strings.Contains(msgs, "sk_live_abcdef1234567890ab") {
		t.Error("messages content should be masked")
	}
}

func TestMultipleSecretsInOneText(t *testing.T) {
	m := testMasker()
	input := "stripe sk_live_1234567890abcdefghij gitlab glpat-xYz12345678901234567"

	masked := m.MaskText(input)
	if strings.Contains(masked, "sk_live_1234567890abcdefghij") {
		t.Error("stripe key should be masked")
	}
	if strings.Contains(masked, "glpat-xYz12345678901234567") {
		t.Error("gitlab token should be masked")
	}
}
