package app

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

type Masker struct {
	scanner         *Scanner
	vault           *Vault
	pii             *PiiDetector
	placeholderMode string
}

func NewMasker(piiCfg PiiConfig, patterns []PatternEntry, cacheSize, vaultSize int, unmask bool, placeholderMode string) *Masker {
	scanner := NewScanner(patterns, cacheSize)

	var pii *PiiDetector
	if piiCfg.Enabled {
		pii = NewPiiDetector(piiCfg)
	}

	var vault *Vault
	if unmask {
		vault = NewVault(vaultSize)
	}

	return &Masker{
		scanner:         scanner,
		vault:           vault,
		pii:             pii,
		placeholderMode: placeholderMode,
	}
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:8])
}

// secretPreview returns first recognizable part of a secret for LLM context.
// "sk-or-v1-e01946fcd70dc..." → "sk-or-v1-e019..."
func secretPreview(s string) string {
	// Show enough to identify the type, mask the rest
	show := 12
	if len(s) <= show+4 {
		return s[:len(s)/2] + "..."
	}
	return s[:show] + "..."
}

// redact shows only first 3 and last 3 chars, masking the rest.
// Short values are fully masked. Operates on runes for UTF-8 safety.
func redact(s string) string {
	runes := []rune(s)
	n := len(runes)
	if n <= 8 {
		return strings.Repeat("*", n)
	}
	return string(runes[:3]) + strings.Repeat("*", n-6) + string(runes[n-3:])
}

func (m *Masker) formatPlaceholder(label, secret string) string {
	hash := shortHash(secret)
	switch m.placeholderMode {
	case "hash":
		return fmt.Sprintf("[[%s:%s]]", label, hash)
	default:
		preview := secretPreview(secret)
		return fmt.Sprintf("[[%s:%s_%s]]", label, preview, hash)
	}
}

// MaskText scans text for secrets and replaces them with [[LABEL:preview_hash]] placeholders.
// Returns masked text and scan duration.
func (m *Masker) MaskTextTimed(text string) (string, time.Duration) {
	start := time.Now()
	result := m.MaskText(text)
	return result, time.Since(start)
}

func (m *Masker) MaskText(text string) string {
	type match struct {
		value string
		label string
	}

	var matches []match

	// Scan with all rules (custom + gitleaks)
	findings := m.scanner.DetectString(text)
	for _, f := range findings {
		label := strings.ToUpper(strings.ReplaceAll(f.RuleID, "-", "_"))
		matches = append(matches, match{value: f.Secret, label: label})
	}

	// PII scan
	if m.pii != nil {
		piiMatches := m.pii.Scan(text)
		for _, p := range piiMatches {
			label := "PII_" + strings.ToUpper(p.EntityType)
			matches = append(matches, match{value: p.Value, label: label})
		}
	}

	if len(matches) == 0 {
		return text
	}

	// Longest matches first to avoid masking substrings
	for i := 0; i < len(matches); i++ {
		for j := i + 1; j < len(matches); j++ {
			if len(matches[j].value) > len(matches[i].value) {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}

	result := text
	for _, m2 := range matches {
		secret := m2.value
		if !strings.Contains(result, secret) {
			continue
		}
		placeholder := m.formatPlaceholder(m2.label, secret)

		if m.vault != nil {
			isNew := m.vault.Store(placeholder, secret)
			if isNew {
				slog.Debug("secret_masked", "label", m2.label, "value", redact(secret), "placeholder", placeholder)
			}
		} else {
			slog.Debug("secret_masked", "label", m2.label, "value", redact(secret), "placeholder", placeholder)
		}
		result = strings.ReplaceAll(result, secret, placeholder)
	}
	return result
}

func (m *Masker) UnmaskText(text string) string {
	if m.vault == nil {
		return text
	}
	result := text
	searchFrom := 0
	for {
		start := strings.Index(result[searchFrom:], "[[")
		if start == -1 {
			break
		}
		start += searchFrom
		end := strings.Index(result[start:], "]]")
		if end == -1 {
			break
		}
		end += start + 2
		placeholder := result[start:end]
		if real, ok := m.vault.Get(placeholder); ok {
			result = result[:start] + real + result[end:]
			searchFrom = start + len(real)
		} else {
			searchFrom = end
		}
	}
	return result
}

func (m *Masker) VaultCount() int {
	if m == nil || m.vault == nil {
		return 0
	}
	return m.vault.Count()
}

// MaskBody masks secrets in request body. Tries JSON (messages[].content), falls back to plain text scan.
// Skips binary content (images, archives, protobuf, etc.).
func (m *Masker) MaskBody(body []byte, contentType string) []byte {
	if len(body) == 0 {
		return body
	}

	if !isTextContent(contentType) {
		return body
	}

	// JSON body — try structured scan first (only user messages)
	if strings.Contains(contentType, "json") {
		masked, err := m.MaskJSON(body)
		if err == nil {
			return masked // MaskJSON handled it (changed or not)
		}
	}

	// Non-JSON text or JSON parse error — plain text scan
	text := string(body)
	masked := m.MaskText(text)
	return []byte(masked)
}

func isTextContent(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "yaml") ||
		strings.Contains(ct, "toml") ||
		strings.Contains(ct, "x-www-form-urlencoded")
}

// MaskJSON masks secrets in user messages only.
// Replaces user message content in-place via string replacement — no JSON re-serialization
// of the top-level object, preserving exact field order, signatures, and encoding.
func (m *Masker) MaskJSON(body []byte) ([]byte, error) {
	// Find scannable arrays: "messages" (Anthropic/OpenAI) or "input" (Codex Responses API)
	var wrapper struct {
		Messages []json.RawMessage `json:"messages"`
		Input    []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, err
	}

	msgs := wrapper.Messages
	if len(msgs) == 0 {
		msgs = wrapper.Input
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("no messages or input key")
	}

	result := string(body)
	for _, msgRaw := range msgs {
		raw := string(msgRaw)

		// Skip assistant messages and anything with signatures/thinking
		var peek struct {
			Role string `json:"role"`
			Type string `json:"type"`
		}
		json.Unmarshal(msgRaw, &peek)
		if peek.Role == "assistant" || peek.Type == "thinking" {
			continue
		}
		// Skip messages containing signature fields (thinking blocks in history)
		// Check both raw and escaped JSON forms
		if strings.Contains(raw, `"signature"`) || strings.Contains(raw, `\"signature\"`) {
			continue
		}

		masked := m.MaskText(raw)
		if masked != raw {
			result = strings.Replace(result, raw, masked, 1)
		}
	}

	if result == string(body) {
		return body, nil
	}

	// Verify signatures preserved
	if strings.Contains(string(body), `"signature"`) {
		type msg struct {
			Content []struct {
				Signature string `json:"signature"`
			} `json:"content"`
		}
		var origWrapper, maskedWrapper struct {
			Messages []json.RawMessage `json:"messages"`
		}
		json.Unmarshal(body, &origWrapper)
		json.Unmarshal([]byte(result), &maskedWrapper)
		for i := range origWrapper.Messages {
			var o, m struct {
				Content []struct {
					Signature string `json:"signature"`
				} `json:"content"`
			}
			json.Unmarshal(origWrapper.Messages[i], &o)
			json.Unmarshal(maskedWrapper.Messages[i], &m)
			for j := range o.Content {
				if o.Content[j].Signature != "" && (j >= len(m.Content) || m.Content[j].Signature != o.Content[j].Signature) {
					slog.Warn("signature_guard_triggered", "message", i, "content", j)
					return body, nil // bail out — return unmasked to avoid breaking API
				}
			}
		}
	}

	return []byte(result), nil
}
