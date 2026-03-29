package app

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Port != 9900 {
		t.Errorf("expected port 9900, got %d", cfg.Port)
	}
	if len(cfg.Routes) == 0 {
		t.Error("expected default routes")
	}
	if cfg.Routes["codex"] != "https://chatgpt.com/backend-api/codex" {
		t.Error("expected default codex route")
	}
	if cfg.Routes["openai"] != "https://api.openai.com" {
		t.Error("expected default openai route")
	}
	if cfg.PII.Enabled {
		t.Error("PII should be disabled by default")
	}
	if !cfg.UnmaskEnabled() {
		t.Error("unmask should be enabled by default")
	}
	if cfg.PlaceholderModeValue() != "preview" {
		t.Errorf("expected default placeholder mode preview, got %q", cfg.PlaceholderModeValue())
	}
	if cfg.LogFormatValue() != "pretty" {
		t.Errorf("expected default log format pretty, got %q", cfg.LogFormatValue())
	}
	if cfg.VaultSize != 2048 {
		t.Errorf("expected default vault size 2048, got %d", cfg.VaultSize)
	}
}

func TestLoadConfigMissing(t *testing.T) {
	cfg := LoadConfig("/nonexistent/path/config.toml")
	if cfg.Port != 9900 {
		t.Error("missing config should return defaults")
	}
}

func TestLoadConfigTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
port = 8888
cache_size = 64
vault_size = 7
unmask = false
placeholder_mode = "hash"
log_format = "json"
log_level = "debug"
default_target = "https://fallback.example.com"

[routes]
test = "https://test.example.com"

[[patterns]]
label = "CUSTOM"
regex = 'custom_[a-z]{10}'
`
	os.WriteFile(path, []byte(content), 0644)

	cfg := LoadConfig(path)
	if cfg.Port != 8888 {
		t.Errorf("expected port 8888, got %d", cfg.Port)
	}
	if cfg.UnmaskEnabled() {
		t.Error("unmask=false should disable unmasking")
	}
	if cfg.CacheSize != 64 {
		t.Errorf("expected cache_size 64, got %d", cfg.CacheSize)
	}
	if cfg.VaultSize != 7 {
		t.Errorf("expected vault_size 7, got %d", cfg.VaultSize)
	}
	if cfg.PlaceholderModeValue() != "hash" {
		t.Errorf("expected hash placeholder mode, got %q", cfg.PlaceholderModeValue())
	}
	if cfg.LogFormatValue() != "json" {
		t.Errorf("expected json log format, got %q", cfg.LogFormatValue())
	}
	if cfg.SlogLevel() != slog.LevelDebug {
		t.Errorf("expected debug log level, got %v", cfg.SlogLevel())
	}
	if cfg.DefaultTarget != "https://fallback.example.com" {
		t.Error("default target not loaded")
	}
	if cfg.Routes["test"] != "https://test.example.com" {
		t.Error("route not loaded")
	}
	if len(cfg.Patterns) != 1 || cfg.Patterns[0].Label != "CUSTOM" {
		t.Error("custom pattern not loaded")
	}
}

func TestPatternEnabled(t *testing.T) {
	p := PatternEntry{Label: "test", Regex: "test"}
	if !p.IsEnabled() {
		t.Error("nil Enabled should mean true")
	}

	f := false
	p.Enabled = &f
	if p.IsEnabled() {
		t.Error("false Enabled should mean false")
	}
}

func TestGenerateDefaultConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.toml")
	err := GenerateDefaultConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	cfg := LoadConfig(path)
	if cfg.Port != 9900 {
		t.Error("generated config should have default port")
	}
	if _, ok := cfg.Routes["anthropic"]; !ok {
		t.Error("generated config should have anthropic route")
	}
	if cfg.Routes["codex"] != "https://chatgpt.com/backend-api/codex" {
		t.Error("generated config should have codex route")
	}
	if cfg.Routes["openai"] != "https://api.openai.com" {
		t.Error("generated config should have openai route")
	}
	if !cfg.UnmaskEnabled() {
		t.Error("generated config should enable unmask by default")
	}
	if cfg.VaultSize != 2048 {
		t.Error("generated config should default vault size to 2048")
	}
	if cfg.PlaceholderModeValue() != "preview" {
		t.Error("generated config should default to preview placeholder mode")
	}
	if cfg.LogFormatValue() != "pretty" {
		t.Error("generated config should default to pretty log format")
	}
}
