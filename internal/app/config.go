package app

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

var tomlDecode = toml.Decode

type Config struct {
	Port            int               `toml:"port"`
	CacheSize       int               `toml:"cache_size"`
	VaultSize       int               `toml:"vault_size"`
	MaxBodySize     int               `toml:"max_body_size"`
	Unmask          *bool             `toml:"unmask"`     // nil/true = unmask responses, false = one-way mask
	LogFormat       string            `toml:"log_format"` // pretty, json (default: pretty)
	LogLevel        string            `toml:"log_level"`  // debug, info, warn, error (default: info)
	PlaceholderMode string            `toml:"placeholder_mode"`
	DefaultTarget   string            `toml:"default_target"`
	Routes          map[string]string `toml:"routes"`
	PII             PiiConfig         `toml:"pii"`
	Patterns        []PatternEntry    `toml:"patterns"`
}

type PiiConfig struct {
	Enabled bool `toml:"enabled"`
}

type PatternEntry struct {
	Label   string `toml:"label"`
	Regex   string `toml:"regex"`
	Enabled *bool  `toml:"enabled"`
}

func (p PatternEntry) IsEnabled() bool {
	return p.Enabled == nil || *p.Enabled
}

func (c Config) UnmaskEnabled() bool {
	return c.Unmask == nil || *c.Unmask
}

func (c Config) SlogLevel() slog.Level {
	switch c.LogLevelValue() {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func (c Config) LogLevelValue() string {
	switch c.LogLevel {
	case "", "info":
		return "info"
	case "debug", "warn", "error":
		return c.LogLevel
	default:
		slog.Warn("config_warning", "field", "log_level", "level", c.LogLevel, "fallback", "info")
		return "info"
	}
}

func (c Config) LogFormatValue() string {
	switch c.LogFormat {
	case "", "pretty":
		return "pretty"
	case "json":
		return "json"
	default:
		slog.Warn("config_warning", "field", "log_format", "format", c.LogFormat, "fallback", "pretty")
		return "pretty"
	}
}

func (c Config) PlaceholderModeValue() string {
	switch c.PlaceholderMode {
	case "", "preview":
		return "preview"
	case "hash":
		return "hash"
	default:
		slog.Warn("config_warning", "field", "placeholder_mode", "mode", c.PlaceholderMode, "fallback", "preview")
		return "preview"
	}
}

func DefaultConfig() Config {
	return Config{
		Port:      9900,
		CacheSize: 2048,
		VaultSize: 2048,
		Routes: map[string]string{
			"anthropic": "https://api.anthropic.com",
			"codex":     "https://chatgpt.com/backend-api/codex",
			"openai":    "https://api.openai.com",
		},
		PII: PiiConfig{
			Enabled: false,
		},
	}
}

func LoadConfig(path string) Config {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		slog.Error("config_parse_error", "err", err)
	}
	return cfg
}

func ConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secretproxy", "config.toml")
}

func GenerateDefaultConfig(path string) error {
	content := `# secretproxy configuration

# Network
port = 9900
max_body_size = 10485760  # 10MB

# Masking
unmask = true               # false = one-way masking, no vault, no memory
placeholder_mode = "preview"  # preview, hash
cache_size = 2048
vault_size = 2048           # placeholder->secret retention for unmask=true

# Logging
log_format = "pretty"       # pretty, json
log_level = "info"          # debug, info, warn, error — debug shows each masked secret

# Routing
# Optional fallback when no /slug route matches.
# default_target = "https://api.openai.com"

[routes]
anthropic = "https://api.anthropic.com"
codex = "https://chatgpt.com/backend-api/codex"
openai = "https://api.openai.com"

# Privacy
[pii]
# Built-in lightweight regex-based PII detection.
# Detects emails, phones, credit cards, IBANs, private IPs, GPS, and internal URLs.
# No external services. Not a compliance or DLP engine.
enabled = false

# Custom regex patterns (in addition to gitleaks built-in 222 patterns).
#
# [[patterns]]
# label = "OPENROUTER"
# regex = 'sk-or-v1-[a-zA-Z0-9]{32,}'
#
# [[patterns]]
# label = "MY_INTERNAL_TOKEN"
# regex = 'myapp_[a-zA-Z0-9]{32}'
#
# [[patterns]]
# label = "DB_URL"
# regex = '(?:postgres|mysql|mongodb(?:\+srv)?|redis)://[^\s:]+:[^\s@]+@[^\s]+'
`
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}
