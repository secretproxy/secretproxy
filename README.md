# secretproxy

[![CI](https://github.com/secretproxy/secretproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/secretproxy/secretproxy/actions/workflows/ci.yml)
[![Release](https://github.com/secretproxy/secretproxy/actions/workflows/release.yml/badge.svg)](https://github.com/secretproxy/secretproxy/actions/workflows/release.yml)
[![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/github/license/secretproxy/secretproxy)](LICENSE)

Local proxy that masks secrets in prompts before they reach the LLM API, and restores them in responses.

![demo](demo.gif)

## Install

```bash
brew install secretproxy/tap/secretproxy
```

Or download a binary from [GitHub Releases](https://github.com/secretproxy/secretproxy/releases).

## Run

```bash
secretproxy service install    # launchd (macOS) / systemd (Linux)
```

Starts automatically on login and restarts on failure.

## Configure

### Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://localhost:9900/anthropic"
  }
}
```

### Codex CLI

Add to `~/.codex/config.yaml`:

```yaml
api_base_url: http://localhost:9900/codex
```

---

## How it works

```
CLI tool ──HTTP──> secretproxy (:9900) ──HTTPS──> upstream API
                    │
                    ├─ Scans request body with regex patterns
                    ├─ Replaces matched values with [[LABEL:preview_hash]]
                    ├─ Forwards the masked request upstream
                    └─ Restores placeholders in the response (SSE, WebSocket, or JSON)
```

**Before** — prompt sent upstream:
```
"debug this config, the key is sk_live_4eC39HqLyjWDarjtT1zdp7dc"
```

**After** — prompt sent upstream:
```
"debug this config, the key is [[STRIPE_ACCESS_TOKEN:sk_live_4eC..._a3f9c1b2e4d5]]"
```

- 222 regex patterns from [gitleaks](https://github.com/gitleaks/gitleaks) (AWS, GCP, GitHub, Stripe, Slack, etc.)
- Optional PII detection (emails, phones, credit cards, IBANs) — regex-based, no external services
- SSE and WebSocket streams are unmasked on the fly
- Plain HTTP locally, HTTPS upstream. No TLS interception, no certificates

## Why

- Prevent raw secrets from leaving your machine in prompts
- Keep enough context for the model with readable placeholders
- Work with existing CLI tools by changing only the base URL
- Stay local and simple: no browser extension, no TLS MITM, no hosted service
- For typical CLI-sized requests, masking overhead is usually well under 1 ms

## What this is NOT

- Not a DLP system, compliance platform, or AI gateway
- Does not mask headers, cookies, or query parameters
- Does not protect against secrets in images or binary data
- Not designed for multi-user or org-wide deployment

## Commands

```bash
secretproxy                           # start proxy
secretproxy start                     # explicit start
secretproxy -port 8080 start          # custom port
secretproxy status                    # show port/config/runtime summary
secretproxy check "text"              # dry-run masking
secretproxy patterns update           # download latest gitleaks rules
secretproxy service install           # install launchd/systemd user service
```

## Configuration

`~/.secretproxy/config.toml`:

```toml
# Network
port = 9900
max_body_size = 10485760  # 10MB

# Masking
unmask = true               # false = one-way, no vault
placeholder_mode = "preview"  # preview, hash
cache_size = 2048
vault_size = 2048

# Logging
log_format = "pretty"       # pretty, json
log_level = "info"          # debug, info, warn, error

# Routing
[routes]
anthropic = "https://api.anthropic.com"
codex = "https://chatgpt.com/backend-api/codex"
openai = "https://api.openai.com"

# Privacy
[pii]
enabled = false

# Custom patterns
# [[patterns]]
# label = "OPENROUTER"
# regex = 'sk-or-v1-[a-zA-Z0-9]{32,}'
```

### Placeholders

Two modes:

- `preview` — `[[STRIPE_ACCESS_TOKEN:sk_live_4eC..._a3f9c1b2]]` — shows prefix for context
- `hash` — `[[STRIPE_ACCESS_TOKEN:a3f9c1b2]]` — opaque

### Routing

First path segment is the route slug:

```
/anthropic/v1/messages  → https://api.anthropic.com/v1/messages
/codex/responses        → https://chatgpt.com/backend-api/codex/responses
/openai/v1/chat         → https://api.openai.com/v1/chat
```

Add custom routes:

```toml
[routes]
myapi = "https://api.example.com"
```

Then use `http://localhost:9900/myapi` as the base URL.

### What gets scanned

| Content-Type | What happens |
|---|---|
| JSON with `messages[]` or `input[]` | User messages scanned, assistant messages skipped |
| JSON without those keys | Full body scanned as text |
| `text/*`, `xml`, `yaml`, `form-urlencoded` | Full body scanned |
| WebSocket text frames | JSON scan |
| Binary | Skipped |

Headers pass through unchanged.

## Other install methods

### go install

```bash
go install github.com/secretproxy/secretproxy/cmd/secretproxy@latest
```

## License

MIT
