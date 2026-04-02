---
name: secret-proxy-secrets
description: |
  Guide for working with secrets when operating behind a secretproxy instance.
  Use when: (1) The environment has ANTHROPIC_BASE_URL or api_base_url pointing
  to localhost:9900 (secretproxy), (2) The user mentions secretproxy, secret-proxy,
  or secret masking proxy, (3) You encounter [[LABEL:...]] placeholders in conversation
  context or tool output, (4) You need to handle, reference, or pass API keys, tokens,
  database URLs, or other credentials in code while behind the proxy.
---

# Working with Secrets Behind secretproxy

secretproxy is a local HTTP proxy that automatically masks secrets in prompts before
they reach the LLM API, and restores (unmasks) them in responses. When you operate
behind it, your behavior around secrets changes.

## How It Works (agent perspective)

```
You send prompt containing sk_live_abc123...
  -> proxy replaces it with [[STRIPE_ACCESS_TOKEN:sk_live_abc..._f9c1b2e4]]
  -> LLM sees only the placeholder
  -> LLM responds referencing [[STRIPE_ACCESS_TOKEN:sk_live_abc..._f9c1b2e4]]
  -> proxy restores the real value before you receive it
```

Masking is transparent. You see real secrets in tool output (file reads, shell
results). The proxy handles masking/unmasking without your intervention.

## Rules

1. **Never work around the proxy.** Do not base64-encode, split, hex-encode, or
   otherwise obfuscate secrets to bypass masking. The proxy exists to protect the user.

2. **Use secrets naturally.** Read files, run commands, write code that references
   credentials as-is. The proxy masks them on the way out and restores them on the
   way back.

3. **Do not store secrets in your responses.** If a user asks you to "remember"
   a key, decline. Secrets belong in `.env` files, vaults, or config -- not in
   conversation memory or CLAUDE.md.

4. **Placeholders are opaque.** If you see `[[LABEL:...]]` in conversation history
   (from a prior turn), treat it as a reference to a secret. Do not attempt to
   decode, guess, or reconstruct the original value from the placeholder.

5. **Expect masked context.** In multi-turn conversations, earlier messages may
   contain placeholders. This is normal. The proxy vault retains mappings for the
   session, so referencing the same secret produces the same placeholder.

## What Gets Masked

| Source | Masked? |
|---|---|
| User message content | Yes (auto) |
| Tool results you report back | Yes (auto) |
| File contents you read with tools | No (local, never sent raw) |
| Shell command output | No (local) |
| Your response text | Unmasked before delivery |
| HTTP headers / auth tokens | No (pass-through) |

## Placeholder Format

Two modes the user may configure:

- **preview**: `[[STRIPE_ACCESS_TOKEN:sk_live_4eC..._a3f9c1b2]]` -- label + truncated value
- **hash**: `[[STRIPE_ACCESS_TOKEN:a3f9c1b2]]` -- label + opaque hash

Both are functionally identical from your perspective.

## Practical Patterns

### Writing code that uses secrets

Reference env vars or config files. Never inline raw secrets:

```python
# Good
api_key = os.environ["STRIPE_SECRET_KEY"]

# Bad -- even though proxy would mask it, this is poor practice
api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
```

### Debugging with secrets

When a user shares a config file or env dump containing secrets, read and analyze
it normally. The proxy ensures the raw values never reach the upstream API. Focus
on the structure and correctness, not on redacting values yourself.

### When you see placeholders in tool_use arguments

If the LLM produces tool calls containing `[[LABEL:...]]` placeholders, the proxy
unmasks them before execution. The tool receives the real secret. No special
handling is needed.

## Detection Scope

222+ secret patterns (AWS, GCP, GitHub, Stripe, Slack, database URLs, generic
`sk-*` keys, etc.) and optionally PII (emails, phones, credit cards, IBANs,
private IPs). Custom patterns can be added via `~/.secretproxy/config.toml`.

## Limitations

- Headers, cookies, and query parameters are NOT scanned.
- Binary data (images, archives) is skipped.
- Secrets in screenshots or images are not detected.
- The proxy is local-only and single-user.
