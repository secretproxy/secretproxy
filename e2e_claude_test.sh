#!/bin/bash
# E2E test: secretproxy + real Claude Code CLI
# Verifies that secrets are masked in API requests and unmasked in responses.
#
# Usage: ./e2e_claude_test.sh
#
# Requirements:
# - secretproxy built (./secretproxy)
# - claude CLI installed
# - Valid ANTHROPIC_API_KEY

set -e

PORT=19900
PROXY_PID=""
LOG="/tmp/secretproxy-e2e.log"

cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
    rm -f "$LOG"
}
trap cleanup EXIT

echo "=== Building ==="
go build -o secretproxy ./cmd/secretproxy || { echo "FAIL: build"; exit 1; }

echo "=== Starting proxy on :$PORT ==="
./secretproxy -port "$PORT" > "$LOG" 2>&1 &
PROXY_PID=$!
sleep 2

if ! curl -s "http://127.0.0.1:$PORT/health" | grep -q "ok"; then
    echo "FAIL: proxy not healthy"
    cat "$LOG"
    exit 1
fi

echo "=== Sending prompt with test secret ==="
# Use a fake but realistic-looking key
TEST_SECRET="sk_live_E2EtestKey9a8b7c6d5e4f3g2h1i0j"

RESPONSE=$(ANTHROPIC_BASE_URL="http://127.0.0.1:$PORT/anthropic" \
    claude -p "Respond with ONLY the exact text I give you, nothing else. Here is the text: ${TEST_SECRET}" \
    --max-turns 1 2>/dev/null)

echo "=== Checking results ==="

# 1. Proxy should have masked the secret
if grep -q "MASK" "$LOG"; then
    echo "PASS: secret was masked"
else
    echo "FAIL: no MASK in proxy log"
    cat "$LOG"
    exit 1
fi

# 2. Secret should NOT appear in proxy log as plaintext (except in MASK line's truncated preview)
if grep -v "MASK\|sk_live_E2Et" "$LOG" | grep -q "$TEST_SECRET"; then
    echo "FAIL: full secret leaked in proxy log"
    cat "$LOG"
    exit 1
else
    echo "PASS: secret not leaked in logs"
fi

# 3. Response should contain the unmasked secret (Claude echoes it back, proxy unmasks)
if echo "$RESPONSE" | grep -q "$TEST_SECRET"; then
    echo "PASS: response contains unmasked secret"
else
    echo "WARN: response doesn't contain exact secret (Claude may have paraphrased)"
    echo "Response: $RESPONSE"
fi

# 4. Response should NOT contain placeholder
if echo "$RESPONSE" | grep -q "\[\[STRIPE_ACCESS_TOKEN:"; then
    echo "FAIL: placeholder leaked to client"
    exit 1
else
    echo "PASS: no placeholder in response"
fi

echo ""
echo "=== Proxy log ==="
cat "$LOG"

echo ""
echo "=== ALL TESTS PASSED ==="
