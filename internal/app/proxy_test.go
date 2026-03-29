package app

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func testProxy() (*Proxy, *Masker) {
	m := testMasker()
	p := &Proxy{
		masker:      m,
		routes:      map[string]string{},
		client:      &http.Client{Timeout: 5 * time.Second},
		maxBodySize: defaultMaxBody,
	}
	return p, m
}

func testProxyNoUnmask() (*Proxy, *Masker) {
	m := testMaskerNoUnmask()
	p := &Proxy{
		masker:      m,
		routes:      map[string]string{},
		client:      &http.Client{Timeout: 5 * time.Second},
		maxBodySize: defaultMaxBody,
	}
	return p, m
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestHealthEndpoint(t *testing.T) {
	p, _ := testProxy()
	srv := newTestServer(t, p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("expected 'ok', got %q", body)
	}
}

func TestRouting(t *testing.T) {
	// Mock upstream
	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path})
	}))
	defer upstream.Close()

	m := testMasker()
	p := &Proxy{
		masker:      m,
		routes:      map[string]string{"api": upstream.URL},
		client:      &http.Client{Timeout: 5 * time.Second},
		maxBodySize: defaultMaxBody,
	}
	srv := newTestServer(t, p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["path"] != "/v1/test" {
		t.Errorf("expected /v1/test, got %s", result["path"])
	}
}

func TestRoutingUnknownSlug(t *testing.T) {
	p, _ := testProxy()
	srv := newTestServer(t, p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/unknown/path")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", resp.StatusCode)
	}
}

func TestRoutingDefaultTarget(t *testing.T) {
	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path})
	}))
	defer upstream.Close()

	m := testMasker()
	p := &Proxy{
		masker:        m,
		routes:        map[string]string{},
		defaultTarget: upstream.URL,
		client:        &http.Client{Timeout: 5 * time.Second},
		maxBodySize:   defaultMaxBody,
	}
	srv := newTestServer(t, p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/unknown/path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["path"] != "/unknown/path" {
		t.Errorf("expected fallback path to be preserved, got %s", result["path"])
	}
}

func TestRejectsOversizedRequestBody(t *testing.T) {
	upstreamCalled := false
	p := &Proxy{
		masker: testMasker(),
		routes: map[string]string{"api": "https://example.com"},
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamCalled = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		})},
		maxBodySize: 8,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/messages", strings.NewReader("123456789"))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()

	p.ServeHTTP(rr, req)

	if upstreamCalled {
		t.Fatal("upstream should not be called for oversized bodies")
	}
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "request body too large") {
		t.Fatalf("expected error message about oversized body, got %q", rr.Body.String())
	}
}

func TestMaskingInProxy(t *testing.T) {
	var receivedBody string
	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	m := testMasker()
	p := &Proxy{
		masker:      m,
		routes:      map[string]string{"api": upstream.URL},
		client:      &http.Client{Timeout: 5 * time.Second},
		maxBodySize: defaultMaxBody,
	}
	srv := newTestServer(t, p)
	defer srv.Close()

	reqBody := `{"messages":[{"role":"user","content":"key sk_live_abcdef1234567890ab"}]}`
	resp, err := http.Post(srv.URL+"/api/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if strings.Contains(receivedBody, "sk_live_abcdef1234567890ab") {
		t.Error("full secret should be masked before reaching upstream")
	}
	if !strings.Contains(receivedBody, "[[STRIPE_ACCESS_TOKEN:") {
		t.Error("placeholder should be in upstream body")
	}
}

func TestSSEStreaming(t *testing.T) {
	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)

		events := []string{
			`event: message_start` + "\n" + `data: {"type":"message_start"}` + "\n\n",
			`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello "}}` + "\n\n",
			`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"world"}}` + "\n\n",
			`event: message_stop` + "\n" + `data: {"type":"message_stop"}` + "\n\n",
		}
		for _, e := range events {
			fmt.Fprint(w, e)
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	m := testMasker()
	p := &Proxy{
		masker:      m,
		routes:      map[string]string{"api": upstream.URL},
		client:      &http.Client{Timeout: 5 * time.Second},
		maxBodySize: defaultMaxBody,
	}
	srv := newTestServer(t, p)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/messages", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/event-stream") {
		t.Errorf("expected SSE content-type, got %s", ct)
	}

	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	if !strings.Contains(text, "message_start") {
		t.Error("missing message_start event")
	}
	if !strings.Contains(text, "hello") {
		t.Error("missing text content")
	}
	if !strings.Contains(text, "message_stop") {
		t.Error("missing message_stop event")
	}
}

func TestSSEUnmasking(t *testing.T) {
	// First mask a secret so it's in the vault
	m := testMasker()
	masked := m.MaskText("sk_live_abcdef1234567890ab")
	placeholder := masked // e.g. [[STRIPE_ACCESS_TOKEN:sk_live_abcd..._hash]]

	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Upstream echoes the placeholder (as a real API would)
		data := fmt.Sprintf(`{"type":"content_block_delta","delta":{"type":"text_delta","text":"%s"}}`, placeholder)
		fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", data)
	}))
	defer upstream.Close()

	p := &Proxy{
		masker:      m,
		routes:      map[string]string{"api": upstream.URL},
		client:      &http.Client{Timeout: 5 * time.Second},
		maxBodySize: defaultMaxBody,
	}
	srv := newTestServer(t, p)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/messages", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "sk_live_abcdef1234567890ab") {
		t.Error("placeholder should be unmasked back to original in SSE response")
	}
}

func TestSSEUnmaskSplitPlaceholder(t *testing.T) {
	// Mask a secret to populate vault
	m := testMasker()
	masked := m.MaskText("sk_live_abcdef1234567890ab")
	// masked is like [[STRIPE_ACCESS_TOKEN:sk_live_abcd..._1727f1911a7b3259]]

	// Split placeholder across multiple SSE chunks (simulates input_json_delta)
	mid := len(masked) / 2
	part1 := masked[:mid]
	part2 := masked[mid:]

	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)

		// content_block_start for tool_use
		fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"bash\"}}\n\n")
		flusher.Flush()

		// Chunk 1: first half of placeholder
		fmt.Fprintf(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"Bearer %s\"}}\n\n", part1)
		flusher.Flush()
		time.Sleep(10 * time.Millisecond)

		// Chunk 2: second half of placeholder
		fmt.Fprintf(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"%s end\"}}\n\n", part2)
		flusher.Flush()
		time.Sleep(10 * time.Millisecond)

		// content_block_stop
		fmt.Fprint(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
		flusher.Flush()

		// message_stop
		fmt.Fprint(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	p := &Proxy{
		masker:      m,
		routes:      map[string]string{"api": upstream.URL},
		client:      &http.Client{Timeout: 5 * time.Second},
		maxBodySize: defaultMaxBody,
	}
	srv := newTestServer(t, p)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/messages", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	if !strings.Contains(text, "sk_live_abcdef1234567890ab") {
		t.Errorf("split placeholder should be unmasked.\nGot: %s", text)
	}
	if strings.Contains(text, "[[STRIPE_ACCESS_TOKEN:") {
		t.Error("placeholder should not remain in output")
	}
}

func TestHeadersPassthrough(t *testing.T) {
	var gotHeaders http.Header
	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	m := testMasker()
	p := &Proxy{
		masker:      m,
		routes:      map[string]string{"api": upstream.URL},
		client:      &http.Client{Timeout: 5 * time.Second},
		maxBodySize: defaultMaxBody,
	}
	srv := newTestServer(t, p)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/test", strings.NewReader("{}"))
	req.Header.Set("X-Api-Key", "sk-ant-test-123")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("Accept-Encoding", "gzip")
	http.DefaultClient.Do(req)

	if gotHeaders.Get("X-Api-Key") != "sk-ant-test-123" {
		t.Error("x-api-key should pass through")
	}
	if gotHeaders.Get("Anthropic-Version") != "2023-06-01" {
		t.Error("anthropic-version should pass through")
	}
	if ae := gotHeaders.Get("Accept-Encoding"); ae != "identity" {
		t.Errorf("accept-encoding should be 'identity', got %q", ae)
	}
}

func TestProxyNoUnmaskModeHTTP(t *testing.T) {
	var receivedBody string
	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"text":"sk_live_abcdef1234567890ab"}`)
	}))
	defer upstream.Close()

	p, _ := testProxyNoUnmask()
	p.routes = map[string]string{"api": upstream.URL}
	srv := newTestServer(t, p)
	defer srv.Close()

	reqBody := `{"messages":[{"role":"user","content":"key sk_live_abcdef1234567890ab"}]}`
	resp, err := http.Post(srv.URL+"/api/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	if strings.Contains(receivedBody, "sk_live_abcdef1234567890ab") {
		t.Error("upstream should not receive the real secret")
	}
	if !strings.Contains(receivedBody, "[[STRIPE_ACCESS_TOKEN:") {
		t.Error("upstream should receive placeholder")
	}
	if !strings.Contains(text, "sk_live_abcdef1234567890ab") {
		t.Errorf("client should receive upstream response unchanged, got: %s", text)
	}
}

func TestWSNoUnmaskMode(t *testing.T) {
	m := testMaskerNoUnmask()
	secret := "sk_live_WSTestSecretKey1234567890ab"

	var receivedMsg string
	mockWS := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("mock upgrade error: %v", err)
			return
		}
		defer conn.Close()

		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		receivedMsg = string(msg)
		conn.WriteMessage(websocket.TextMessage, msg)
	}))
	defer mockWS.Close()

	wsURL := "ws" + strings.TrimPrefix(mockWS.URL, "http")
	proxy := &Proxy{
		masker:      m,
		routes:      map[string]string{"api": wsURL},
		client:      &http.Client{Timeout: 5 * time.Second},
		maxBodySize: defaultMaxBody,
	}
	proxySrv := newTestServer(t, proxy)
	defer proxySrv.Close()

	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(proxySrv.URL, "http")+"/api/test", nil)
	if err != nil {
		t.Fatalf("client dial error: %v", err)
	}
	defer client.Close()

	msg := `{"type":"response.create","input":[{"content":"check key ` + secret + `"}]}`
	if err := client.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
		t.Fatalf("write error: %v", err)
	}

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, resp, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	if strings.Contains(receivedMsg, secret) {
		t.Error("upstream should not see the real secret")
	}
	if !strings.Contains(receivedMsg, "[[STRIPE_ACCESS_TOKEN:") {
		t.Errorf("upstream should see placeholder, got: %s", receivedMsg[:min(200, len(receivedMsg))])
	}
	if !strings.Contains(string(resp), "[[STRIPE_ACCESS_TOKEN:") {
		t.Errorf("client should receive placeholder unchanged, got: %s", string(resp))
	}
	if strings.Contains(string(resp), secret) {
		t.Error("client should not see the real secret in no-unmask mode")
	}
}
