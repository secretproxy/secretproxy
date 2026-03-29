package app

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestWSMaskUnmask verifies that secrets in WebSocket text messages
// are masked client→upstream and unmasked upstream→client.
func TestWSMaskUnmask(t *testing.T) {
	m := testMasker()
	secret := "sk_live_WSTestSecretKey1234567890ab"

	// Mock upstream WS server: receives masked message, echoes it back
	var receivedMsg string
	mockWS := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("mock upgrade error: %v", err)
			return
		}
		defer conn.Close()

		// Read one message
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		receivedMsg = string(msg)

		// Echo it back (simulates API response containing placeholder)
		conn.WriteMessage(websocket.TextMessage, msg)
	}))
	defer mockWS.Close()

	// Proxy with mock as upstream
	wsURL := "ws" + strings.TrimPrefix(mockWS.URL, "http")
	proxy := &Proxy{
		masker:      m,
		routes:      map[string]string{"api": wsURL},
		client:      &http.Client{Timeout: 5 * time.Second},
		maxBodySize: defaultMaxBody,
	}
	proxySrv := newTestServer(t, proxy)
	defer proxySrv.Close()

	// Connect client to proxy
	proxyWS := "ws" + strings.TrimPrefix(proxySrv.URL, "http") + "/api/test"
	client, _, err := websocket.DefaultDialer.Dial(proxyWS, nil)
	if err != nil {
		t.Fatalf("client dial error: %v", err)
	}
	defer client.Close()

	// Send message with secret
	msg := `{"type":"response.create","input":[{"content":"check key ` + secret + `"}]}`
	err = client.WriteMessage(websocket.TextMessage, []byte(msg))
	if err != nil {
		t.Fatalf("write error: %v", err)
	}

	// Read echoed response
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, resp, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	// Verify: upstream received masked message (no real secret)
	if strings.Contains(receivedMsg, secret) {
		t.Error("upstream should NOT see real secret")
	}
	if !strings.Contains(receivedMsg, "[[STRIPE_ACCESS_TOKEN:") {
		t.Errorf("upstream should see placeholder, got: %s", receivedMsg[:min(200, len(receivedMsg))])
	}

	// Verify: client receives unmasked response (real secret restored)
	respStr := string(resp)
	if !strings.Contains(respStr, secret) {
		t.Errorf("client should see real secret in response, got: %s", respStr[:min(200, len(respStr))])
	}
	if strings.Contains(respStr, "[[STRIPE_ACCESS_TOKEN:") {
		t.Error("client should NOT see placeholder")
	}
}

// TestWSBinaryPassthrough verifies binary messages pass through unchanged.
func TestWSBinaryPassthrough(t *testing.T) {
	m := testMasker()

	mockWS := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()
		msgType, msg, _ := conn.ReadMessage()
		conn.WriteMessage(msgType, msg)
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
		t.Fatal(err)
	}
	defer client.Close()

	// Send binary
	binary := []byte{0x00, 0x01, 0x02, 0xFF}
	client.WriteMessage(websocket.BinaryMessage, binary)

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	msgType, resp, err := client.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if msgType != websocket.BinaryMessage {
		t.Errorf("expected binary, got type %d", msgType)
	}
	if string(resp) != string(binary) {
		t.Error("binary should pass through unchanged")
	}
}
