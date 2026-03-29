package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const defaultMaxBody = 10 * 1024 * 1024

type Proxy struct {
	masker        *Masker
	routes        map[string]string
	defaultTarget string
	client        *http.Client
	maxBodySize   int64
}

func NewProxy(masker *Masker, routes map[string]string, defaultTarget string, maxBodySize int) *Proxy {
	mbs := int64(maxBodySize)
	if mbs <= 0 {
		mbs = defaultMaxBody
	}
	return &Proxy{
		masker:        masker,
		routes:        routes,
		defaultTarget: strings.TrimRight(defaultTarget, "/"),
		client:        &http.Client{Timeout: 5 * time.Minute},
		maxBodySize:   mbs,
	}
}

func (p *Proxy) resolveTarget(r *http.Request) (targetBase, path string, err error) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	slug := parts[0]
	if target, ok := p.routes[slug]; ok {
		rest := "/"
		if len(parts) > 1 {
			rest = "/" + parts[1]
		}
		return strings.TrimRight(target, "/"), rest, nil
	}
	if p.defaultTarget != "" {
		return p.defaultTarget, r.URL.Path, nil
	}
	return "", "", fmt.Errorf("no route for '/%s' — add to [routes] in config.toml", slug)
}

// shortHost strips scheme from URL for compact logging.
func shortHost(url string) string {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "wss://")
	url = strings.TrimPrefix(url, "ws://")
	return url
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		w.Write([]byte("ok"))
		return
	}

	targetBase, path, err := p.resolveTarget(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	query := ""
	if r.URL.RawQuery != "" {
		query = "?" + r.URL.RawQuery
	}
	targetURL := targetBase + path + query

	// WebSocket upgrade — raw TCP relay
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		p.proxyWebSocket(w, r, targetURL)
		return
	}

	// Regular HTTP
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.maxBodySize))
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	ct := r.Header.Get("Content-Type")
	vaultBefore := p.masker.VaultCount()
	maskedBody := p.masker.MaskBody(body, ct)
	vaultAfter := p.masker.VaultCount()
	newSecrets := vaultAfter - vaultBefore

	target := shortHost(targetBase) + path
	logRequest(r.Method, target, newSecrets, vaultAfter)

	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader(maskedBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	for key, vals := range r.Header {
		k := strings.ToLower(key)
		if k == "host" || k == "content-length" || k == "accept-encoding" {
			continue
		}
		for _, v := range vals {
			upReq.Header.Add(key, v)
		}
	}
	upReq.Header.Set("Accept-Encoding", "identity")

	resp, err := p.client.Do(upReq)
	if err != nil {
		slog.Error("upstream_error", "target", target, "err", err)
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, vals := range resp.Header {
		k := strings.ToLower(key)
		if k == "transfer-encoding" || k == "content-length" || k == "content-encoding" {
			continue
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}

	respCT := resp.Header.Get("Content-Type")

	if p.masker.VaultCount() == 0 {
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		logResponse(target, resp.StatusCode, "pass", false, 0)
		return
	}

	w.WriteHeader(resp.StatusCode)

	if strings.Contains(respCT, "text/event-stream") {
		logResponse(target, resp.StatusCode, "sse", true, 0)
		UnmaskSSE(resp.Body, w, p.masker)
	} else {
		respBody, _ := io.ReadAll(resp.Body)
		io.Copy(w, strings.NewReader(p.masker.UnmaskText(string(respBody))))
		logResponse(target, resp.StatusCode, "body", true, len(respBody))
	}
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin:       func(r *http.Request) bool { return true },
	EnableCompression: true,
}

func (p *Proxy) proxyWebSocket(w http.ResponseWriter, r *http.Request, targetURL string) {
	wsURL := strings.Replace(targetURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsStart := time.Now()

	logWSSession(wsURL)

	// Forward auth headers
	reqHeader := http.Header{}
	for key, vals := range r.Header {
		k := strings.ToLower(key)
		if k == "upgrade" || k == "connection" || k == "host" ||
			strings.HasPrefix(k, "sec-websocket") {
			continue
		}
		for _, v := range vals {
			reqHeader.Add(key, v)
		}
	}

	dialer := websocket.Dialer{
		EnableCompression: true,
		HandshakeTimeout:  30 * time.Second,
	}
	upstream, resp, err := dialer.Dial(wsURL, reqHeader)
	if err != nil {
		body := ""
		if resp != nil {
			b, _ := io.ReadAll(resp.Body)
			body = string(b[:min(200, len(b))])
			resp.Body.Close()
		}
		slog.Error("ws_dial_error", "target", shortHost(wsURL), "err", err, "body", body)
		http.Error(w, "websocket error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	client, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("ws_upgrade_error", "err", err)
		return
	}
	defer client.Close()

	done := make(chan struct{})
	wsMsgCount := 0

	// Client → Upstream (mask)
	go func() {
		defer close(done)
		for {
			msgType, msg, err := client.ReadMessage()
			if err != nil {
				return
			}
			if msgType == websocket.TextMessage {
				vaultBefore := p.masker.VaultCount()
				if masked, err := p.masker.MaskJSON(msg); err == nil && string(masked) != string(msg) {
					vaultAfter := p.masker.VaultCount()
					newSecrets := vaultAfter - vaultBefore
					msg = masked
					wsMsgCount++
					logWSMasked(wsMsgCount, newSecrets, vaultAfter)
				}
			}
			if err := upstream.WriteMessage(msgType, msg); err != nil {
				return
			}
		}
	}()

	// Upstream → Client (unmask)
	for {
		msgType, msg, err := upstream.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.TextMessage && p.masker.VaultCount() > 0 {
			msg = []byte(p.masker.UnmaskText(string(msg)))
		}
		if err := client.WriteMessage(msgType, msg); err != nil {
			break
		}
	}

	// Close client to unblock goroutine's ReadMessage
	client.Close()
	<-done
	logWSClose(time.Since(wsStart))
}
