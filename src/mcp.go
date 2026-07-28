package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	mcpProtocolVersion = "2025-06-18"
	serverName         = "aegis"
)

// ---------------------------------------------------------------------------
// JSON-RPC
// ---------------------------------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

func rpcOK(id json.RawMessage, result any) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func rpcFail(id json.RawMessage, code int, msg string) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// ---------------------------------------------------------------------------
// MCP sessions
// ---------------------------------------------------------------------------

// mcpSessions binds an Mcp-Session-Id to the access token that created it.
type mcpSessions struct {
	mu   sync.Mutex
	byID map[string]string // session id -> token hash
	seen map[string]time.Time
}

func newMCPSessions() *mcpSessions {
	return &mcpSessions{byID: map[string]string{}, seen: map[string]time.Time{}}
}

func (m *mcpSessions) create(tokenHash string) string {
	id := randToken(16)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[id] = tokenHash
	m.seen[id] = time.Now()
	return id
}

func (m *mcpSessions) valid(id, tokenHash string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.byID[id]
	if !ok {
		return false
	}
	m.seen[id] = time.Now()
	return h == tokenHash
}

func (m *mcpSessions) drop(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, id)
	delete(m.seen, id)
}

func (m *mcpSessions) sweep() {
	cutoff := time.Now().Add(-24 * time.Hour)
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, t := range m.seen {
		if t.Before(cutoff) {
			delete(m.byID, id)
			delete(m.seen, id)
		}
	}
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()

	// DNS-rebinding protection: a browser-originated request must come from
	// our own origin.
	if origin := r.Header.Get("Origin"); origin != "" && !s.originAllowed(cfg, origin) {
		writeHTTPError(w, http.StatusForbidden, "origin not allowed")
		return
	}

	user, tokenHash, ok := s.authenticate(w, r, cfg)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodDelete:
		if id := r.Header.Get("Mcp-Session-Id"); id != "" {
			s.mcp.drop(id)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodGet:
		s.streamNotifications(w, r)
		return
	case http.MethodPost:
		// handled below
	default:
		writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	body, err := readLimited(r, 4<<20)
	if err != nil {
		writeRPC(w, "", rpcFail(nil, codeParseError, "request body too large or unreadable"))
		return
	}

	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		writeRPC(w, "", rpcFail(nil, codeInvalidRequest, "empty request"))
		return
	}

	// A batch is an array; a single call is an object.
	if trimmed[0] == '[' {
		var batch []rpcRequest
		if err := json.Unmarshal(body, &batch); err != nil {
			writeRPC(w, "", rpcFail(nil, codeParseError, "malformed JSON-RPC batch"))
			return
		}
		var out []*rpcResponse
		sessionID := ""
		for _, req := range batch {
			resp, sid := s.dispatch(r, req, user, tokenHash, cfg)
			if sid != "" {
				sessionID = sid
			}
			if resp != nil {
				out = append(out, resp)
			}
		}
		if len(out) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeRPCRaw(w, sessionID, out)
		return
	}

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPC(w, "", rpcFail(nil, codeParseError, "malformed JSON-RPC request"))
		return
	}
	resp, sessionID := s.dispatch(r, req, user, tokenHash, cfg)
	if resp == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeRPC(w, sessionID, resp)
}

func (s *Server) originAllowed(cfg *Config, origin string) bool {
	if strings.EqualFold(origin, cfg.Issuer()) {
		return true
	}
	lo := strings.ToLower(origin)
	return strings.HasPrefix(lo, "http://localhost") || strings.HasPrefix(lo, "http://127.0.0.1")
}

// authenticate resolves the bearer token to a user.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, cfg *Config) (*User, string, bool) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		s.challenge(w, cfg)
		return nil, "", false
	}
	raw := strings.TrimSpace(auth[len(prefix):])
	tok := s.sessions.LookupAccess(raw)
	if tok == nil {
		s.challenge(w, cfg)
		return nil, "", false
	}
	user, ok := cfg.Users[tok.User]
	if !ok {
		// The user was removed from the config; the token dies with it.
		s.challenge(w, cfg)
		return nil, "", false
	}
	return user, hashToken(raw), true
}

func (s *Server) challenge(w http.ResponseWriter, cfg *Config) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer resource_metadata=%q`, cfg.endpoint("/.well-known/oauth-protected-resource")))
	writeHTTPError(w, http.StatusUnauthorized, "authentication required")
}

// streamNotifications holds an SSE connection open. v1 only sends keep-alives.
func (s *Server) streamNotifications(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeHTTPError(w, http.StatusNotImplemented, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.stop:
			return
		case <-ticker.C:
			fmt.Fprint(w, ": keep-alive\n\n")
			flusher.Flush()
		}
	}
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

func (s *Server) dispatch(r *http.Request, req rpcRequest, user *User, tokenHash string, cfg *Config) (*rpcResponse, string) {
	isNotification := len(req.ID) == 0

	// Every method except initialize requires a valid session id, if one was
	// issued. A mismatch means the session belongs to a different token.
	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" && req.Method != "initialize" {
		if !s.mcp.valid(sid, tokenHash) {
			return rpcFail(req.ID, codeInvalidRequest, "unknown or mismatched session"), ""
		}
	}

	switch req.Method {
	case "initialize":
		sid := s.mcp.create(tokenHash)
		return rpcOK(req.ID, map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"serverInfo":      map[string]any{"name": serverName, "version": version},
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": true},
			},
			"instructions": "Aegis performs authenticated HTTP requests on your behalf. " +
				"Credentials are attached by the server; never include API keys or " +
				"Authorization headers yourself. Call list_targets first to see what is permitted.",
		}), sid

	case "notifications/initialized", "notifications/cancelled":
		return nil, ""

	case "ping":
		if isNotification {
			return nil, ""
		}
		return rpcOK(req.ID, map[string]any{}), ""

	case "tools/list":
		return rpcOK(req.ID, map[string]any{"tools": toolDefinitions()}), ""

	case "tools/call":
		return s.callTool(r, req, user, cfg), ""

	default:
		if isNotification {
			return nil, ""
		}
		return rpcFail(req.ID, codeMethodNotFound, "unknown method: "+req.Method), ""
	}
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

func writeRPC(w http.ResponseWriter, sessionID string, resp *rpcResponse) {
	writeRPCRaw(w, sessionID, resp)
}

func writeRPCRaw(w http.ResponseWriter, sessionID string, v any) {
	if sessionID != "" {
		w.Header().Set("Mcp-Session-Id", sessionID)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func readLimited(r *http.Request, limit int64) ([]byte, error) {
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("body too large")
	}
	return b, nil
}
