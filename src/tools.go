package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

func toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name": "list_targets",
			"description": "List the HTTP targets you are permitted to reach through Aegis. " +
				"Call this before http_request to learn which hosts, paths and methods are available.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"additionalProperties": false,
			},
		},
		{
			"name": "http_request",
			"description": "Perform an HTTP request through Aegis. Credentials are added by the " +
				"server - never include API keys, tokens or Authorization headers yourself. " +
				"Only URLs matching a permitted target will be sent.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{
						"type":        "string",
						"description": "Absolute URL, including scheme and host.",
					},
					"method": map[string]any{
						"type":        "string",
						"enum":        []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
						"description": "HTTP method. Defaults to GET.",
					},
					"headers": map[string]any{
						"type":                 "object",
						"additionalProperties": map[string]any{"type": "string"},
						"description":          "Extra request headers. Authorization and other credential headers are rejected.",
					},
					"query": map[string]any{
						"type":                 "object",
						"additionalProperties": map[string]any{"type": "string"},
						"description":          "Query parameters merged into the URL.",
					},
					"body": map[string]any{
						"type":        "string",
						"description": "Raw request body.",
					},
				},
				"required":             []string{"url"},
				"additionalProperties": false,
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) callTool(r *http.Request, req rpcRequest, user *User, cfg *Config) *rpcResponse {
	var p toolCallParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return rpcFail(req.ID, codeInvalidParams, "malformed tool call parameters")
		}
	}
	switch p.Name {
	case "list_targets":
		return rpcOK(req.ID, toolResult(listTargets(user), false))
	case "http_request":
		result, isErr := s.httpRequestTool(r, p.Arguments, user, cfg)
		return rpcOK(req.ID, toolResult(result, isErr))
	default:
		return rpcFail(req.ID, codeInvalidParams, "unknown tool: "+p.Name)
	}
}

// toolResult wraps a payload in the MCP content envelope.
func toolResult(payload any, isError bool) map[string]any {
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		b = []byte(`{"error":"internal_error","message":"result could not be encoded"}`)
		isError = true
	}
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": string(b)}},
		"isError":           isError,
		"structuredContent": payload,
	}
}

// ---------------------------------------------------------------------------
// list_targets
// ---------------------------------------------------------------------------

type targetView struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	BaseURL     string   `json:"base_url"`
	Methods     []string `json:"methods"`
	Paths       []string `json:"paths"`
	RateLimit   string   `json:"rate_limit,omitempty"`
}

func listTargets(u *User) map[string]any {
	views := make([]targetView, 0, len(u.Targets))
	for _, t := range u.Targets {
		views = append(views, targetView{
			ID:          t.ID,
			Description: t.Description,
			BaseURL:     t.BaseURL.String(),
			Methods:     t.MethodList,
			Paths:       t.PathSources,
			RateLimit:   t.RateLimit.Source,
		})
	}
	out := map[string]any{
		"targets":   views,
		"allow_any": u.AllowAny,
	}
	if u.AllowAny {
		out["note"] = "This user may also request any other public URL. Private, loopback " +
			"and cloud metadata addresses remain blocked, and no credentials are attached " +
			"to requests outside the listed targets."
	}
	return out
}

// ---------------------------------------------------------------------------
// http_request
// ---------------------------------------------------------------------------

type httpRequestArgs struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Query   map[string]string `json:"query"`
	Body    string            `json:"body"`
}

// toolError is the shape returned to the model for an Aegis-side refusal.
type toolError struct {
	Error        string `json:"error"`
	Message      string `json:"message"`
	Status       int    `json:"status"`
	RetryAfterMS int64  `json:"retry_after_ms,omitempty"`
}

func fail(code, msg string, status int) (any, bool) {
	return toolError{Error: code, Message: msg, Status: status}, true
}

func (s *Server) httpRequestTool(r *http.Request, rawArgs json.RawMessage, user *User, cfg *Config) (any, bool) {
	start := time.Now()
	audit := AuditRecord{User: user.Name}
	defer func() {
		audit.DurationMS = time.Since(start).Milliseconds()
		audit.emit()
	}()

	var args httpRequestArgs
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			audit.Error = "invalid_url"
			return fail("invalid_url", "Malformed tool arguments.", http.StatusBadRequest)
		}
	}

	// --- 2. parse and normalise ---------------------------------------
	target := (*Target)(nil)
	u, err := normalizeURL(args.URL)
	if err != nil {
		audit.URL = "<invalid>"
		audit.Error = "invalid_url"
		return fail("invalid_url", err.Error()+".", http.StatusBadRequest)
	}
	method := strings.ToUpper(strings.TrimSpace(args.Method))
	if method == "" {
		method = "GET"
	}
	if !validMethods[method] {
		audit.Method, audit.URL = method, u.String()
		audit.Error = "invalid_url"
		return fail("invalid_url", "Unsupported HTTP method.", http.StatusBadRequest)
	}
	if err := mergeQuery(u, args.Query); err != nil {
		audit.Method, audit.URL = method, u.String()
		audit.Error = "invalid_url"
		return fail("invalid_url", err.Error()+".", http.StatusBadRequest)
	}
	audit.Method = method

	// --- 3. match target ----------------------------------------------
	target = MatchTarget(user, u)
	audit.URL = auditURL(u, target)
	if target == nil && !user.AllowAny {
		audit.Error = "no_target"
		return fail("no_target",
			"No permitted target matches this URL. Call list_targets to see what is available.",
			http.StatusForbidden)
	}
	if target != nil {
		audit.Target = target.ID
	}

	// --- 4. network guard ---------------------------------------------
	ctx, cancel := context.WithTimeout(r.Context(), target.timeout(cfg))
	defer cancel()
	if _, err := resolveGuard(ctx, u.Hostname()); err != nil {
		audit.Error = "blocked_network"
		return fail("blocked_network", "The destination address is not reachable through Aegis.",
			http.StatusForbidden)
	}

	// --- 5. rate limit -------------------------------------------------
	limiter := user.anyLimiter
	if target != nil {
		limiter = target.limiter
	}
	if ok, wait := limiter.Allow(); !ok {
		audit.Error = "rate_limited"
		return toolError{
			Error:        "rate_limited",
			Message:      "Rate limit for this target exceeded.",
			Status:       http.StatusTooManyRequests,
			RetryAfterMS: wait.Milliseconds(),
		}, true
	}

	// --- 6. method check ------------------------------------------------
	if target != nil && !target.Methods[method] {
		audit.Error = "method_not_allowed"
		return fail("method_not_allowed",
			fmt.Sprintf("Target %q allows only %s.", target.ID, strings.Join(target.MethodList, ", ")),
			http.StatusForbidden)
	}

	// --- 7. header check ------------------------------------------------
	headers, err := checkModelHeaders(args.Headers, target)
	if err != nil {
		audit.Error = "reserved_header"
		return fail("reserved_header", err.Error()+".", http.StatusBadRequest)
	}

	// --- 8. body size ---------------------------------------------------
	body := []byte(args.Body)
	if int64(len(body)) > maxRequestBodyBytes {
		audit.Error = "request_too_large"
		return fail("request_too_large", "The request body exceeds 1 MiB.", http.StatusRequestEntityTooLarge)
	}

	// --- 9. build and inject --------------------------------------------
	httpReq, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		audit.Error = "invalid_url"
		return fail("invalid_url", "The request could not be constructed.", http.StatusBadRequest)
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	if len(body) > 0 && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	httpReq.Header.Set("User-Agent", "aegis/"+version)

	body, err = applyInjection(httpReq, body, target, user.Secrets)
	if err != nil {
		audit.Error = "body_injection_failed"
		return fail("body_injection_failed", err.Error()+".", http.StatusBadRequest)
	}
	if len(body) > 0 {
		httpReq.Body = io.NopCloser(bytes.NewReader(body))
		httpReq.ContentLength = int64(len(body))
		httpReq.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	if target != nil {
		audit.Injected = target.SecretNames
	}
	// Recompute the audited URL now that injection has run: injected query
	// parameters only exist at this point, and they must be masked.
	audit.URL = auditURL(httpReq.URL, target)

	// --- 10. send --------------------------------------------------------
	client := s.httpClient(target, user, cfg)
	resp, err := client.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			audit.Error = "upstream_timeout"
			return fail("upstream_timeout", "The upstream server did not respond in time.",
				http.StatusGatewayTimeout)
		}
		if strings.Contains(err.Error(), "blocked range") {
			audit.Error = "blocked_network"
			return fail("blocked_network", "The destination address is not reachable through Aegis.",
				http.StatusForbidden)
		}
		if strings.Contains(err.Error(), errRedirectOutOfScope) {
			audit.Error = "redirect_out_of_scope"
			return fail("redirect_out_of_scope", "The upstream redirected outside the permitted target.",
				http.StatusForbidden)
		}
		audit.Error = "upstream_error"
		return fail("upstream_error", "The upstream server could not be reached.", http.StatusBadGateway)
	}
	defer resp.Body.Close()

	limit := target.responseLimit(cfg)
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if readErr != nil && len(raw) == 0 {
		audit.Error = "upstream_error"
		return fail("upstream_error", "The response could not be read.", http.StatusBadGateway)
	}
	originalLen := len(raw)

	// --- 11. redact ------------------------------------------------------
	cleaned, nRedacted := user.redactor.Bytes(raw)

	// --- 12. truncate ----------------------------------------------------
	cleaned, truncated := truncateUTF8(cleaned, limit)

	// --- 13. headers -----------------------------------------------------
	outHeaders := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		if droppedResponseHeaders[k] {
			continue
		}
		v, n := user.redactor.String(strings.Join(vs, ", "))
		nRedacted += n
		outHeaders[strings.ToLower(k)] = v
	}

	audit.Status = resp.StatusCode
	audit.Bytes = originalLen
	audit.Truncated = truncated
	audit.Redacted = nRedacted

	out := map[string]any{
		"status":      resp.StatusCode,
		"headers":     outHeaders,
		"body":        string(cleaned),
		"truncated":   truncated,
		"duration_ms": time.Since(start).Milliseconds(),
	}
	if target != nil {
		out["target"] = target.ID
	} else {
		out["target"] = nil
	}
	return out, false
}

// ---------------------------------------------------------------------------
// Outbound client
// ---------------------------------------------------------------------------

const errRedirectOutOfScope = "aegis: redirect out of scope"

func (s *Server) httpClient(t *Target, u *User, cfg *Config) *http.Client {
	timeout := t.timeout(cfg)
	return &http.Client{
		Timeout:   timeout,
		Transport: s.transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if t == nil || !t.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			// Every hop is re-checked: a redirect is an untrusted URL.
			nu, err := normalizeURL(req.URL.String())
			if err != nil {
				return errors.New(errRedirectOutOfScope)
			}
			if MatchTarget(u, nu) != t {
				return errors.New(errRedirectOutOfScope)
			}
			return nil
		},
	}
}
