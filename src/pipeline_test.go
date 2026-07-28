package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

const (
	testSecret   = "sk-live-0123456789abcdefXYZ"
	testAPIKey   = "apikey-abcdefghijklmnop"
	testConfYAML = `
server:
  public_url: "https://aegis.test"
  max_response_bytes: 4096
users:
  - name: andreas
    password: "hunter2hunter2"
    secrets:
      tok: "sk-live-0123456789abcdefXYZ"
      key: "apikey-abcdefghijklmnop"
    targets:
      - id: api
        description: "Test API"
        base_url: "https://api.example.com"
        methods: [GET, POST]
        paths: ["/v1/**"]
        inject:
          headers:
            Authorization: "Bearer ${tok}"
          query:
            appid: "${key}"
      - id: readonly
        description: "Read-only API"
        base_url: "https://ro.example.com"
        methods: [GET]
        paths: ["/**"]
  - name: opener
    password: "pw-long-enough"
    allow_any: true
    secrets:
      other: "other-secret-value-1234"
`
)

// stubTransport captures the outgoing request and returns a canned response.
type stubTransport struct {
	seen     *http.Request
	seenBody []byte
	respond  func(r *http.Request) *http.Response
}

func (s *stubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.seen = r
	if r.Body != nil {
		s.seenBody, _ = io.ReadAll(r.Body)
	}
	if s.respond != nil {
		return s.respond(r), nil
	}
	return textResponse(200, "ok", nil), nil
}

func textResponse(status int, body string, headers map[string]string) *http.Response {
	h := http.Header{}
	h.Set("Content-Type", "text/plain")
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode: status,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

type harness struct {
	srv  *Server
	cfg  *Config
	stub *stubTransport
	logs *bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	cfg := mustConfig(t, testConfYAML)
	s := NewServer(cfg)
	stub := &stubTransport{}
	s.transport = stub
	h := &harness{srv: s, cfg: cfg, stub: stub, logs: &bytes.Buffer{}}

	// Bypass DNS: the pipeline's own guard is exercised in security_test.go.
	prevResolve := resolveGuard
	resolveGuard = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	prevOut := logOut
	logOut = h.logs
	t.Cleanup(func() {
		resolveGuard = prevResolve
		logOut = prevOut
	})
	return h
}

// call runs http_request for a user and returns the decoded result plus the
// raw JSON the model would see.
func (h *harness) call(t *testing.T, user string, args map[string]any) (map[string]any, string) {
	t.Helper()
	raw, _ := json.Marshal(args)
	u := h.cfg.Users[user]

	req, _ := http.NewRequest("POST", "https://aegis.test/mcp", nil)

	result, isErr := h.srv.httpRequestTool(req, raw, u, h.cfg)
	envelope := toolResult(result, isErr)
	text := envelope["content"].([]map[string]any)[0]["text"].(string)

	var decoded map[string]any
	json.Unmarshal([]byte(text), &decoded)
	return decoded, text
}

// ---------------------------------------------------------------------------
// Pipeline behaviour
// ---------------------------------------------------------------------------

func TestPipelineInjectsAndHidesSecret(t *testing.T) {
	h := newHarness(t)
	h.stub.respond = func(r *http.Request) *http.Response {
		return textResponse(200, "hello", nil)
	}

	res, text := h.call(t, "andreas", map[string]any{
		"url": "https://api.example.com/v1/things",
	})

	if got := res["status"]; got != float64(200) {
		t.Fatalf("status = %v, body = %s", got, text)
	}
	// The secret went out...
	if got := h.stub.seen.Header.Get("Authorization"); got != "Bearer "+testSecret {
		t.Errorf("outgoing Authorization = %q", got)
	}
	if got := h.stub.seen.URL.Query().Get("appid"); got != testAPIKey {
		t.Errorf("outgoing appid = %q", got)
	}
	// ...but never came back.
	assertNoSecret(t, text)
	assertNoSecret(t, h.logs.String())
	// The audit log records the names.
	if !strings.Contains(h.logs.String(), `"injected":["key","tok"]`) {
		t.Errorf("audit log should name the injected secrets: %s", h.logs.String())
	}
	// ...and masks the injected query parameter.
	if !strings.Contains(h.logs.String(), "appid=%5BREDACTED%5D") {
		t.Errorf("audit URL should mask the injected parameter: %s", h.logs.String())
	}
}

func TestPipelineRedactsReflectedSecret(t *testing.T) {
	h := newHarness(t)
	h.stub.respond = func(r *http.Request) *http.Response {
		// A debug endpoint that echoes the credential back, and an error
		// header that does the same. This is the case redaction exists for.
		return textResponse(401,
			`{"error":"bad token","token":"`+testSecret+`"}`,
			map[string]string{"X-Debug-Auth": "Bearer " + testSecret})
	}

	res, text := h.call(t, "andreas", map[string]any{
		"url": "https://api.example.com/v1/echo",
	})

	if res["status"] != float64(401) {
		t.Fatalf("upstream 401 should be reported as a result, got %v", res["status"])
	}
	assertNoSecret(t, text)
	if !strings.Contains(text, "[REDACTED:tok]") {
		t.Errorf("expected a redaction marker: %s", text)
	}
	headers := res["headers"].(map[string]any)
	if !strings.Contains(headers["x-debug-auth"].(string), "[REDACTED:tok]") {
		t.Errorf("header not redacted: %v", headers)
	}
}

func TestPipelineDropsSetCookie(t *testing.T) {
	h := newHarness(t)
	h.stub.respond = func(r *http.Request) *http.Response {
		return textResponse(200, "ok", map[string]string{"Set-Cookie": "session=abc; HttpOnly"})
	}
	res, _ := h.call(t, "andreas", map[string]any{"url": "https://api.example.com/v1/x"})
	headers := res["headers"].(map[string]any)
	if _, ok := headers["set-cookie"]; ok {
		t.Error("Set-Cookie must not reach the model")
	}
}

func TestPipelineTruncates(t *testing.T) {
	h := newHarness(t)
	h.stub.respond = func(r *http.Request) *http.Response {
		return textResponse(200, strings.Repeat("x", 10000), nil)
	}
	res, _ := h.call(t, "andreas", map[string]any{"url": "https://api.example.com/v1/big"})
	if res["truncated"] != true {
		t.Error("a response over the limit must be flagged as truncated")
	}
	if len(res["body"].(string)) > 4096 {
		t.Errorf("body not truncated: %d bytes", len(res["body"].(string)))
	}
}

func TestPipelineRefusals(t *testing.T) {
	cases := []struct {
		name string
		user string
		args map[string]any
		want string
	}{
		{"unmatched host", "andreas",
			map[string]any{"url": "https://evil.example.com/v1/x"}, "no_target"},
		{"unmatched path", "andreas",
			map[string]any{"url": "https://api.example.com/v2/x"}, "no_target"},
		{"method not allowed", "andreas",
			map[string]any{"url": "https://ro.example.com/x", "method": "DELETE"}, "method_not_allowed"},
		{"reserved header", "andreas",
			map[string]any{"url": "https://api.example.com/v1/x",
				"headers": map[string]any{"Authorization": "Bearer guess"}}, "reserved_header"},
		{"relative url", "andreas",
			map[string]any{"url": "/v1/x"}, "invalid_url"},
		{"traversal", "andreas",
			map[string]any{"url": "https://api.example.com/v1/../../etc"}, "invalid_url"},
		{"bad scheme", "andreas",
			map[string]any{"url": "file:///etc/passwd"}, "invalid_url"},
		{"credentials in url", "andreas",
			map[string]any{"url": "https://u:p@api.example.com/v1/x"}, "invalid_url"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			res, text := h.call(t, c.user, c.args)
			if res["error"] != c.want {
				t.Errorf("error = %v, want %q (%s)", res["error"], c.want, text)
			}
			assertNoSecret(t, text)
		})
	}
}

func TestAllowAnyStillBlocksPrivateNetworks(t *testing.T) {
	h := newHarness(t)
	// Restore the real guard for this one: the point is that allow_any does
	// not disable it.
	resolveGuard = resolveAndCheck

	res, text := h.call(t, "opener", map[string]any{"url": "http://169.254.169.254/latest/meta-data/"})
	if res["error"] != "blocked_network" {
		t.Errorf("allow_any must not reach cloud metadata: %s", text)
	}

	res, text = h.call(t, "opener", map[string]any{"url": "http://192.168.1.1/admin"})
	if res["error"] != "blocked_network" {
		t.Errorf("allow_any must not reach private ranges: %s", text)
	}
}

func TestAllowAnyInjectsNothing(t *testing.T) {
	h := newHarness(t)
	h.stub.respond = func(r *http.Request) *http.Response { return textResponse(200, "ok", nil) }

	res, _ := h.call(t, "opener", map[string]any{"url": "https://example.org/anything"})
	if res["error"] != nil {
		t.Fatalf("allow_any user should reach a public URL: %v", res["error"])
	}
	if h.stub.seen.Header.Get("Authorization") != "" {
		t.Error("no credentials may be attached outside a configured target")
	}
	if res["target"] != nil {
		t.Errorf("target should be null for an allow_any request, got %v", res["target"])
	}
}

func TestRateLimitRefusal(t *testing.T) {
	cfg := mustConfig(t, `
server:
  public_url: "https://aegis.test"
users:
  - name: a
    password: pw-long-enough
    targets:
      - id: t
        description: t
        base_url: "https://api.example.com"
        paths: ["/**"]
        rate_limit: "1/h"
`)
	s := NewServer(cfg)
	s.transport = &stubTransport{}

	prev := resolveGuard
	resolveGuard = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	prevOut := logOut
	logOut = &bytes.Buffer{}
	defer func() { resolveGuard = prev; logOut = prevOut }()

	req, _ := http.NewRequest("POST", "https://aegis.test/mcp", nil)
	args, _ := json.Marshal(map[string]any{"url": "https://api.example.com/x"})

	if _, isErr := s.httpRequestTool(req, args, cfg.Users["a"], cfg); isErr {
		t.Fatal("the first request should be allowed")
	}
	res, isErr := s.httpRequestTool(req, args, cfg.Users["a"], cfg)
	if !isErr {
		t.Fatal("the second request should be rate limited")
	}
	te := res.(toolError)
	if te.Error != "rate_limited" || te.RetryAfterMS <= 0 {
		t.Errorf("unexpected refusal: %+v", te)
	}
}

// ---------------------------------------------------------------------------
// list_targets
// ---------------------------------------------------------------------------

func TestListTargetsHidesSecrets(t *testing.T) {
	cfg := mustConfig(t, testConfYAML)
	out := listTargets(cfg.Users["andreas"])
	b, _ := json.Marshal(out)

	assertNoSecret(t, string(b))
	for _, forbidden := range []string{"inject", "Authorization", "tok", "appid"} {
		if strings.Contains(string(b), forbidden) {
			t.Errorf("list_targets leaks %q: %s", forbidden, b)
		}
	}
	if !strings.Contains(string(b), "Test API") {
		t.Errorf("descriptions should be present: %s", b)
	}
}

// ---------------------------------------------------------------------------
// The test that matters most
// ---------------------------------------------------------------------------

// TestNoSecretEverLeaks drives a broad matrix of inputs and upstream
// behaviours and asserts that no secret value appears in any tool result or
// log line. Everything else in this file checks a mechanism; this checks the
// promise.
func TestNoSecretEverLeaks(t *testing.T) {
	responses := []func(r *http.Request) *http.Response{
		func(r *http.Request) *http.Response { return textResponse(200, "clean", nil) },
		func(r *http.Request) *http.Response { return textResponse(200, testSecret, nil) },
		func(r *http.Request) *http.Response {
			return textResponse(500, "error: "+testSecret+" invalid", nil)
		},
		func(r *http.Request) *http.Response {
			return textResponse(200, "ok", map[string]string{"X-Echo": testSecret})
		},
		func(r *http.Request) *http.Response {
			// The whole request echoed back, the worst case.
			var b strings.Builder
			b.WriteString(r.URL.String())
			for k, v := range r.Header {
				b.WriteString(k + ": " + strings.Join(v, ",") + "\n")
			}
			return textResponse(200, b.String(), nil)
		},
		func(r *http.Request) *http.Response {
			return textResponse(200, strings.Repeat(testSecret, 500), nil)
		},
	}

	argSets := []map[string]any{
		{"url": "https://api.example.com/v1/x"},
		{"url": "https://api.example.com/v1/x", "method": "POST", "body": `{"a":1}`},
		{"url": "https://api.example.com/v1/x", "query": map[string]any{"appid": "guess"}},
		{"url": "https://api.example.com/v1/x", "headers": map[string]any{"Accept": "*/*"}},
		{"url": "https://api.example.com/v9/nope"},
		{"url": "https://nowhere.example.net/x"},
		{"url": "not a url"},
		{"url": "https://api.example.com/v1/x", "method": "TRACE"},
		{"url": "https://api.example.com/v1/x", "headers": map[string]any{"Authorization": "x"}},
	}

	for ri, respond := range responses {
		for ai, args := range argSets {
			h := newHarness(t)
			h.stub.respond = respond
			_, text := h.call(t, "andreas", args)
			assertNoSecret(t, text)
			assertNoSecret(t, h.logs.String())
			if t.Failed() {
				t.Fatalf("leak with response %d and args %d: %s", ri, ai, text)
			}
		}
	}
}

func assertNoSecret(t *testing.T, s string) {
	t.Helper()
	for name, v := range map[string]string{"tok": testSecret, "key": testAPIKey} {
		if strings.Contains(s, v) {
			t.Errorf("secret %q leaked into output: %s", name, s)
		}
	}
}
