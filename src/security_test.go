package main

import (
	"net"
	"net/http"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustConfig(t *testing.T, yaml string) *Config {
	t.Helper()
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// ---------------------------------------------------------------------------
// Network guard
// ---------------------------------------------------------------------------

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", // cloud metadata
		"100.64.0.1", "0.0.0.0", "224.0.0.1", "240.0.0.1",
		"::1", "fc00::1", "fd12:3456::1", "fe80::1", "::",
		"::ffff:127.0.0.1",       // IPv4-mapped loopback
		"::ffff:169.254.169.254", // IPv4-mapped metadata
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test IP %q", s)
		}
		if !isBlockedIP(ip) {
			t.Errorf("isBlockedIP(%s) = false, want true", s)
		}
	}

	allowed := []string{
		"1.1.1.1", "8.8.8.8", "140.82.121.4", "172.32.0.1",
		"192.169.0.1", "2606:4700::1111",
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if isBlockedIP(ip) {
			t.Errorf("isBlockedIP(%s) = true, want false", s)
		}
	}

	if !isBlockedIP(nil) {
		t.Error("a nil IP must be treated as blocked")
	}
}

func TestConfigRejectsPrivateBaseURL(t *testing.T) {
	_, err := ParseConfig([]byte(`
server:
  public_url: "https://aegis.test"
users:
  - name: a
    password: pw
    targets:
      - id: internal
        description: internal service
        base_url: "http://192.168.1.10:8080"
`))
	if err == nil {
		t.Fatal("a base_url in a private range must be rejected at load time")
	}
	if !strings.Contains(err.Error(), "blocked network range") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Templates and injection
// ---------------------------------------------------------------------------

func TestCompileTemplate(t *testing.T) {
	secrets := map[string]string{"tok": "s3cr3t-value-long", "b": "second-value-x"}

	tpl, err := CompileTemplate("Bearer ${tok}", secrets)
	if err != nil {
		t.Fatal(err)
	}
	if got := tpl.Expand(secrets); got != "Bearer s3cr3t-value-long" {
		t.Errorf("expand = %q", got)
	}
	if len(tpl.Secrets) != 1 || tpl.Secrets[0] != "tok" {
		t.Errorf("secrets = %v", tpl.Secrets)
	}

	tpl, err = CompileTemplate("$${tok} is literal", secrets)
	if err != nil {
		t.Fatal(err)
	}
	if got := tpl.Expand(secrets); got != "${tok} is literal" {
		t.Errorf("escape failed: %q", got)
	}
	if len(tpl.Secrets) != 0 {
		t.Errorf("escaped reference must not count as a secret: %v", tpl.Secrets)
	}

	tpl, err = CompileTemplate("${tok}:${b}:${tok}", secrets)
	if err != nil {
		t.Fatal(err)
	}
	if got := tpl.Expand(secrets); got != "s3cr3t-value-long:second-value-x:s3cr3t-value-long" {
		t.Errorf("multi expand = %q", got)
	}
	if len(tpl.Secrets) != 2 {
		t.Errorf("want 2 distinct secrets, got %v", tpl.Secrets)
	}

	for _, bad := range []string{"${missing}", "${", "${}", "${bad name}"} {
		if _, err := CompileTemplate(bad, secrets); err == nil {
			t.Errorf("CompileTemplate(%q) should fail", bad)
		}
	}
}

func TestUndefinedSecretIsConfigError(t *testing.T) {
	_, err := ParseConfig([]byte(`
server:
  public_url: "https://aegis.test"
users:
  - name: a
    password: pw
    targets:
      - id: x
        description: x
        base_url: "https://api.example.com"
        inject:
          headers:
            Authorization: "Bearer ${nope}"
`))
	if err == nil || !strings.Contains(err.Error(), "undefined secret") {
		t.Fatalf("want undefined-secret error, got %v", err)
	}
}

func TestApplyInjection(t *testing.T) {
	cfg := mustConfig(t, `
server:
  public_url: "https://aegis.test"
users:
  - name: a
    password: pw
    secrets:
      tok: "token-value-1234"
      key: "apikey-value-5678"
    targets:
      - id: t
        description: t
        base_url: "https://api.example.com"
        methods: [GET, POST]
        inject:
          headers:
            Authorization: "Bearer ${tok}"
          query:
            appid: "${key}"
          body:
            "$.auth.token": "${tok}"
`)
	u := cfg.Users["a"]
	tgt := u.Targets[0]

	req, _ := http.NewRequest("POST", "https://api.example.com/x?appid=guess&keep=1", nil)
	req.Header.Set("Content-Type", "application/json")
	body := []byte(`{"hello":"world","auth":{"other":true}}`)

	out, err := applyInjection(req, body, tgt, u.Secrets)
	if err != nil {
		t.Fatal(err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer token-value-1234" {
		t.Errorf("header = %q", got)
	}
	if got := req.URL.Query().Get("appid"); got != "apikey-value-5678" {
		t.Errorf("injected query must overwrite the model's value, got %q", got)
	}
	if got := req.URL.Query().Get("keep"); got != "1" {
		t.Errorf("unrelated query parameter was lost")
	}
	if !strings.Contains(string(out), `"token":"token-value-1234"`) {
		t.Errorf("body injection missing: %s", out)
	}
	if !strings.Contains(string(out), `"other":true`) {
		t.Errorf("body injection destroyed sibling keys: %s", out)
	}
	if !strings.Contains(string(out), `"hello":"world"`) {
		t.Errorf("body injection destroyed unrelated keys: %s", out)
	}
}

func TestBodyInjectionRejectsNonJSON(t *testing.T) {
	cfg := mustConfig(t, `
server:
  public_url: "https://aegis.test"
users:
  - name: a
    password: pw
    secrets:
      tok: "token-value-1234"
    targets:
      - id: t
        description: t
        base_url: "https://api.example.com"
        methods: [POST]
        inject:
          body:
            "$.token": "${tok}"
`)
	u := cfg.Users["a"]
	req, _ := http.NewRequest("POST", "https://api.example.com/x", nil)
	req.Header.Set("Content-Type", "text/plain")

	if _, err := applyInjection(req, []byte("not json"), u.Targets[0], u.Secrets); err == nil {
		t.Fatal("body injection into a non-JSON body must fail")
	}
}

func TestCheckModelHeaders(t *testing.T) {
	cfg := mustConfig(t, `
server:
  public_url: "https://aegis.test"
users:
  - name: a
    password: pw
    secrets:
      tok: "token-value-1234"
    targets:
      - id: t
        description: t
        base_url: "https://api.example.com"
        inject:
          headers:
            X-Api-Key: "${tok}"
`)
	tgt := cfg.Users["a"].Targets[0]

	for _, h := range []string{"Authorization", "authorization", "Cookie", "Host", "X-Forwarded-For", "X-Real-IP"} {
		if _, err := checkModelHeaders(map[string]string{h: "x"}, tgt); err == nil {
			t.Errorf("header %q must be rejected", h)
		}
	}
	// A header the target injects is also off limits.
	if _, err := checkModelHeaders(map[string]string{"x-api-key": "guess"}, tgt); err == nil {
		t.Error("a target-injected header must be rejected")
	}
	// Header splitting.
	if _, err := checkModelHeaders(map[string]string{"X-Note": "a\r\nX-Evil: 1"}, tgt); err == nil {
		t.Error("a header value with CRLF must be rejected")
	}
	// Ordinary headers pass and are canonicalised.
	out, err := checkModelHeaders(map[string]string{"accept": "application/json"}, tgt)
	if err != nil {
		t.Fatal(err)
	}
	if out["Accept"] != "application/json" {
		t.Errorf("header not canonicalised: %v", out)
	}
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

func TestRedactor(t *testing.T) {
	r := NewRedactor(map[string]string{
		"tok":   "supersecret-token-value",
		"short": "abc",
		"pre":   "supersecret-token",
	})

	if len(r.Skipped) != 1 || r.Skipped[0] != "short" {
		t.Errorf("short secrets = %v, want [short]", r.Skipped)
	}

	body := []byte(`{"echo":"supersecret-token-value","again":"supersecret-token-value"}`)
	out, n := r.Bytes(body)
	if n != 2 {
		t.Errorf("replacements = %d, want 2", n)
	}
	if strings.Contains(string(out), "supersecret-token-value") {
		t.Fatalf("secret survived redaction: %s", out)
	}
	if !strings.Contains(string(out), "[REDACTED:tok]") {
		t.Errorf("longest match must win, got %s", out)
	}

	// The short secret is deliberately not redacted.
	out, _ = r.Bytes([]byte("value abc here"))
	if !strings.Contains(string(out), "abc") {
		t.Error("secrets below the minimum length must be left alone")
	}

	// Headers too.
	s, n := r.String("Bearer supersecret-token-value")
	if n != 1 || strings.Contains(s, "supersecret-token-value") {
		t.Errorf("header redaction failed: %q", s)
	}
}

func TestTruncateAfterRedaction(t *testing.T) {
	secret := "0123456789abcdefghij"
	r := NewRedactor(map[string]string{"s": secret})

	// The secret straddles the truncation boundary: redaction must run first.
	body := []byte(strings.Repeat("x", 95) + secret + strings.Repeat("y", 100))
	cleaned, n := r.Bytes(body)
	if n != 1 {
		t.Fatalf("expected one replacement, got %d", n)
	}
	out, truncated := truncateUTF8(cleaned, 100)
	if !truncated {
		t.Error("expected truncation")
	}
	if strings.Contains(string(out), secret) {
		t.Fatalf("secret survived: %s", out)
	}
	// A partial secret must not survive either.
	if strings.Contains(string(out), secret[:10]) {
		t.Fatalf("secret prefix survived: %s", out)
	}
}

func TestTruncateUTF8Boundary(t *testing.T) {
	b := []byte("aaaa" + "ä") // 'ä' is two bytes
	out, truncated := truncateUTF8(b, 5)
	if !truncated {
		t.Fatal("expected truncation")
	}
	if string(out) != "aaaa" {
		t.Errorf("cut mid-rune: %q", out)
	}
	if out, tr := truncateUTF8([]byte("abc"), 10); tr || string(out) != "abc" {
		t.Error("short input must pass through untouched")
	}
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func TestLimiter(t *testing.T) {
	r, err := ParseRate("3/m")
	if err != nil {
		t.Fatal(err)
	}
	l := NewLimiter(r)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow(); !ok {
			t.Fatalf("request %d should have been allowed", i+1)
		}
	}
	ok, wait := l.Allow()
	if ok {
		t.Fatal("the fourth request must be refused")
	}
	if wait <= 0 {
		t.Error("a refusal must report a retry delay")
	}

	var nilLimiter *Limiter
	if ok, _ := nilLimiter.Allow(); !ok {
		t.Error("a nil limiter means unlimited")
	}
}

func TestParseRate(t *testing.T) {
	for _, good := range []string{"1/s", "60/m", "1000/h"} {
		if _, err := ParseRate(good); err != nil {
			t.Errorf("ParseRate(%q): %v", good, err)
		}
	}
	for _, bad := range []string{"", "60", "60/d", "0/m", "-1/m", "x/m", "60/"} {
		if _, err := ParseRate(bad); err == nil {
			t.Errorf("ParseRate(%q) should fail", bad)
		}
	}
}
