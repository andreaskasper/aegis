package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// oauthConf builds a config with a freshly generated bcrypt hash, so the test
// exercises the real hashing path rather than a pasted constant.
func oauthConf(t *testing.T) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("bcrypt-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return `
server:
  public_url: "https://aegis.test"
  code_ttl: "60s"
users:
  - name: andreas
    password: "hunter2hunter2"
  - name: hashed
    password: "bcrypt:` + string(h) + `"
`
}

func newOAuthServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	cfg := mustConfig(t, oauthConf(t))
	s := NewServer(cfg)
	prevOut := logOut
	logOut = &bytes.Buffer{}
	t.Cleanup(func() { logOut = prevOut })
	return s, s.routes()
}

func pkce() (verifier, challenge string) {
	verifier = randToken(48)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Discovery and registration
// ---------------------------------------------------------------------------

func TestDiscoveryDocuments(t *testing.T) {
	_, h := newOAuthServer(t)

	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-protected-resource",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !strings.Contains(rec.Body.String(), "https://aegis.test") {
			t.Errorf("%s: issuer missing: %s", path, rec.Body)
		}
	}
}

func TestDynamicClientRegistration(t *testing.T) {
	_, h := newOAuthServer(t)

	body := `{"client_name":"Claude","redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 201 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out["client_id"] == "" || out["client_id"] == nil {
		t.Error("no client_id issued")
	}

	bad := []string{
		`{"redirect_uris":[]}`,
		`{"redirect_uris":["not-a-uri"]}`,
		`{"redirect_uris":["http://evil.example.com/cb"]}`,
		`{"redirect_uris":["https://x.example.com/cb#frag"]}`,
		`{"redirect_uris":["https://x.example.com/cb"],"token_endpoint_auth_method":"client_secret_post"}`,
	}
	for _, b := range bad {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/register", strings.NewReader(b)))
		if rec.Code < 400 {
			t.Errorf("registration %s should have been rejected, got %d", b, rec.Code)
		}
	}

	// Loopback over http is the documented exception.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/register",
		strings.NewReader(`{"redirect_uris":["http://localhost:8765/cb"]}`)))
	if rec.Code != 201 {
		t.Errorf("loopback http redirect should be allowed, got %d: %s", rec.Code, rec.Body)
	}
}

// ---------------------------------------------------------------------------
// Full flow
// ---------------------------------------------------------------------------

func TestAuthorizationCodeFlow(t *testing.T) {
	s, h := newOAuthServer(t)
	redirect := "https://claude.ai/cb"
	c := s.sessions.RegisterClient("Claude", []string{redirect})
	verifier, challenge := pkce()

	// 1. Login form
	form := authorizeURL(c.ID, redirect, "st4te", challenge)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", form, nil))
	if rec.Code != 200 {
		t.Fatalf("login form: %d %s", rec.Code, rec.Body)
	}
	csrf := extractCSRF(t, rec.Body.String())

	// 2. Wrong password does not issue a code
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, postForm("/authorize", url.Values{
		"csrf": {csrf}, "client_id": {c.ID}, "redirect_uri": {redirect},
		"username": {"andreas"}, "password": {"wrong"},
	}))
	if rec.Code != 401 {
		t.Fatalf("wrong password: status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "Unknown user") {
		t.Error("the error must not distinguish unknown user from wrong password")
	}
	csrf = extractCSRF(t, rec.Body.String())

	// 3. Correct password redirects with a code
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, postForm("/authorize", url.Values{
		"csrf": {csrf}, "client_id": {c.ID}, "redirect_uri": {redirect},
		"username": {"andreas"}, "password": {"hunter2hunter2"},
	}))
	if rec.Code != 302 {
		t.Fatalf("login: status %d, body %s", rec.Code, rec.Body)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code in redirect")
	}
	if loc.Query().Get("state") != "st4te" {
		t.Error("state not echoed back")
	}

	// 4. Token exchange with a wrong verifier fails
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, postForm("/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {c.ID},
		"code_verifier": {randToken(48)},
	}))
	if rec.Code != 400 {
		t.Fatalf("PKCE mismatch should fail, got %d", rec.Code)
	}

	// 5. ...and the code is now burned, even for the correct verifier
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, postForm("/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {c.ID},
		"code_verifier": {verifier},
	}))
	if rec.Code != 400 {
		t.Error("a consumed code must not be reusable")
	}
}

func TestTokenExchangeAndRefreshRotation(t *testing.T) {
	s, h := newOAuthServer(t)
	redirect := "https://claude.ai/cb"
	c := s.sessions.RegisterClient("Claude", []string{redirect})
	verifier, challenge := pkce()

	code := s.sessions.NewCode("andreas", c.ID, redirect, challenge, time.Minute)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postForm("/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {c.ID}, "code_verifier": {verifier},
	}))
	if rec.Code != 200 {
		t.Fatalf("token exchange: %d %s", rec.Code, rec.Body)
	}
	var tok map[string]any
	json.Unmarshal(rec.Body.Bytes(), &tok)
	access := tok["access_token"].(string)
	refresh := tok["refresh_token"].(string)

	if s.sessions.LookupAccess(access) == nil {
		t.Fatal("access token not usable")
	}

	// Rotate.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, postForm("/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {c.ID},
	}))
	if rec.Code != 200 {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body)
	}
	var tok2 map[string]any
	json.Unmarshal(rec.Body.Bytes(), &tok2)
	access2 := tok2["access_token"].(string)

	// Reusing the rotated refresh token kills the family.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, postForm("/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {c.ID},
	}))
	if rec.Code != 400 {
		t.Error("a reused refresh token must be rejected")
	}
	if s.sessions.LookupAccess(access2) != nil {
		t.Error("refresh reuse must invalidate the whole token family")
	}
}

func TestAuthorizeRejectsUnknownClientAndRedirect(t *testing.T) {
	s, h := newOAuthServer(t)
	c := s.sessions.RegisterClient("Claude", []string{"https://claude.ai/cb"})
	_, challenge := pkce()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", authorizeURL("nope", "https://claude.ai/cb", "s", challenge), nil))
	if rec.Code != 400 {
		t.Errorf("unknown client should be a 400 page, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", authorizeURL(c.ID, "https://evil.example.com/cb", "s", challenge), nil))
	if rec.Code != 400 {
		t.Errorf("unregistered redirect_uri should be a 400 page, got %d", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Error("an unverified redirect_uri must never be redirected to")
	}
}

func TestAuthorizeRequiresPKCE(t *testing.T) {
	s, h := newOAuthServer(t)
	redirect := "https://claude.ai/cb"
	c := s.sessions.RegisterClient("Claude", []string{redirect})

	u := "/authorize?response_type=code&client_id=" + c.ID +
		"&redirect_uri=" + url.QueryEscape(redirect) + "&state=s"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", u, nil))
	if rec.Code != 302 {
		t.Fatalf("expected a redirect with an error, got %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("missing PKCE should be invalid_request, got %q", loc.Query().Get("error"))
	}
}

func TestBcryptPassword(t *testing.T) {
	cfg := mustConfig(t, oauthConf(t))
	u := cfg.Users["hashed"]
	if !u.PasswordIsHash {
		t.Fatal("bcrypt: prefix not recognised")
	}
	if !VerifyPassword(u, "bcrypt-password") {
		t.Error("correct password rejected")
	}
	if VerifyPassword(u, "wrong") {
		t.Error("wrong password accepted")
	}
	if VerifyPassword(nil, "anything") {
		t.Error("an unknown user must never authenticate")
	}
}

func TestMCPRequiresAuth(t *testing.T) {
	_, h := newOAuthServer(t)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)))
	if rec.Code != 401 {
		t.Fatalf("unauthenticated /mcp should be 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "resource_metadata") {
		t.Errorf("401 must point at the resource metadata: %q", rec.Header().Get("WWW-Authenticate"))
	}

	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Authorization", "Bearer nonsense")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Errorf("an invalid token should be 401, got %d", rec.Code)
	}
}

func TestMCPInitializeAndToolsList(t *testing.T) {
	s, h := newOAuthServer(t)
	access, _ := s.sessions.IssueTokens("andreas", "cid", "", time.Hour)

	rec := rpcCall(h, access, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if rec.Code != 200 {
		t.Fatalf("initialize: %d %s", rec.Code, rec.Body)
	}
	sid := rec.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("no session id issued")
	}

	rec = rpcCall(h, access, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if !strings.Contains(rec.Body.String(), "http_request") ||
		!strings.Contains(rec.Body.String(), "list_targets") {
		t.Errorf("tools/list incomplete: %s", rec.Body)
	}

	// A session id from a different token must not be accepted.
	other, _ := s.sessions.IssueTokens("andreas", "cid2", "", time.Hour)
	rec = rpcCall(h, other, sid, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	if !strings.Contains(rec.Body.String(), "mismatched session") {
		t.Errorf("session id must be bound to its token: %s", rec.Body)
	}

	// Unknown method.
	rec = rpcCall(h, access, sid, `{"jsonrpc":"2.0","id":4,"method":"nope"}`)
	if !strings.Contains(rec.Body.String(), "-32601") {
		t.Errorf("unknown method should be -32601: %s", rec.Body)
	}
}

func TestMCPRejectsForeignOrigin(t *testing.T) {
	s, h := newOAuthServer(t)
	access, _ := s.sessions.IssueTokens("andreas", "cid", "", time.Hour)

	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("a foreign Origin must be refused, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func authorizeURL(clientID, redirect, state, challenge string) string {
	v := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return "/authorize?" + v.Encode()
}

func postForm(path string, v url.Values) *http.Request {
	req := httptest.NewRequest("POST", path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func rpcCall(h http.Handler, token, sessionID, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func extractCSRF(t *testing.T, html string) string {
	t.Helper()
	const marker = `name="csrf" value="`
	i := strings.Index(html, marker)
	if i < 0 {
		t.Fatalf("no csrf token in form: %s", html)
	}
	rest := html[i+len(marker):]
	j := strings.Index(rest, `"`)
	return rest[:j]
}
