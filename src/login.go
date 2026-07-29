package main

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// dummyHash is compared against when the username is unknown, so that a
// wrong username and a wrong password cost the same. Without this, response
// timing enumerates valid usernames.
var dummyHash = []byte("$2a$12$C6UzMDM.H6dfI/f/IKcEe.7Ll2Nz9UhtLBW0Ap0hqUEP3IsWQ0eLW")

// VerifyPassword checks a candidate against a user, in constant time where it
// matters. A nil user still performs the work.
func VerifyPassword(u *User, candidate string) bool {
	if u == nil {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(candidate))
		return false
	}
	if u.PasswordIsHash {
		return bcrypt.CompareHashAndPassword(u.Password, []byte(candidate)) == nil
	}
	return constantTimeEqual(string(u.Password), candidate)
}

// ---------------------------------------------------------------------------
// Authorization endpoint
// ---------------------------------------------------------------------------

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.authorizeForm(w, r)
	case http.MethodPost:
		s.authorizeSubmit(w, r)
	default:
		writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) authorizeForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")

	// Client and redirect_uri are validated before anything is echoed back,
	// and failures here render a page rather than redirecting - redirecting
	// to an unverified URI is how open redirectors are built.
	c := s.sessions.Client(clientID)
	if c == nil {
		renderError(w, http.StatusBadRequest, "Unknown client. Register with this server before authorizing.")
		return
	}
	if redirectURI == "" || !c.AllowsRedirect(redirectURI) {
		renderError(w, http.StatusBadRequest, "The redirect URI does not match this client's registration.")
		return
	}
	if q.Get("response_type") != "code" {
		redirectWithError(w, r, redirectURI, q.Get("state"), "unsupported_response_type", "only response_type=code is supported")
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		redirectWithError(w, r, redirectURI, q.Get("state"), "invalid_request", "PKCE with S256 is required")
		return
	}

	csrf := s.sessions.NewCSRF(clientID, redirectURI, q.Get("state"), q.Get("code_challenge"))
	renderLogin(w, http.StatusOK, loginView{
		ClientName:  c.Name,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		CSRF:        csrf,
	})
}

func (s *Server) authorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderError(w, http.StatusBadRequest, "Malformed form submission.")
		return
	}
	clientID := r.PostForm.Get("client_id")
	redirectURI := r.PostForm.Get("redirect_uri")
	csrf := r.PostForm.Get("csrf")

	c := s.sessions.Client(clientID)
	if c == nil || !c.AllowsRedirect(redirectURI) {
		renderError(w, http.StatusBadRequest, "Unknown client or redirect URI.")
		return
	}

	entry, ok := s.sessions.ConsumeCSRF(csrf, clientID, redirectURI)
	if !ok {
		// A stale token means the form was submitted twice, or the client
		// restarted the flow behind the user's back. The PKCE challenge is
		// not ours to invent, so we cannot re-issue a usable form: say
		// plainly what happened and where to restart.
		logWarn("login_stale_form", map[string]any{"client_id": clientID, "ip": clientIP(r)})
		renderError(w, http.StatusBadRequest,
			"This login form is no longer valid - it was already used, or the client started a new "+
				"attempt. Close this window and trigger the connection from your client again.")
		return
	}

	ip := clientIP(r)
	if ok, _ := s.loginLimiter.Allow(ip); !ok {
		logWarn("login_failed", map[string]any{"reason": "rate_limited", "ip": ip})
		renderLogin(w, http.StatusTooManyRequests, loginView{
			ClientName:  c.Name,
			ClientID:    clientID,
			RedirectURI: redirectURI,
			CSRF:        s.sessions.NewCSRF(clientID, redirectURI, entry.state, entry.challenge),
			Error:       "Too many attempts. Try again shortly.",
		})
		return
	}

	cfg := s.Config()
	username := strings.TrimSpace(r.PostForm.Get("username"))
	password := r.PostForm.Get("password")
	user := cfg.Users[username]

	if !VerifyPassword(user, password) {
		logWarn("login_failed", map[string]any{"ip": ip, "client_id": clientID})
		renderLogin(w, http.StatusUnauthorized, loginView{
			ClientName:  c.Name,
			ClientID:    clientID,
			RedirectURI: redirectURI,
			CSRF:        s.sessions.NewCSRF(clientID, redirectURI, entry.state, entry.challenge),
			Error:       "Invalid username or password.",
		})
		return
	}

	code := s.sessions.NewCode(user.Name, clientID, redirectURI, entry.challenge, cfg.CodeTTL)
	logInfo("login_success", map[string]any{"user": user.Name, "client_id": clientID, "ip": ip})

	u, err := url.Parse(redirectURI)
	if err != nil {
		renderError(w, http.StatusBadRequest, "Invalid redirect URI.")
		return
	}
	q := u.Query()
	q.Set("code", code)
	if entry.state != "" {
		q.Set("state", entry.state)
	}
	u.RawQuery = q.Encode()

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		renderError(w, http.StatusBadRequest, "Invalid redirect URI.")
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

type loginView struct {
	ClientName  string
	ClientID    string
	RedirectURI string
	CSRF        string
	Error       string
	Nonce       string
}

// originOf reduces a redirect URI to its scheme and authority, which is what
// belongs in form-action.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// securityHeaders locks the page down. formAction is the origin the login form
// is allowed to end up at.
//
// This one is worth reading twice. form-action does not only constrain where a
// form posts to - browsers also apply it to the redirect that follows the
// submission. With a bare 'self' the POST to /authorize succeeds, aegis answers
// 302 to the client's callback, and the browser silently refuses to follow it:
// the user clicks Sign in and nothing happens at all. So the client's redirect
// origin has to be named here.
func securityHeaders(w http.ResponseWriter, nonce, formAction string) {
	action := "'self'"
	if formAction != "" {
		action += " " + formAction
	}
	csp := "default-src 'none'; img-src 'self'; " +
		"style-src 'nonce-" + nonce + "'; script-src 'nonce-" + nonce + "'; " +
		"form-action " + action + "; frame-ancestors 'none'; base-uri 'none'"

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", csp)
}

func renderLogin(w http.ResponseWriter, status int, v loginView) {
	v.Nonce = randToken(16)
	securityHeaders(w, v.Nonce, originOf(v.RedirectURI))
	w.WriteHeader(status)
	loginTemplate.Execute(w, v)
}

func renderError(w http.ResponseWriter, status int, msg string) {
	nonce := randToken(16)
	// No form on this page, so nothing may be submitted from it.
	securityHeaders(w, nonce, "")
	w.WriteHeader(status)
	errorTemplate.Execute(w, struct {
		Message string
		Nonce   string
	}{msg, nonce})
}

const pageCSS = `
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background:#f5f6f8; color:#16181d; padding:24px; }
.card { width:100%; max-width:380px; background:#fff; border:1px solid #e3e5e9;
  border-radius:12px; padding:32px; box-shadow:0 1px 3px rgba(0,0,0,.06); }
.mark { display:block; width:56px; height:56px; margin:0 auto 14px; border-radius:14px; }
h1 { margin:0 0 4px; font-size:20px; letter-spacing:-.01em; text-align:center; }
.sub { margin:0 0 24px; color:#6b7280; font-size:13px; text-align:center; }
label { display:block; font-size:13px; font-weight:500; margin:0 0 6px; }
input { width:100%; padding:10px 12px; margin:0 0 16px; border:1px solid #d4d7dd;
  border-radius:8px; font-size:15px; background:#fff; color:inherit; }
input:focus { outline:2px solid #2563eb; outline-offset:-1px; border-color:transparent; }
button { width:100%; padding:11px; border:0; border-radius:8px; background:#16181d;
  color:#fff; font-size:15px; font-weight:500; cursor:pointer;
  display:inline-flex; align-items:center; justify-content:center; gap:9px; }
button:hover { background:#2d3139; }
button[disabled] { opacity:.7; cursor:default; }
.spin { width:15px; height:15px; border:2px solid currentColor; border-right-color:transparent;
  border-radius:50%; animation:spin .7s linear infinite; }
@keyframes spin { to { transform:rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spin { animation-duration:2s; } }
.err { background:#fef2f2; border:1px solid #fecaca; color:#991b1b;
  padding:10px 12px; border-radius:8px; margin:0 0 20px; font-size:13px; text-align:center; }
.foot { margin:24px 0 0; padding-top:16px; border-top:1px solid #eceef1;
  color:#9aa0aa; font-size:12px; text-align:center; }
@media (prefers-color-scheme: dark) {
  body { background:#0e0f12; color:#e6e8eb; }
  .card { background:#17191d; border-color:#26282e; box-shadow:none; }
  input { background:#0e0f12; border-color:#33363d; }
  button { background:#e6e8eb; color:#0e0f12; }
  button:hover { background:#fff; }
  .err { background:#2a1416; border-color:#5c2226; color:#fca5a5; }
  .foot { border-color:#26282e; }
}
`

var loginTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in - aegis</title>
<link rel="icon" type="image/png" href="/favicon.png">
<style nonce="{{.Nonce}}">` + pageCSS + `</style></head>
<body><main class="card">
<img class="mark" src="/favicon.png" alt="" width="56" height="56">
<h1>aegis</h1>
<p class="sub">{{if .ClientName}}<strong>{{.ClientName}}</strong> is requesting access on your behalf.{{else}}Sign in to continue.{{end}}</p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post" action="/authorize" id="f">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="hidden" name="client_id" value="{{.ClientID}}">
  <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
  <label for="u">Username</label>
  <input id="u" name="username" autocomplete="username" autocapitalize="off"
         autocorrect="off" spellcheck="false" autofocus required>
  <label for="p">Password</label>
  <input id="p" name="password" type="password" autocomplete="current-password"
         enterkeyhint="go" required>
  <button type="submit" id="b">Sign in</button>
</form>
<p class="foot">Your credentials are never shared with the client.</p>
<script nonce="{{.Nonce}}">
(function () {
  var f = document.getElementById("f"), b = document.getElementById("b");
  f.addEventListener("submit", function () {
    // Disable on the next tick: the browser has collected the form data by
    // then, and a button disabled too early can cancel the submission.
    setTimeout(function () {
      b.disabled = true;
      b.textContent = "";
      var s = document.createElement("span");
      s.className = "spin";
      b.appendChild(s);
      b.appendChild(document.createTextNode("Signing in…"));
    }, 0);
  });
})();
</script>
</main></body></html>`))

var errorTemplate = template.Must(template.New("error").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Error - aegis</title>
<link rel="icon" type="image/png" href="/favicon.png">
<style nonce="{{.Nonce}}">` + pageCSS + `</style></head>
<body><main class="card">
<img class="mark" src="/favicon.png" alt="" width="56" height="56">
<h1>aegis</h1>
<p class="sub">Authorization could not continue.</p>
<div class="err">{{.Message}}</div>
</main></body></html>`))
