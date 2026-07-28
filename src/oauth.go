package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

func (s *Server) handleProtectedResource(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	writeJSONCached(w, map[string]any{
		"resource":                 cfg.endpoint("/mcp"),
		"authorization_servers":    []string{cfg.Issuer()},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"aegis"},
	})
}

func (s *Server) handleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	writeJSONCached(w, map[string]any{
		"issuer":                                cfg.Issuer(),
		"authorization_endpoint":                cfg.endpoint("/authorize"),
		"token_endpoint":                        cfg.endpoint("/token"),
		"registration_endpoint":                 cfg.endpoint("/register"),
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"aegis"},
	})
}

func writeJSONCached(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=300")
	json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// Dynamic client registration (RFC 7591)
// ---------------------------------------------------------------------------

type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if ok, _ := s.registerLimiter.Allow(clientIP(r)); !ok {
		writeHTTPError(w, http.StatusTooManyRequests, "too many registrations")
		return
	}

	var req registrationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "malformed registration document")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "at least one redirect_uri is required")
		return
	}
	if req.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != "none" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata",
			"only public clients (token_endpoint_auth_method=none) are supported")
		return
	}
	for _, u := range req.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}

	name := req.ClientName
	if name == "" {
		name = "unnamed client"
	}
	c := s.sessions.RegisterClient(name, req.RedirectURIs)
	logInfo("client_registered", map[string]any{
		"client_id": c.ID, "client_name": c.Name, "redirect_uris": c.RedirectURIs,
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        c.Created.Unix(),
		"client_name":                c.Name,
		"redirect_uris":              c.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return errString("redirect_uri must be an absolute URI")
	}
	if u.Fragment != "" {
		return errString("redirect_uri must not contain a fragment")
	}
	host := strings.ToLower(u.Hostname())
	isLoopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback) {
		return errString("redirect_uri must use https (http is allowed only for loopback)")
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	cfg := s.Config()

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.tokenFromCode(w, r, cfg)
	case "refresh_token":
		s.tokenFromRefresh(w, r, cfg)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (s *Server) tokenFromCode(w http.ResponseWriter, r *http.Request, cfg *Config) {
	code := r.PostForm.Get("code")
	clientID := r.PostForm.Get("client_id")
	redirectURI := r.PostForm.Get("redirect_uri")
	verifier := r.PostForm.Get("code_verifier")

	if code == "" || clientID == "" || redirectURI == "" || verifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing required parameter")
		return
	}
	ac, ok := s.sessions.ConsumeCode(code)
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
		return
	}
	if !constantTimeEqual(ac.ClientID, clientID) || !constantTimeEqual(ac.RedirectURI, redirectURI) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code does not match this client")
		return
	}
	if !verifyPKCE(verifier, ac.CodeChallenge) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	if _, exists := cfg.Users[ac.User]; !exists {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "user no longer exists")
		return
	}

	access, refresh := s.sessions.IssueTokens(ac.User, clientID, "", cfg.TokenTTL)
	logInfo("token_issued", map[string]any{"user": ac.User, "client_id": clientID, "grant": "authorization_code"})
	writeTokenResponse(w, access, refresh, cfg.TokenTTL)
}

func (s *Server) tokenFromRefresh(w http.ResponseWriter, r *http.Request, cfg *Config) {
	token := r.PostForm.Get("refresh_token")
	clientID := r.PostForm.Get("client_id")
	if token == "" || clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing required parameter")
		return
	}
	t, ok, reuse := s.sessions.RotateRefresh(token, clientID)
	if reuse {
		logWarn("token_reuse_detected", map[string]any{"client_id": clientID})
	}
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or expired")
		return
	}
	if _, exists := cfg.Users[t.User]; !exists {
		s.sessions.KillFamily(t.Family)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "user no longer exists")
		return
	}
	access, refresh := s.sessions.IssueTokens(t.User, clientID, t.Family, cfg.TokenTTL)
	logInfo("token_issued", map[string]any{"user": t.User, "client_id": clientID, "grant": "refresh_token"})
	writeTokenResponse(w, access, refresh, cfg.TokenTTL)
}

func writeTokenResponse(w http.ResponseWriter, access, refresh string, ttl time.Duration) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(ttl.Seconds()),
		"refresh_token": refresh,
		"scope":         "aegis",
	})
}

// verifyPKCE checks BASE64URL(SHA256(verifier)) == challenge.
func verifyPKCE(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return constantTimeEqual(want, strings.TrimRight(challenge, "="))
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error":             code,
		"error_description": desc,
	})
}

func writeHTTPError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": msg, "status": status})
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}
