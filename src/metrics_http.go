package main

import (
	"net/http"
	"strings"
)

// metricsPath is where the endpoint is mounted, or "" when it is off.
//
// The route is fixed at startup, so switching metrics on is one of the few
// changes that needs a restart rather than a reload. Changing the key, on the
// other hand, is picked up by the next scrape.
func metricsPath(cfg *Config) string {
	if cfg.Metrics == nil {
		return ""
	}
	return cfg.Metrics.Path
}

// handleMetrics serves the Prometheus endpoint.
//
// Authentication is a shared key rather than the OAuth flow, because Prometheus
// cannot walk an authorization code exchange. `authorization` with a
// credentials_file in the scrape config is the idiomatic counterpart.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	if cfg.Metrics == nil {
		writeHTTPError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Its own bucket, so a scraper hammering with a wrong key cannot be used
	// as an oracle and cannot exhaust the login limiter.
	if ok, _ := s.metricsLimiter.Allow(clientIP(r)); !ok {
		writeHTTPError(w, http.StatusTooManyRequests, "too many requests")
		return
	}

	if !metricsKeyOK(r, cfg.Metrics.APIKey) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="aegis metrics"`)
		writeHTTPError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	body := s.metrics.Render(s.metricsSnapshot(cfg))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Write([]byte(body))
}

// metricsKeyOK accepts the key as a bearer token, or as X-API-Key for scrapers
// that find that easier. Both comparisons are constant time.
func metricsKeyOK(r *http.Request, key string) bool {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		if constantTimeEqual(strings.TrimSpace(auth[len(prefix):]), key) {
			return true
		}
	}
	if v := r.Header.Get("X-API-Key"); v != "" {
		return constantTimeEqual(v, key)
	}
	return false
}

// metricsSnapshot gathers the values the registry cannot know by itself.
func (s *Server) metricsSnapshot(cfg *Config) snapshot {
	sessions, refresh, clients := s.sessions.Counts()

	targets, short := 0, 0
	for _, u := range cfg.Users {
		targets += len(u.Targets)
		if u.redactor != nil {
			short += len(u.redactor.Skipped)
		}
	}

	return snapshot{
		Sessions:     sessions,
		RefreshCount: refresh,
		Clients:      clients,
		Users:        len(cfg.Users),
		Targets:      targets,
		ShortSecrets: short,
		Version:      version,
		Commit:       commit,
	}
}
