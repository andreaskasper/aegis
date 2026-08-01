package main

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// MetricsConfig is nil when the endpoint is off, and off is the default. An
// endpoint that reports how many secrets an operator holds, how many targets
// they reach and when somebody last signed in is not something to expose
// unasked - and because the route is only registered when this is non-nil, a
// disabled endpoint answers a genuine 404 rather than a 401 that tells a
// stranger there is something here worth guessing a key for.
type MetricsConfig struct {
	Path      string
	APIKey    string
	RateLimit Rate
}

// rawMetrics is the YAML shape. It hangs off rawServer, so the strict decoder
// accepts a server.metrics block.
type rawMetrics struct {
	Path      string `yaml:"path"`
	APIKey    string `yaml:"api_key"`
	RateLimit string `yaml:"rate_limit"`
}

const (
	defaultMetricsPath = "/metrics"
	defaultMetricsRate = "60/m"

	// minMetricsKeyLen is short enough not to annoy and long enough that the
	// rate limiter, not the key, is what makes guessing hopeless.
	minMetricsKeyLen = 16
)

// reservedMetricsPaths are routes aegis already owns. Mounting the endpoint on
// one of them would shadow it, and the symptom - a health check that suddenly
// wants a bearer token - looks nothing like the mistake that caused it.
var reservedMetricsPaths = map[string]bool{
	"/":                                       true,
	"/healthz":                                true,
	"/mcp":                                    true,
	"/token":                                  true,
	"/register":                               true,
	"/authorize":                              true,
	"/favicon.ico":                            true,
	"/favicon.png":                            true,
	"/logo.png":                               true,
	"/.well-known/oauth-protected-resource":   true,
	"/.well-known/oauth-authorization-server": true,
}

// buildMetrics resolves the metrics section, reporting every problem it finds
// rather than the first.
//
// The environment wins over the file, matching AEGIS_LISTEN and
// AEGIS_PUBLIC_URL: a container is often configured entirely without a config
// file, and metrics should not be the one thing that forces one to exist.
func buildMetrics(raw *rawMetrics, fail func(string, ...any)) *MetricsConfig {
	on := raw != nil
	if v := os.Getenv("AEGIS_METRICS"); v != "" {
		on = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}
	if !on {
		return nil
	}
	if raw == nil {
		raw = &rawMetrics{}
	}

	m := &MetricsConfig{
		Path: firstNonEmpty(os.Getenv("AEGIS_METRICS_PATH"), raw.Path, defaultMetricsPath),
	}

	if !strings.HasPrefix(m.Path, "/") {
		fail("server.metrics.path: %q must start with a slash", m.Path)
	} else if reservedMetricsPaths[m.Path] {
		fail("server.metrics.path: %q is already served by aegis", m.Path)
	}

	// Unlike every other setting here, the key has no default. A metrics
	// endpoint that came up unauthenticated because nobody set one would be a
	// hole opened by omission, and this is a program whose entire purpose is
	// not having those.
	key := firstNonEmpty(os.Getenv("AEGIS_METRICS_KEY"), raw.APIKey)
	switch {
	case key == "":
		fail("server.metrics.api_key: required when metrics are enabled")
	default:
		v, err := resolveValue(key)
		if err != nil {
			fail("server.metrics.api_key: %v", err)
		} else if len(v) < minMetricsKeyLen {
			fail("server.metrics.api_key: must be at least %d characters", minMetricsKeyLen)
		} else {
			m.APIKey = v
		}
	}

	if r, err := ParseRate(firstNonEmpty(raw.RateLimit, defaultMetricsRate)); err != nil {
		fail("server.metrics.rate_limit: %v", err)
	} else {
		m.RateLimit = r
	}

	return m
}

// metricsRate is the bucket the endpoint gets. A zero Rate means unlimited,
// which is what a disabled endpoint deserves - the route does not exist, so
// the limiter is never consulted.
func metricsRate(c *Config) Rate {
	if c == nil || c.Metrics == nil {
		return Rate{}
	}
	return c.Metrics.RateLimit
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

// snapshot carries the values the registry cannot know by itself: everything
// derived from the configuration, which is swapped wholesale on reload, plus
// the session counts. Keeping them out of the registry is deliberate. A gauge
// that is recomputed per scrape cannot drift away from the thing it describes,
// and a counter that can go down is not a counter.
type snapshot struct {
	Sessions     int
	RefreshCount int
	Clients      int
	Users        int
	Targets      int
	ShortSecrets int
	Version      string
	Commit       string
}

// metricsRegistry holds the totals that only make sense cumulatively.
//
// It is reached through a package-level value rather than threaded through
// every call site, because the one place that increments it - AuditRecord.emit
// - has no reason to know that a Server exists. Server.metrics points at the
// same registry so the handler can reach it the ordinary way.
type metricsRegistry struct {
	started time.Time

	requests   atomic.Int64
	failures   atomic.Int64
	bytes      atomic.Int64
	truncated  atomic.Int64
	redactions atomic.Int64
}

var metricsReg = newMetricsRegistry()

func newMetricsRegistry() *metricsRegistry {
	return &metricsRegistry{started: time.Now()}
}

// observe records one proxied request. Nothing here allocates, blocks or can
// fail: a metrics endpoint that slows down the request path is worse than no
// metrics endpoint at all.
func (m *metricsRegistry) observe(a AuditRecord) {
	if m == nil {
		return
	}
	m.requests.Add(1)
	if a.Error != "" || a.Status >= 400 {
		m.failures.Add(1)
		return
	}
	m.bytes.Add(int64(a.Bytes))
	if a.Truncated {
		m.truncated.Add(1)
	}
	if a.Redacted > 0 {
		m.redactions.Add(int64(a.Redacted))
	}
}

// Render writes the Prometheus text exposition format, version 0.0.4, by hand.
//
// By hand because the alternative is a client library, and this program has
// three dependencies. A scrape endpoint is not worth a fourth.
//
// No metric carries a user name, a target id, a URL or a secret name. The
// point of aegis is that those do not leave the process, and an endpoint that
// leaked them behind a shared key would be a second way in.
func (m *metricsRegistry) Render(s snapshot) string {
	var b strings.Builder

	line := func(kind, name, help string, value string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %s\n", name, help, name, kind, name, value)
	}
	gauge := func(name, help string, v int) {
		line("gauge", name, help, fmt.Sprintf("%d", v))
	}
	counter := func(name, help string, v int64) {
		line("counter", name, help, fmt.Sprintf("%d", v))
	}

	fmt.Fprintf(&b, "# HELP aegis_build_info Build information, always 1.\n# TYPE aegis_build_info gauge\n")
	fmt.Fprintf(&b, "aegis_build_info{version=%q,commit=%q} 1\n", escapeLabel(s.Version), escapeLabel(s.Commit))

	line("gauge", "aegis_uptime_seconds", "Seconds since the process started.",
		fmt.Sprintf("%.0f", time.Since(m.started).Seconds()))

	gauge("aegis_users", "Users defined in the active configuration.", s.Users)
	gauge("aegis_targets", "Targets across all users in the active configuration.", s.Targets)
	gauge("aegis_short_secrets", "Secrets too short to be redacted from responses.", s.ShortSecrets)
	gauge("aegis_oauth_clients", "Dynamically registered OAuth clients held in memory.", s.Clients)
	gauge("aegis_access_tokens", "Live access tokens held in memory.", s.Sessions)
	gauge("aegis_refresh_tokens", "Live refresh tokens held in memory.", s.RefreshCount)

	counter("aegis_requests_total", "Proxied HTTP requests, allowed or refused.", m.requests.Load())
	counter("aegis_request_failures_total", "Proxied requests that failed or returned 4xx/5xx.", m.failures.Load())
	counter("aegis_response_bytes_total", "Response bytes returned to the model after truncation.", m.bytes.Load())
	counter("aegis_responses_truncated_total", "Responses cut short at max_response_bytes.", m.truncated.Load())
	counter("aegis_redactions_total", "Secret values removed from responses.", m.redactions.Load())

	return b.String()
}

// escapeLabel quotes a label value the way the exposition format requires.
// Neither version nor commit should ever contain these, but a build flag is an
// input like any other.
func escapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return strings.ReplaceAll(v, "\n", `\n`)
}

// ---------------------------------------------------------------------------
// Session counts
// ---------------------------------------------------------------------------

// Counts reports live access tokens, live refresh tokens and registered
// clients.
//
// It takes the same lock as everything else in the store. A scrape happens
// once every few seconds and the lock is held for three len() calls; reading
// the maps without it to avoid that would produce three numbers that never
// quite agreed with each other.
func (s *SessionStore) Counts() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens), len(s.refresh), len(s.clients)
}
