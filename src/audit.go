package main

import (
	"encoding/json"
	"io"
	"net/url"
	"os"
	"sync"
	"time"
)

// Log levels, lowest first.
const (
	levelDebug = iota
	levelInfo
	levelWarn
	levelError
)

var levelNames = map[int]string{
	levelDebug: "debug", levelInfo: "info", levelWarn: "warn", levelError: "error",
}

var logLevel = levelInfo

func setLogLevel(name string) {
	switch name {
	case "debug":
		logLevel = levelDebug
	case "warn":
		logLevel = levelWarn
	case "error":
		logLevel = levelError
	default:
		logLevel = levelInfo
	}
}

var (
	logMu sync.Mutex
	// logOut is a variable so tests can capture output; production always
	// writes to stdout.
	logOut io.Writer = os.Stdout
)

// logEvent writes one JSON object per line to stdout. Request and response
// bodies are never passed here, at any level.
func logEvent(level int, event string, fields map[string]any) {
	if level < logLevel {
		return
	}
	rec := make(map[string]any, len(fields)+3)
	for k, v := range fields {
		rec[k] = v
	}
	rec["ts"] = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	rec["level"] = levelNames[level]
	rec["event"] = event

	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	logOut.Write(append(b, '\n'))
}

func logInfo(event string, f map[string]any)  { logEvent(levelInfo, event, f) }
func logWarn(event string, f map[string]any)  { logEvent(levelWarn, event, f) }
func logError(event string, f map[string]any) { logEvent(levelError, event, f) }

// ---------------------------------------------------------------------------
// Request audit
// ---------------------------------------------------------------------------

// AuditRecord is one line per http_request, allowed or refused.
type AuditRecord struct {
	User       string
	ClientID   string
	Target     string
	Method     string
	URL        string
	Status     int
	DurationMS int64
	Bytes      int
	Truncated  bool
	Injected   []string
	Redacted   int
	Error      string
}

func (a AuditRecord) emit() {
	// The single choke point for proxied requests, so the single place the
	// counters need touching.
	metricsReg.observe(a)

	f := map[string]any{
		"user":        a.User,
		"method":      a.Method,
		"url":         a.URL,
		"status":      a.Status,
		"duration_ms": a.DurationMS,
	}
	if a.ClientID != "" {
		f["client_id"] = a.ClientID
	}
	if a.Target != "" {
		f["target"] = a.Target
	} else {
		f["target"] = nil
	}
	if a.Error != "" {
		f["error"] = a.Error
	} else {
		f["bytes"] = a.Bytes
		f["truncated"] = a.Truncated
		f["redacted"] = a.Redacted
	}
	if a.Injected == nil {
		a.Injected = []string{}
	}
	f["injected"] = a.Injected
	logInfo("request", f)
}

// auditURL renders a URL for the log with injected query parameters masked.
// Everything a target injects is a secret by definition, so its value must
// not appear even in a log line the operator sees.
func auditURL(u *url.URL, t *Target) string {
	if u == nil {
		return ""
	}
	if t == nil || len(t.InjectQuery) == 0 {
		return u.String()
	}
	c := *u
	q := c.Query()
	for name := range t.InjectQuery {
		if q.Has(name) {
			q.Set(name, "[REDACTED]")
		}
	}
	c.RawQuery = q.Encode()
	return c.String()
}
