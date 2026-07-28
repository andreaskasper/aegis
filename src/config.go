package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Raw YAML shapes
// ---------------------------------------------------------------------------

type rawConfig struct {
	Server rawServer `yaml:"server"`
	Users  []rawUser `yaml:"users"`
}

type rawServer struct {
	Listen           string `yaml:"listen"`
	PublicURL        string `yaml:"public_url"`
	MaxResponseBytes int64  `yaml:"max_response_bytes"`
	RequestTimeout   string `yaml:"request_timeout"`
	TokenTTL         string `yaml:"token_ttl"`
	CodeTTL          string `yaml:"code_ttl"`
	LoginRateLimit   string `yaml:"login_rate_limit"`
}

type rawUser struct {
	Name     string            `yaml:"name"`
	Password string            `yaml:"password"`
	AllowAny bool              `yaml:"allow_any"`
	Secrets  map[string]string `yaml:"secrets"`
	Targets  []rawTarget       `yaml:"targets"`
}

type rawTarget struct {
	ID               string     `yaml:"id"`
	Description      string     `yaml:"description"`
	BaseURL          string     `yaml:"base_url"`
	Methods          []string   `yaml:"methods"`
	Paths            []string   `yaml:"paths"`
	RateLimit        string     `yaml:"rate_limit"`
	Timeout          string     `yaml:"timeout"`
	MaxResponseBytes int64      `yaml:"max_response_bytes"`
	FollowRedirects  bool       `yaml:"follow_redirects"`
	Inject           *rawInject `yaml:"inject"`
}

type rawInject struct {
	Headers map[string]string `yaml:"headers"`
	Query   map[string]string `yaml:"query"`
	Body    map[string]string `yaml:"body"`
}

// ---------------------------------------------------------------------------
// Resolved config
// ---------------------------------------------------------------------------

// Config is immutable once built. It is swapped atomically on reload.
type Config struct {
	Listen           string
	PublicURL        *url.URL
	MaxResponseBytes int64
	RequestTimeout   time.Duration
	TokenTTL         time.Duration
	CodeTTL          time.Duration
	LoginRateLimit   Rate

	Users map[string]*User // keyed by name
}

type User struct {
	Name     string
	AllowAny bool

	// Password is either a bcrypt hash (PasswordIsHash) or a literal.
	Password       []byte
	PasswordIsHash bool

	// Secrets maps a secret name to its resolved value. Values never leave
	// the process in readable form.
	Secrets map[string]string

	Targets []*Target

	// redactor is precomputed from Secrets so the hot path does no setup.
	redactor *Redactor
	// anyLimiter guards allow_any requests.
	anyLimiter *Limiter
}

type Target struct {
	ID               string
	Description      string
	BaseURL          *url.URL
	Methods          map[string]bool
	MethodList       []string
	Paths            []*PathPattern
	PathSources      []string
	RateLimit        Rate
	Timeout          time.Duration
	MaxResponseBytes int64
	FollowRedirects  bool

	InjectHeaders map[string]*Template
	InjectQuery   map[string]*Template
	InjectBody    map[string]*Template

	// SecretNames lists the secrets referenced by this target's injection
	// rules, for the audit log.
	SecretNames []string

	limiter *Limiter
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const (
	defaultListen           = ":2019"
	defaultMaxResponseBytes = 1 << 20 // 1 MiB
	defaultRequestTimeout   = 30 * time.Second
	defaultTokenTTL         = 12 * time.Hour
	defaultCodeTTL          = 60 * time.Second
	defaultAllowAnyRate     = "60/m"
	defaultLoginRate        = "10/m"
	maxRequestBodyBytes     = 1 << 20 // 1 MiB
)

var validMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true,
}

var (
	nameRe   = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
	secretRe = regexp.MustCompile(`^[a-zA-Z0-9_]{1,64}$`)
)

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

// LoadConfig reads, resolves and validates a configuration file. It reports
// every problem it finds rather than stopping at the first.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return ParseConfig(data)
}

func ParseConfig(data []byte) (*Config, error) {
	var raw rawConfig
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	var errs []string
	fail := func(format string, a ...any) {
		errs = append(errs, fmt.Sprintf(format, a...))
	}

	cfg := &Config{
		Listen:           firstNonEmpty(os.Getenv("AEGIS_LISTEN"), raw.Server.Listen, defaultListen),
		MaxResponseBytes: raw.Server.MaxResponseBytes,
		Users:            map[string]*User{},
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = defaultMaxResponseBytes
	}

	// --- public_url ---------------------------------------------------
	pub := firstNonEmpty(os.Getenv("AEGIS_PUBLIC_URL"), raw.Server.PublicURL)
	if pub == "" {
		fail("server.public_url is required (or set AEGIS_PUBLIC_URL)")
	} else if u, err := url.Parse(pub); err != nil {
		fail("server.public_url: %v", err)
	} else if !u.IsAbs() || u.Host == "" {
		fail("server.public_url must be an absolute URL")
	} else if u.Scheme != "http" && u.Scheme != "https" {
		fail("server.public_url must be http or https")
	} else if u.Path != "" && u.Path != "/" {
		fail("server.public_url must not have a path")
	} else {
		u.Path = ""
		u.RawQuery = ""
		u.Fragment = ""
		cfg.PublicURL = u
	}

	// --- durations ----------------------------------------------------
	cfg.RequestTimeout = mustDuration(raw.Server.RequestTimeout, defaultRequestTimeout, "server.request_timeout", fail)
	cfg.TokenTTL = mustDuration(raw.Server.TokenTTL, defaultTokenTTL, "server.token_ttl", fail)
	cfg.CodeTTL = mustDuration(raw.Server.CodeTTL, defaultCodeTTL, "server.code_ttl", fail)

	loginRate := raw.Server.LoginRateLimit
	if loginRate == "" {
		loginRate = defaultLoginRate
	}
	if r, err := ParseRate(loginRate); err != nil {
		fail("server.login_rate_limit: %v", err)
	} else {
		cfg.LoginRateLimit = r
	}

	// --- users --------------------------------------------------------
	if len(raw.Users) == 0 {
		fail("at least one user is required")
	}
	for ui, ru := range raw.Users {
		where := fmt.Sprintf("users[%d]", ui)
		if ru.Name == "" {
			fail("%s: name is required", where)
			continue
		}
		where = fmt.Sprintf("user %q", ru.Name)
		if !nameRe.MatchString(ru.Name) {
			fail("%s: name must match [a-zA-Z0-9._-]{1,64}", where)
			continue
		}
		if _, dup := cfg.Users[ru.Name]; dup {
			fail("%s: duplicate user name", where)
			continue
		}

		u := &User{
			Name:     ru.Name,
			AllowAny: ru.AllowAny,
			Secrets:  map[string]string{},
		}

		// password
		if ru.Password == "" {
			fail("%s: password is required", where)
		} else if strings.HasPrefix(ru.Password, "bcrypt:") {
			u.Password = []byte(strings.TrimPrefix(ru.Password, "bcrypt:"))
			u.PasswordIsHash = true
		} else if v, err := resolveValue(ru.Password); err != nil {
			fail("%s: password: %v", where, err)
		} else {
			u.Password = []byte(v)
		}

		// secrets
		for name, val := range ru.Secrets {
			if !secretRe.MatchString(name) {
				fail("%s: secret %q: name must match [a-zA-Z0-9_]{1,64}", where, name)
				continue
			}
			v, err := resolveValue(val)
			if err != nil {
				fail("%s: secret %q: %v", where, name, err)
				continue
			}
			if v == "" {
				fail("%s: secret %q resolves to an empty value", where, name)
				continue
			}
			u.Secrets[name] = v
		}

		// targets
		seenTargets := map[string]bool{}
		for ti, rt := range ru.Targets {
			t, terrs := buildTarget(rt, ti, u)
			for _, e := range terrs {
				fail("%s: %s", where, e)
			}
			if t == nil {
				continue
			}
			if seenTargets[t.ID] {
				fail("%s: duplicate target id %q", where, t.ID)
				continue
			}
			seenTargets[t.ID] = true
			u.Targets = append(u.Targets, t)
		}

		u.redactor = NewRedactor(u.Secrets)
		if u.AllowAny {
			r, _ := ParseRate(defaultAllowAnyRate)
			u.anyLimiter = NewLimiter(r)
		}
		cfg.Users[u.Name] = u
	}

	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return cfg, nil
}

func buildTarget(rt rawTarget, idx int, u *User) (*Target, []string) {
	var errs []string
	fail := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	id := rt.ID
	if id == "" {
		fail("targets[%d]: id is required", idx)
		return nil, errs
	}
	if !nameRe.MatchString(id) {
		fail("target %q: id must match [a-zA-Z0-9._-]{1,64}", id)
		return nil, errs
	}
	if rt.Description == "" {
		fail("target %q: description is required", id)
	}

	t := &Target{
		ID:               id,
		Description:      rt.Description,
		MaxResponseBytes: rt.MaxResponseBytes,
		FollowRedirects:  rt.FollowRedirects,
		Methods:          map[string]bool{},
		InjectHeaders:    map[string]*Template{},
		InjectQuery:      map[string]*Template{},
		InjectBody:       map[string]*Template{},
	}

	// base_url
	if rt.BaseURL == "" {
		fail("target %q: base_url is required", id)
	} else if bu, err := url.Parse(rt.BaseURL); err != nil {
		fail("target %q: base_url: %v", id, err)
	} else if !bu.IsAbs() || bu.Host == "" {
		fail("target %q: base_url must be absolute", id)
	} else if bu.Scheme != "http" && bu.Scheme != "https" {
		fail("target %q: base_url must be http or https", id)
	} else if bu.RawQuery != "" || bu.Fragment != "" {
		fail("target %q: base_url must not contain a query or fragment", id)
	} else if bu.User != nil {
		fail("target %q: base_url must not contain credentials", id)
	} else {
		bu.Host = strings.ToLower(bu.Host)
		bu.Path = strings.TrimSuffix(bu.Path, "/")
		if ip := net.ParseIP(bu.Hostname()); ip != nil && isBlockedIP(ip) {
			fail("target %q: base_url points into a blocked network range", id)
		}
		t.BaseURL = bu
	}

	// methods
	methods := rt.Methods
	if len(methods) == 0 {
		methods = []string{"GET"}
	}
	for _, m := range methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if !validMethods[m] {
			fail("target %q: unknown method %q", id, m)
			continue
		}
		if !t.Methods[m] {
			t.Methods[m] = true
			t.MethodList = append(t.MethodList, m)
		}
	}

	// paths
	paths := rt.Paths
	if len(paths) == 0 {
		paths = []string{"/**"}
	}
	for _, p := range paths {
		pat, err := CompilePathPattern(p)
		if err != nil {
			fail("target %q: path %q: %v", id, p, err)
			continue
		}
		t.Paths = append(t.Paths, pat)
		t.PathSources = append(t.PathSources, p)
	}

	// rate limit
	if rt.RateLimit != "" {
		r, err := ParseRate(rt.RateLimit)
		if err != nil {
			fail("target %q: rate_limit: %v", id, err)
		} else {
			t.RateLimit = r
			t.limiter = NewLimiter(r)
		}
	}

	// timeout
	if rt.Timeout != "" {
		d, err := time.ParseDuration(rt.Timeout)
		if err != nil || d <= 0 {
			fail("target %q: timeout: invalid duration %q", id, rt.Timeout)
		} else {
			t.Timeout = d
		}
	}

	// injection
	secretNames := map[string]bool{}
	compile := func(section, key, val string, dst map[string]*Template) {
		tpl, err := CompileTemplate(val, u.Secrets)
		if err != nil {
			fail("target %q: inject.%s.%s: %v", id, section, key, err)
			return
		}
		for _, n := range tpl.Secrets {
			secretNames[n] = true
		}
		dst[key] = tpl
	}
	if rt.Inject != nil {
		for k, v := range rt.Inject.Headers {
			canon := canonicalHeader(k)
			if isReservedInjectHeader(canon) {
				fail("target %q: inject.headers.%s: header may not be injected", id, k)
				continue
			}
			compile("headers", canon, v, t.InjectHeaders)
		}
		for k, v := range rt.Inject.Query {
			compile("query", k, v, t.InjectQuery)
		}
		for k, v := range rt.Inject.Body {
			if !strings.HasPrefix(k, "$.") {
				fail("target %q: inject.body.%s: key must be a JSON path starting with $.", id, k)
				continue
			}
			compile("body", k, v, t.InjectBody)
		}
	}
	for n := range secretNames {
		t.SecretNames = append(t.SecretNames, n)
	}
	sort.Strings(t.SecretNames)

	if len(errs) > 0 {
		return nil, errs
	}
	return t, nil
}

// ---------------------------------------------------------------------------
// Value resolution
// ---------------------------------------------------------------------------

// resolveValue expands the env:, file: and literal: prefixes.
func resolveValue(v string) (string, error) {
	switch {
	case strings.HasPrefix(v, "literal:"):
		return strings.TrimPrefix(v, "literal:"), nil
	case strings.HasPrefix(v, "env:"):
		name := strings.TrimPrefix(v, "env:")
		if name == "" {
			return "", fmt.Errorf("env: reference without a variable name")
		}
		val, ok := os.LookupEnv(name)
		if !ok || val == "" {
			return "", fmt.Errorf("environment variable %s is unset or empty", name)
		}
		return val, nil
	case strings.HasPrefix(v, "file:"):
		p := strings.TrimPrefix(v, "file:")
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("cannot read %s: %w", p, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	default:
		return v, nil
	}
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

func (t *Target) responseLimit(cfg *Config) int64 {
	if t != nil && t.MaxResponseBytes > 0 {
		return t.MaxResponseBytes
	}
	return cfg.MaxResponseBytes
}

func (t *Target) timeout(cfg *Config) time.Duration {
	if t != nil && t.Timeout > 0 {
		return t.Timeout
	}
	return cfg.RequestTimeout
}

// Issuer returns the OAuth issuer string.
func (c *Config) Issuer() string { return strings.TrimSuffix(c.PublicURL.String(), "/") }

func (c *Config) endpoint(path string) string { return c.Issuer() + path }

// ---------------------------------------------------------------------------
// Rate parsing
// ---------------------------------------------------------------------------

// Rate is "<count>/<unit>" with unit s, m or h.
type Rate struct {
	Count  int
	Window time.Duration
	Source string
}

func (r Rate) Zero() bool { return r.Count == 0 }

func ParseRate(s string) (Rate, error) {
	parts := strings.SplitN(strings.TrimSpace(s), "/", 2)
	if len(parts) != 2 {
		return Rate{}, fmt.Errorf("expected <count>/<s|m|h>, got %q", s)
	}
	n, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || n <= 0 {
		return Rate{}, fmt.Errorf("invalid count in %q", s)
	}
	var w time.Duration
	switch strings.TrimSpace(parts[1]) {
	case "s":
		w = time.Second
	case "m":
		w = time.Minute
	case "h":
		w = time.Hour
	default:
		return Rate{}, fmt.Errorf("unknown unit in %q, expected s, m or h", s)
	}
	return Rate{Count: n, Window: w, Source: s}, nil
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func mustDuration(s string, def time.Duration, where string, fail func(string, ...any)) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		fail("%s: invalid duration %q", where, s)
		return def
	}
	return d
}
