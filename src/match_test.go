package main

import "testing"

func TestPathPatternMatch(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/**", "/", true},
		{"/**", "/a", true},
		{"/**", "/a/b/c", true},
		{"/v1/**", "/v1", true},
		{"/v1/**", "/v1/contacts", true},
		{"/v1/**", "/v1/contacts/42", true},
		{"/v1/**", "/v2/contacts", false},
		{"/v1/*", "/v1/contacts", true},
		{"/v1/*", "/v1/contacts/42", false},
		{"/v1/*", "/v1", false},
		{"/repos/*/*/issues", "/repos/a/b/issues", true},
		{"/repos/*/*/issues", "/repos/a/issues", false},
		{"/a/**/z", "/a/z", true},
		{"/a/**/z", "/a/b/z", true},
		{"/a/**/z", "/a/b/c/z", true},
		{"/a/**/z", "/a/b/c", false},
		{"/user", "/user", true},
		{"/user", "/user/emails", false},
		{"/file?.txt", "/fileA.txt", true},
		{"/file?.txt", "/fileAB.txt", false},
		{"/data/2.5/**", "/data/2.5/weather", true},
		{"/pre*post", "/preXYZpost", true},
		{"/pre*post", "/preXYZpost/extra", false},
		{"/**/secret", "/secret", true},
		{"/**/secret", "/a/b/secret", true},
	}
	for _, c := range cases {
		p, err := CompilePathPattern(c.pattern)
		if err != nil {
			t.Fatalf("compile %q: %v", c.pattern, err)
		}
		if got := p.Match(c.path); got != c.want {
			t.Errorf("pattern %q vs path %q = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestPathPatternCompileErrors(t *testing.T) {
	bad := []string{"v1/**", "/a/b**", "/a/**c", "/a//b", "/a/../b"}
	for _, p := range bad {
		if _, err := CompilePathPattern(p); err == nil {
			t.Errorf("pattern %q should not compile", p)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	bad := []string{
		"",
		"/relative",
		"ftp://example.com/x",
		"file:///etc/passwd",
		"https://user:pass@example.com/x",
		"https://example.com/a/../../etc",
		"https://example.com/../etc",
	}
	for _, raw := range bad {
		if _, err := normalizeURL(raw); err == nil {
			t.Errorf("normalizeURL(%q) should fail", raw)
		}
	}

	good := map[string]string{
		"https://EXAMPLE.com":          "https://example.com/",
		"https://example.com:443/a":    "https://example.com/a",
		"http://example.com:80/a":      "http://example.com/a",
		"https://example.com/a/./b":    "https://example.com/a/b",
		"https://example.com/a#frag":   "https://example.com/a",
		"https://example.com/a?x=1":    "https://example.com/a?x=1",
		"https://example.com:8443/a/b": "https://example.com:8443/a/b",
	}
	for in, want := range good {
		u, err := normalizeURL(in)
		if err != nil {
			t.Fatalf("normalizeURL(%q): %v", in, err)
		}
		if u.String() != want {
			t.Errorf("normalizeURL(%q) = %q, want %q", in, u.String(), want)
		}
	}
}

func TestMatchTarget(t *testing.T) {
	cfg := mustConfig(t, `
server:
  public_url: "https://aegis.test"
users:
  - name: a
    password: pw
    secrets:
      tok: "0123456789abcdef"
    targets:
      - id: narrow
        description: narrow first
        base_url: "https://api.example.com"
        methods: [GET]
        paths: ["/v1/**"]
      - id: wide
        description: catch-all second
        base_url: "https://api.example.com"
        methods: [GET, POST]
        paths: ["/**"]
      - id: ported
        description: non-default port
        base_url: "https://api.example.com:8443"
        paths: ["/**"]
      - id: based
        description: base path prefix
        base_url: "https://other.example.com/api/v2"
        paths: ["/**"]
`)
	u := cfg.Users["a"]

	cases := []struct {
		url  string
		want string
	}{
		{"https://api.example.com/v1/x", "narrow"},
		{"https://api.example.com/v2/x", "wide"},
		{"https://api.example.com:443/v1/x", "narrow"},
		{"https://api.example.com:8443/v1/x", "ported"},
		{"http://api.example.com/v1/x", ""},
		{"https://API.EXAMPLE.COM/v1/x", "narrow"},
		{"https://other.example.com/api/v2/things", "based"},
		{"https://other.example.com/api/v3/things", ""},
		{"https://other.example.com/api/v2x/things", ""},
		{"https://elsewhere.com/v1/x", ""},
	}
	for _, c := range cases {
		nu, err := normalizeURL(c.url)
		if err != nil {
			t.Fatalf("normalize %q: %v", c.url, err)
		}
		got := MatchTarget(u, nu)
		gotID := ""
		if got != nil {
			gotID = got.ID
		}
		if gotID != c.want {
			t.Errorf("MatchTarget(%q) = %q, want %q", c.url, gotID, c.want)
		}
	}
}

func TestHasPathPrefix(t *testing.T) {
	cases := []struct {
		p, prefix string
		want      bool
	}{
		{"/api/v2/x", "/api/v2", true},
		{"/api/v2", "/api/v2", true},
		{"/api/v2x", "/api/v2", false},
		{"/anything", "", true},
		{"/anything", "/", true},
	}
	for _, c := range cases {
		if got := hasPathPrefix(c.p, c.prefix); got != c.want {
			t.Errorf("hasPathPrefix(%q,%q) = %v, want %v", c.p, c.prefix, got, c.want)
		}
	}
}
