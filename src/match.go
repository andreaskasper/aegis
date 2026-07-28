package main

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

// ---------------------------------------------------------------------------
// Path patterns
// ---------------------------------------------------------------------------

// PathPattern is a compiled glob over path segments. A single star matches any
// characters within one segment, a double star matches zero or more whole
// segments and must stand alone as a segment, and a question mark matches one
// character within a segment.
type PathPattern struct {
	Source   string
	segments []string
}

func CompilePathPattern(p string) (*PathPattern, error) {
	if !strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("pattern must start with /")
	}
	if strings.Contains(p, "//") {
		return nil, fmt.Errorf("pattern must not contain empty segments")
	}
	segs := splitPath(p)
	for _, s := range segs {
		if strings.Contains(s, "**") && s != "**" {
			return nil, fmt.Errorf("** is only valid as a complete segment")
		}
		if s == ".." || s == "." {
			return nil, fmt.Errorf("pattern must not contain . or .. segments")
		}
	}
	return &PathPattern{Source: p, segments: segs}, nil
}

func (p *PathPattern) Match(urlPath string) bool {
	return matchSegments(p.segments, splitPath(urlPath))
}

// splitPath turns "/a/b/" into ["a","b"]. "/" becomes [].
func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// matchSegments is the standard recursive glob matcher with ** backtracking.
func matchSegments(pat, seg []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// ** at the end matches everything that remains.
			if len(pat) == 1 {
				return true
			}
			for i := 0; i <= len(seg); i++ {
				if matchSegments(pat[1:], seg[i:]) {
					return true
				}
			}
			return false
		}
		if len(seg) == 0 {
			return false
		}
		if !matchSegment(pat[0], seg[0]) {
			return false
		}
		pat, seg = pat[1:], seg[1:]
	}
	return len(seg) == 0
}

// matchSegment matches a single segment supporting * and ?.
func matchSegment(pat, s string) bool {
	// Iterative wildcard match, linear in practice.
	var star = -1
	var mark int
	i, j := 0, 0
	for i < len(s) {
		switch {
		case j < len(pat) && (pat[j] == '?' || pat[j] == s[i]):
			i++
			j++
		case j < len(pat) && pat[j] == '*':
			star = j
			mark = i
			j++
		case star >= 0:
			j = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for j < len(pat) && pat[j] == '*' {
		j++
	}
	return j == len(pat)
}

// ---------------------------------------------------------------------------
// URL normalisation
// ---------------------------------------------------------------------------

// normalizeURL parses and cleans a model-supplied URL. It rejects anything
// that could confuse later matching.
func normalizeURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("cannot parse URL")
	}
	if !u.IsAbs() || u.Host == "" {
		return nil, fmt.Errorf("URL must be absolute and include a host")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("only http and https are supported")
	}
	if u.User != nil {
		return nil, fmt.Errorf("credentials in the URL are not permitted")
	}
	if u.Fragment != "" {
		u.Fragment = ""
		u.RawFragment = ""
	}
	// Reject traversal before cleaning, so ".." can never be laundered into
	// a path that matches a narrower pattern than intended.
	for _, seg := range splitPath(u.Path) {
		if seg == ".." {
			return nil, fmt.Errorf("path must not contain .. segments")
		}
	}
	if u.Path == "" {
		u.Path = "/"
	} else {
		u.Path = path.Clean(u.Path)
	}
	u.Host = strings.ToLower(u.Host)
	u.Host = stripDefaultPort(u.Scheme, u.Host)
	return u, nil
}

func stripDefaultPort(scheme, host string) string {
	switch {
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		return strings.TrimSuffix(host, ":80")
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		return strings.TrimSuffix(host, ":443")
	}
	return host
}

// ---------------------------------------------------------------------------
// Target matching
// ---------------------------------------------------------------------------

// MatchTarget returns the first target of u whose base URL and path patterns
// accept this URL. The method is deliberately NOT considered here: the caller
// checks it afterwards so the audit log can name the attempted target.
func MatchTarget(u *User, req *url.URL) *Target {
	for _, t := range u.Targets {
		if !sameOrigin(t.BaseURL, req) {
			continue
		}
		if !hasPathPrefix(req.Path, t.BaseURL.Path) {
			continue
		}
		for _, p := range t.Paths {
			if p.Match(req.Path) {
				return t
			}
		}
	}
	return nil
}

func sameOrigin(base, req *url.URL) bool {
	if base.Scheme != req.Scheme {
		return false
	}
	return stripDefaultPort(base.Scheme, strings.ToLower(base.Host)) ==
		stripDefaultPort(req.Scheme, strings.ToLower(req.Host))
}

// hasPathPrefix reports whether p starts with prefix on a segment boundary.
func hasPathPrefix(p, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return true
	}
	if !strings.HasPrefix(p, prefix) {
		return false
	}
	rest := p[len(prefix):]
	return rest == "" || strings.HasPrefix(rest, "/")
}
