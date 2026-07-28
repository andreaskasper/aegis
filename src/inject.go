package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

// Template is a compiled injection value: literal chunks interleaved with
// secret references. Compiling at load time means an undefined secret is a
// configuration error, never a runtime surprise.
type Template struct {
	Source  string
	parts   []tplPart
	Secrets []string
}

type tplPart struct {
	literal string
	secret  string // empty for literal parts
}

// CompileTemplate parses ${secret} references. $${ is a literal "${".
func CompileTemplate(s string, secrets map[string]string) (*Template, error) {
	t := &Template{Source: s}
	seen := map[string]bool{}
	var lit strings.Builder

	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], "$${") {
			lit.WriteString("${")
			i += 3
			continue
		}
		if strings.HasPrefix(s[i:], "${") {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return nil, fmt.Errorf("unterminated ${ reference")
			}
			name := s[i+2 : i+end]
			if name == "" {
				return nil, fmt.Errorf("empty ${} reference")
			}
			if !secretRe.MatchString(name) {
				return nil, fmt.Errorf("invalid secret name %q", name)
			}
			if _, ok := secrets[name]; !ok {
				return nil, fmt.Errorf("undefined secret %q", name)
			}
			if lit.Len() > 0 {
				t.parts = append(t.parts, tplPart{literal: lit.String()})
				lit.Reset()
			}
			t.parts = append(t.parts, tplPart{secret: name})
			if !seen[name] {
				seen[name] = true
				t.Secrets = append(t.Secrets, name)
			}
			i += end + 1
			continue
		}
		lit.WriteByte(s[i])
		i++
	}
	if lit.Len() > 0 {
		t.parts = append(t.parts, tplPart{literal: lit.String()})
	}
	sort.Strings(t.Secrets)
	return t, nil
}

// Expand resolves the template against a user's secrets.
func (t *Template) Expand(secrets map[string]string) string {
	if len(t.parts) == 1 && t.parts[0].secret == "" {
		return t.parts[0].literal
	}
	var b strings.Builder
	for _, p := range t.parts {
		if p.secret == "" {
			b.WriteString(p.literal)
		} else {
			b.WriteString(secrets[p.secret])
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Reserved headers
// ---------------------------------------------------------------------------

// reservedHeaders may never be set by the model.
var reservedHeaders = map[string]bool{
	"Authorization":       true,
	"Proxy-Authorization": true,
	"Cookie":              true,
	"Host":                true,
	"Content-Length":      true,
	"Connection":          true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"X-Forwarded-For":     true,
	"X-Forwarded-Host":    true,
	"X-Forwarded-Proto":   true,
	"X-Real-Ip":           true,
}

// headers that a target may not inject either, because they are controlled by
// the transport rather than by us.
var uninjectableHeaders = map[string]bool{
	"Host":              true,
	"Content-Length":    true,
	"Connection":        true,
	"Transfer-Encoding": true,
	"Upgrade":           true,
}

func canonicalHeader(h string) string { return http.CanonicalHeaderKey(strings.TrimSpace(h)) }

func isReservedInjectHeader(canon string) bool { return uninjectableHeaders[canon] }

// checkModelHeaders rejects headers the model must not control.
func checkModelHeaders(headers map[string]string, t *Target) (map[string]string, error) {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		canon := canonicalHeader(k)
		if canon == "" {
			return nil, fmt.Errorf("empty header name")
		}
		if reservedHeaders[canon] {
			return nil, fmt.Errorf("header %s may not be set", canon)
		}
		if t != nil {
			if _, injected := t.InjectHeaders[canon]; injected {
				return nil, fmt.Errorf("header %s is managed by aegis and may not be set", canon)
			}
		}
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("header %s contains a line break", canon)
		}
		out[canon] = v
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Injection
// ---------------------------------------------------------------------------

// applyInjection mutates the outgoing request: headers and query parameters
// are overwritten, JSON body fields are merged. It is the last thing that
// happens before the request is sent.
func applyInjection(req *http.Request, body []byte, t *Target, secrets map[string]string) ([]byte, error) {
	if t == nil {
		return body, nil
	}

	for name, tpl := range t.InjectHeaders {
		req.Header.Set(name, tpl.Expand(secrets))
	}

	if len(t.InjectQuery) > 0 {
		q := req.URL.Query()
		for name, tpl := range t.InjectQuery {
			q.Set(name, tpl.Expand(secrets))
		}
		req.URL.RawQuery = q.Encode()
	}

	if len(t.InjectBody) > 0 {
		ct := req.Header.Get("Content-Type")
		if len(body) == 0 || !isJSONContentType(ct) {
			return nil, fmt.Errorf("body injection requires a JSON request body")
		}
		var doc any
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("body injection requires a JSON request body")
		}
		obj, ok := doc.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("body injection requires a JSON object at the root")
		}
		for p, tpl := range t.InjectBody {
			if err := setJSONPath(obj, p, tpl.Expand(secrets)); err != nil {
				return nil, err
			}
		}
		nb, err := json.Marshal(obj)
		if err != nil {
			return nil, fmt.Errorf("body injection failed")
		}
		return nb, nil
	}
	return body, nil
}

func isJSONContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}

// setJSONPath writes value at a JSONPath-lite location such as "$.auth.token",
// creating intermediate objects as needed.
func setJSONPath(obj map[string]any, p string, value string) error {
	keys := strings.Split(strings.TrimPrefix(p, "$."), ".")
	if len(keys) == 0 || keys[0] == "" {
		return fmt.Errorf("invalid body injection path %q", p)
	}
	cur := obj
	for i, k := range keys {
		if i == len(keys)-1 {
			cur[k] = value
			return nil
		}
		next, ok := cur[k]
		if !ok {
			m := map[string]any{}
			cur[k] = m
			cur = m
			continue
		}
		m, ok := next.(map[string]any)
		if !ok {
			return fmt.Errorf("body injection path %q crosses a non-object value", p)
		}
		cur = m
	}
	return nil
}

// mergeQuery folds model-supplied parameters into the URL.
func mergeQuery(u *url.URL, extra map[string]string) error {
	if len(extra) == 0 {
		return nil
	}
	q := u.Query()
	for k, v := range extra {
		if k == "" {
			return fmt.Errorf("empty query parameter name")
		}
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return nil
}
