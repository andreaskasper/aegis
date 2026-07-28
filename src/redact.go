package main

import (
	"bytes"
	"sort"
	"strings"
	"unicode/utf8"
)

// minRedactLen is the shortest secret Aegis will search for. Below this the
// false-positive rate destroys legitimate content: a four-character secret
// would match inside ordinary words and numbers. Short secrets are reported
// at startup instead.
const minRedactLen = 8

// Redactor removes a user's secret values from anything on its way to the
// model. It is built once per config load.
type Redactor struct {
	// entries are sorted longest-first so that an overlapping pair yields
	// the more specific name.
	entries []redactEntry
	// Skipped lists secrets too short to be redacted safely.
	Skipped []string
}

type redactEntry struct {
	value []byte
	repl  []byte
}

func NewRedactor(secrets map[string]string) *Redactor {
	r := &Redactor{}
	names := make([]string, 0, len(secrets))
	for n := range secrets {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		v := secrets[n]
		if len(v) < minRedactLen {
			r.Skipped = append(r.Skipped, n)
			continue
		}
		r.entries = append(r.entries, redactEntry{
			value: []byte(v),
			repl:  []byte("[REDACTED:" + n + "]"),
		})
	}
	sort.SliceStable(r.entries, func(i, j int) bool {
		return len(r.entries[i].value) > len(r.entries[j].value)
	})
	return r
}

// Bytes replaces every occurrence of every secret and reports how many
// replacements were made.
func (r *Redactor) Bytes(b []byte) ([]byte, int) {
	if r == nil || len(r.entries) == 0 || len(b) == 0 {
		return b, 0
	}
	count := 0
	for _, e := range r.entries {
		n := bytes.Count(b, e.value)
		if n == 0 {
			continue
		}
		b = bytes.ReplaceAll(b, e.value, e.repl)
		count += n
	}
	return b, count
}

// String is the string form of Bytes.
func (r *Redactor) String(s string) (string, int) {
	if r == nil || len(r.entries) == 0 || s == "" {
		return s, 0
	}
	count := 0
	for _, e := range r.entries {
		v := string(e.value)
		n := strings.Count(s, v)
		if n == 0 {
			continue
		}
		s = strings.ReplaceAll(s, v, string(e.repl))
		count += n
	}
	return s, count
}

// ---------------------------------------------------------------------------
// Truncation
// ---------------------------------------------------------------------------

// truncateUTF8 cuts b to at most limit bytes without splitting a rune.
// Redaction must run before this, so a secret cannot survive by straddling
// the cut.
func truncateUTF8(b []byte, limit int64) ([]byte, bool) {
	if limit <= 0 || int64(len(b)) <= limit {
		return b, false
	}
	cut := int(limit)
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}
	// If the rune at the boundary is incomplete, drop it entirely.
	if cut > 0 {
		if r, size := utf8.DecodeLastRune(b[:cut]); r == utf8.RuneError && size <= 1 {
			cut--
		}
	}
	return b[:cut], true
}

// ---------------------------------------------------------------------------
// Response headers
// ---------------------------------------------------------------------------

// droppedResponseHeaders never reach the model.
var droppedResponseHeaders = map[string]bool{
	"Set-Cookie":  true,
	"Set-Cookie2": true,
}
