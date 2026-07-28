package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// All state below lives in memory only and is lost on restart. That is the
// point: a container holding credentials should leave nothing on disk.

const (
	maxClients      = 1000
	maxTokens       = 10000
	refreshTokenTTL = 30 * 24 * time.Hour
	csrfTTL         = 10 * time.Minute
)

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

type Client struct {
	ID           string
	Name         string
	RedirectURIs []string
	Created      time.Time
	lastSeen     time.Time
}

type AuthCode struct {
	User          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Expiry        time.Time
}

type Token struct {
	User     string
	ClientID string
	Family   string
	Expiry   time.Time
}

type csrfEntry struct {
	clientID    string
	redirectURI string
	state       string
	challenge   string
	expiry      time.Time
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

type SessionStore struct {
	mu sync.Mutex

	clients map[string]*Client
	codes   map[string]*AuthCode
	tokens  map[string]*Token
	refresh map[string]*Token
	csrf    map[string]*csrfEntry

	// consumedRefresh remembers which family a spent refresh token belonged
	// to. Without it, presenting an already-rotated token would look like an
	// unknown token, and the theft it signals would go unnoticed.
	consumedRefresh map[string]consumedToken

	// deadFamilies marks refresh-token families invalidated by a reuse.
	deadFamilies map[string]time.Time
}

type consumedToken struct {
	family string
	at     time.Time
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		clients:         map[string]*Client{},
		codes:           map[string]*AuthCode{},
		tokens:          map[string]*Token{},
		refresh:         map[string]*Token{},
		csrf:            map[string]*csrfEntry{},
		consumedRefresh: map[string]consumedToken{},
		deadFamilies:    map[string]time.Time{},
	}
}

// ---------------------------------------------------------------------------
// Secret generation and hashing
// ---------------------------------------------------------------------------

// randToken returns n bytes of crypto/rand as base64url.
func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken is what we store. The plaintext exists only in the response that
// issued it.
func hashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

func (s *SessionStore) RegisterClient(name string, redirectURIs []string) *Client {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.clients) >= maxClients {
		s.evictClientsLocked()
	}
	c := &Client{
		ID:           randToken(16),
		Name:         name,
		RedirectURIs: redirectURIs,
		Created:      time.Now(),
		lastSeen:     time.Now(),
	}
	s.clients[c.ID] = c
	return c
}

func (s *SessionStore) Client(id string) *Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clients[id]
	if c != nil {
		c.lastSeen = time.Now()
	}
	return c
}

func (s *SessionStore) evictClientsLocked() {
	var oldestID string
	var oldest time.Time
	for id, c := range s.clients {
		if oldestID == "" || c.lastSeen.Before(oldest) {
			oldestID, oldest = id, c.lastSeen
		}
	}
	if oldestID != "" {
		delete(s.clients, oldestID)
	}
}

func (c *Client) AllowsRedirect(uri string) bool {
	for _, r := range c.RedirectURIs {
		if constantTimeEqual(r, uri) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// CSRF tokens for the login form
// ---------------------------------------------------------------------------

func (s *SessionStore) NewCSRF(clientID, redirectURI, state, challenge string) string {
	tok := randToken(16)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.csrf[hashToken(tok)] = &csrfEntry{
		clientID:    clientID,
		redirectURI: redirectURI,
		state:       state,
		challenge:   challenge,
		expiry:      time.Now().Add(csrfTTL),
	}
	return tok
}

// ConsumeCSRF validates a token and removes it. Single use.
func (s *SessionStore) ConsumeCSRF(tok, clientID, redirectURI string) (*csrfEntry, bool) {
	h := hashToken(tok)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.csrf[h]
	if !ok {
		return nil, false
	}
	delete(s.csrf, h)
	if time.Now().After(e.expiry) {
		return nil, false
	}
	if e.clientID != clientID || e.redirectURI != redirectURI {
		return nil, false
	}
	return e, true
}

// ---------------------------------------------------------------------------
// Authorization codes
// ---------------------------------------------------------------------------

func (s *SessionStore) NewCode(user, clientID, redirectURI, challenge string, ttl time.Duration) string {
	code := randToken(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[hashToken(code)] = &AuthCode{
		User:          user,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: challenge,
		Expiry:        time.Now().Add(ttl),
	}
	return code
}

// ConsumeCode removes the code whether or not it turns out to be valid, so a
// failed exchange cannot be retried.
func (s *SessionStore) ConsumeCode(code string) (*AuthCode, bool) {
	h := hashToken(code)
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[h]
	if !ok {
		return nil, false
	}
	delete(s.codes, h)
	if time.Now().After(c.Expiry) {
		return nil, false
	}
	return c, true
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

// IssueTokens mints an access token and a refresh token in the same family.
func (s *SessionStore) IssueTokens(user, clientID, family string, ttl time.Duration) (string, string) {
	if family == "" {
		family = randToken(16)
	}
	access := randToken(32)
	refresh := randToken(32)

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tokens) >= maxTokens {
		s.evictTokensLocked()
	}
	now := time.Now()
	s.tokens[hashToken(access)] = &Token{User: user, ClientID: clientID, Family: family, Expiry: now.Add(ttl)}
	s.refresh[hashToken(refresh)] = &Token{User: user, ClientID: clientID, Family: family, Expiry: now.Add(refreshTokenTTL)}
	return access, refresh
}

// LookupAccess resolves a bearer token to its session.
func (s *SessionStore) LookupAccess(token string) *Token {
	h := hashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[h]
	if !ok {
		return nil
	}
	if time.Now().After(t.Expiry) {
		delete(s.tokens, h)
		return nil
	}
	if _, dead := s.deadFamilies[t.Family]; dead {
		delete(s.tokens, h)
		return nil
	}
	return t
}

// RotateRefresh exchanges a refresh token. Reusing an already-rotated token
// kills the whole family: that is the signature of a stolen token.
func (s *SessionStore) RotateRefresh(token, clientID string) (*Token, bool, bool) {
	h := hashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.refresh[h]
	if !ok {
		// Not live. If we have seen it before, this is a replay of a token
		// that was already exchanged - the signature of a stolen token.
		if c, seen := s.consumedRefresh[h]; seen {
			s.killFamilyLocked(c.family)
			return nil, false, true
		}
		return nil, false, false
	}
	delete(s.refresh, h)
	s.consumedRefresh[h] = consumedToken{family: t.Family, at: time.Now()}

	if _, dead := s.deadFamilies[t.Family]; dead {
		return nil, false, true
	}
	if time.Now().After(t.Expiry) || t.ClientID != clientID {
		// Treat a mismatched client as a compromise of the family.
		s.killFamilyLocked(t.Family)
		return nil, false, true
	}
	return t, true, false
}

// KillFamily invalidates every token in a family.
func (s *SessionStore) KillFamily(family string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.killFamilyLocked(family)
}

func (s *SessionStore) killFamilyLocked(family string) {
	s.deadFamilies[family] = time.Now()
	for h, t := range s.tokens {
		if t.Family == family {
			delete(s.tokens, h)
		}
	}
	for h, t := range s.refresh {
		if t.Family == family {
			delete(s.refresh, h)
		}
	}
}

func (s *SessionStore) evictTokensLocked() {
	var oldestH string
	var oldest time.Time
	for h, t := range s.tokens {
		if oldestH == "" || t.Expiry.Before(oldest) {
			oldestH, oldest = h, t.Expiry
		}
	}
	if oldestH != "" {
		delete(s.tokens, oldestH)
		logWarn("token_evicted", map[string]any{"reason": "token table full"})
	}
}

// ---------------------------------------------------------------------------
// Janitor
// ---------------------------------------------------------------------------

// Sweep removes expired entries. Called every 60s.
func (s *SessionStore) Sweep() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	for h, c := range s.codes {
		if now.After(c.Expiry) {
			delete(s.codes, h)
		}
	}
	for h, t := range s.tokens {
		if now.After(t.Expiry) {
			delete(s.tokens, h)
		}
	}
	for h, t := range s.refresh {
		if now.After(t.Expiry) {
			delete(s.refresh, h)
		}
	}
	for h, e := range s.csrf {
		if now.After(e.expiry) {
			delete(s.csrf, h)
		}
	}
	cutoff := now.Add(-refreshTokenTTL)
	for f, t := range s.deadFamilies {
		if t.Before(cutoff) {
			delete(s.deadFamilies, f)
		}
	}
	for h, c := range s.consumedRefresh {
		if c.at.Before(cutoff) {
			delete(s.consumedRefresh, h)
		}
	}
}

func (s *SessionStore) RunJanitor(stop <-chan struct{}) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.Sweep()
		case <-stop:
			return
		}
	}
}
