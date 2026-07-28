package main

import (
	"sync"
	"time"
)

// Limiter is a token bucket refilled continuously over the rate window.
type Limiter struct {
	mu       sync.Mutex
	rate     Rate
	tokens   float64
	capacity float64
	perSec   float64
	last     time.Time
}

func NewLimiter(r Rate) *Limiter {
	if r.Count <= 0 || r.Window <= 0 {
		return nil
	}
	return &Limiter{
		rate:     r,
		tokens:   float64(r.Count),
		capacity: float64(r.Count),
		perSec:   float64(r.Count) / r.Window.Seconds(),
		last:     time.Now(),
	}
}

// Allow takes one token. It returns false and the wait until the next token
// when the bucket is empty. A nil limiter is unlimited.
func (l *Limiter) Allow() (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.perSec
	if l.tokens > l.capacity {
		l.tokens = l.capacity
	}
	l.last = now

	if l.tokens >= 1 {
		l.tokens--
		return true, 0
	}
	need := (1 - l.tokens) / l.perSec
	return false, time.Duration(need * float64(time.Second))
}

// ---------------------------------------------------------------------------
// Keyed limiters (per source IP)
// ---------------------------------------------------------------------------

// KeyedLimiter holds one bucket per key, with lazy eviction of idle buckets.
type KeyedLimiter struct {
	mu      sync.Mutex
	rate    Rate
	buckets map[string]*Limiter
	seen    map[string]time.Time
	maxKeys int
}

func NewKeyedLimiter(r Rate) *KeyedLimiter {
	return &KeyedLimiter{
		rate:    r,
		buckets: map[string]*Limiter{},
		seen:    map[string]time.Time{},
		maxKeys: 10000,
	}
}

func (k *KeyedLimiter) Allow(key string) (bool, time.Duration) {
	if k == nil || k.rate.Count <= 0 {
		return true, 0
	}
	k.mu.Lock()
	b, ok := k.buckets[key]
	if !ok {
		if len(k.buckets) >= k.maxKeys {
			k.evictLocked()
		}
		b = NewLimiter(k.rate)
		k.buckets[key] = b
	}
	k.seen[key] = time.Now()
	k.mu.Unlock()
	return b.Allow()
}

// evictLocked drops the buckets idle for longest. Called with the lock held.
func (k *KeyedLimiter) evictLocked() {
	cutoff := time.Now().Add(-10 * time.Minute)
	for key, t := range k.seen {
		if t.Before(cutoff) {
			delete(k.buckets, key)
			delete(k.seen, key)
		}
	}
	// Still full: drop an arbitrary quarter rather than grow unbounded.
	if len(k.buckets) >= k.maxKeys {
		n := k.maxKeys / 4
		for key := range k.buckets {
			delete(k.buckets, key)
			delete(k.seen, key)
			n--
			if n <= 0 {
				break
			}
		}
	}
}
