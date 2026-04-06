package porter

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimitConfig configures the rate limiting middleware.
type RateLimitConfig struct {
	// Requests is the maximum number of requests allowed per window. Required.
	Requests int
	// Window is the duration of the rate limit window. Required.
	Window time.Duration
	// KeyFunc extracts a rate-limiting key from the request. When nil, IPKey is
	// used.
	KeyFunc func(*http.Request) string
	// PerPath maps exact request paths to individual rate limit rules that
	// override the default Requests/Window for those paths.
	PerPath map[string]RateRule
	// ExemptPaths lists exact request paths that bypass rate limiting entirely.
	ExemptPaths []string
	// ExemptFunc is a custom function that, when it returns true, bypasses rate
	// limiting for the request.
	ExemptFunc func(*http.Request) bool
	// ErrorHandler is called when a request is rate limited. When nil, a bare
	// 429 Too Many Requests response is written with a Retry-After header.
	ErrorHandler func(http.ResponseWriter, *http.Request)
}

// RateRule defines a rate limit for a specific path.
type RateRule struct {
	// Requests is the maximum number of requests allowed per window.
	Requests int
	// Window is the duration of the rate limit window.
	Window time.Duration
}

// window tracks the request count and start time for a single rate-limit key.
type window struct {
	count int
	start time.Time
}

// rateLimitStore holds the internal state for rate limiting.
type rateLimitStore struct {
	mu      sync.Mutex
	windows map[string]*window
	nowFunc func() time.Time
}

// RateLimit returns middleware that enforces fixed-window rate limiting. Each
// unique key (by default the client IP) is allowed a configured number of
// requests per time window. Requests that exceed the limit receive a 429
// response with a Retry-After header indicating when the window resets.
func RateLimit(cfg RateLimitConfig) func(http.Handler) http.Handler {
	keyFunc := cfg.KeyFunc
	if keyFunc == nil {
		keyFunc = IPKey
	}

	exemptSet := make(map[string]bool, len(cfg.ExemptPaths))
	for _, p := range cfg.ExemptPaths {
		exemptSet[p] = true
	}

	store := &rateLimitStore{
		windows: make(map[string]*window),
		nowFunc: time.Now,
	}

	return buildRateLimitHandler(cfg, store, exemptSet, keyFunc)
}

// buildRateLimitHandler constructs the rate limiting handler using the given
// store. This is separated from RateLimit so tests can inject a custom nowFunc.
func buildRateLimitHandler(cfg RateLimitConfig, store *rateLimitStore, exemptSet map[string]bool, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if exemptSet[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			if cfg.ExemptFunc != nil && cfg.ExemptFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			key := keyFunc(r)

			limit := cfg.Requests
			dur := cfg.Window
			compositeKey := key
			if rule, ok := cfg.PerPath[r.URL.Path]; ok {
				limit = rule.Requests
				dur = rule.Window
				compositeKey = key + "|" + r.URL.Path
			}

			store.mu.Lock()
			now := store.nowFunc()
			entry, ok := store.windows[compositeKey]
			if !ok || now.Sub(entry.start) >= dur {
				entry = &window{count: 0, start: now}
				store.windows[compositeKey] = entry
			}
			entry.count++
			count := entry.count
			start := entry.start
			store.mu.Unlock()

			if count > limit {
				remaining := dur - now.Sub(start)
				retryAfter := max(int(remaining.Seconds()), 1)
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				if cfg.ErrorHandler != nil {
					cfg.ErrorHandler(w, r)
					return
				}
				http.Error(w, "", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// IPKey extracts the client IP address from a request. It checks
// X-Forwarded-For first (using the first listed IP), then X-Real-IP, then
// falls back to RemoteAddr with the port stripped.
func IPKey(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
		if ip != "" {
			return ip
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// BruteForceConfig configures the brute force protection middleware.
type BruteForceConfig struct {
	// MaxAttempts is the number of failures allowed before blocking the key.
	// Required.
	MaxAttempts int
	// Cooldown is how long a key remains blocked after reaching MaxAttempts.
	// Required.
	Cooldown time.Duration
	// KeyFunc extracts a tracking key from the request. When nil, IPKey is used.
	KeyFunc func(*http.Request) string
	// FailureStatus lists the HTTP status codes that count as failures. When
	// nil, only 401 Unauthorized is counted.
	FailureStatus []int
	// ErrorHandler is called when a request is blocked. When nil, a bare 429
	// Too Many Requests response is written with a Retry-After header.
	ErrorHandler func(http.ResponseWriter, *http.Request)
}

// bruteForceEntry tracks failure attempts for a single key.
type bruteForceEntry struct {
	count     int
	blockedAt time.Time
}

// bruteForceStore holds the internal state for brute force protection.
type bruteForceStore struct {
	mu      sync.Mutex
	entries map[string]*bruteForceEntry
	nowFunc func() time.Time
	max     int
	cooldown time.Duration
}

type bruteForceCtxKeyType struct{}

var bruteForceCtxKey bruteForceCtxKeyType

// bruteForceCtxValue is stored on the request context so that ResetFailures
// can locate the store and key.
type bruteForceCtxValue struct {
	store *bruteForceStore
	key   string
}

// bruteForceWriter intercepts WriteHeader to detect failure status codes and
// increment the failure counter.
type bruteForceWriter struct {
	http.ResponseWriter
	store        *bruteForceStore
	key          string
	failureSet   map[int]bool
	once         sync.Once
}

func (bw *bruteForceWriter) WriteHeader(code int) {
	bw.once.Do(func() {
		if bw.failureSet[code] {
			bw.store.mu.Lock()
			entry, ok := bw.store.entries[bw.key]
			if !ok {
				entry = &bruteForceEntry{}
				bw.store.entries[bw.key] = entry
			}
			entry.count++
			if entry.count >= bw.store.max {
				entry.blockedAt = bw.store.nowFunc()
			}
			bw.store.mu.Unlock()
		}
	})
	bw.ResponseWriter.WriteHeader(code)
}

// BruteForceProtect returns middleware that tracks failed response status codes
// and blocks a key after it exceeds MaxAttempts failures. The downstream
// handler's response status is inspected via a wrapped ResponseWriter. Once
// blocked, the key is rejected with a 429 response until the Cooldown expires.
func BruteForceProtect(cfg BruteForceConfig) func(http.Handler) http.Handler {
	keyFunc := cfg.KeyFunc
	if keyFunc == nil {
		keyFunc = IPKey
	}

	failureSet := make(map[int]bool, len(cfg.FailureStatus))
	if len(cfg.FailureStatus) == 0 {
		failureSet[http.StatusUnauthorized] = true
	} else {
		for _, code := range cfg.FailureStatus {
			failureSet[code] = true
		}
	}

	store := &bruteForceStore{
		entries:  make(map[string]*bruteForceEntry),
		nowFunc:  time.Now,
		max:      cfg.MaxAttempts,
		cooldown: cfg.Cooldown,
	}

	return buildBruteForceHandler(cfg, store, failureSet, keyFunc)
}

// buildBruteForceHandler constructs the brute force handler using the given
// store. This is separated from BruteForceProtect so tests can inject a custom
// nowFunc.
func buildBruteForceHandler(cfg BruteForceConfig, store *bruteForceStore, failureSet map[int]bool, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFunc(r)

			store.mu.Lock()
			entry, ok := store.entries[key]
			if ok && entry.count >= store.max {
				elapsed := store.nowFunc().Sub(entry.blockedAt)
				if elapsed < store.cooldown {
					remaining := store.cooldown - elapsed
					retryAfter := max(int(remaining.Seconds()), 1)
					store.mu.Unlock()
					w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
					if cfg.ErrorHandler != nil {
						cfg.ErrorHandler(w, r)
						return
					}
					http.Error(w, "", http.StatusTooManyRequests)
					return
				}
				// Cooldown expired: reset.
				entry.count = 0
				entry.blockedAt = time.Time{}
			}
			store.mu.Unlock()

			// Store tracker on context so ResetFailures can clear the counter.
			r = r.WithContext(context.WithValue(r.Context(), bruteForceCtxKey, &bruteForceCtxValue{
				store: store,
				key:   key,
			}))

			wrapped := &bruteForceWriter{
				ResponseWriter: w,
				store:          store,
				key:            key,
				failureSet:     failureSet,
			}

			next.ServeHTTP(wrapped, r)
		})
	}
}

// ResetFailures clears the failure count for the request's key. Call this on
// successful authentication so the counter resets.
func ResetFailures(r *http.Request) {
	v, ok := r.Context().Value(bruteForceCtxKey).(*bruteForceCtxValue)
	if !ok || v == nil {
		return
	}
	v.store.mu.Lock()
	delete(v.store.entries, v.key)
	v.store.mu.Unlock()
}
