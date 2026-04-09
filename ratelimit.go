package dorman

import (
	"bufio"
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
	// ExemptPaths lists path prefixes that bypass rate limiting entirely. A
	// request is exempt when its path starts with any of the listed prefixes.
	// For example, "/public/" exempts "/public/js/htmx.min.js".
	ExemptPaths []string
	// ExemptFunc is a custom function that, when it returns true, bypasses rate
	// limiting for the request.
	ExemptFunc func(*http.Request) bool
	// ErrorHandler is called when a request is rate limited. When nil, a bare
	// 429 Too Many Requests response is written with a Retry-After header.
	ErrorHandler func(http.ResponseWriter, *http.Request)
	// CleanupInterval is how often the background goroutine removes expired
	// entries from the in-memory store. When zero, it defaults to Window.
	CleanupInterval time.Duration
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
	done    chan struct{}
}

// startCleanup launches a background goroutine that periodically removes
// expired windows from the store. It uses the store's nowFunc so tests can
// control time. The goroutine stops when done is closed.
func (s *rateLimitStore) startCleanup(interval, window time.Duration) {
	// Determine the longest window to use when PerPath rules exist; callers
	// pass the maximum across all rules.
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				s.evict(window)
			}
		}
	}()
}

// evict removes windows that have expired relative to the given duration.
func (s *rateLimitStore) evict(window time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFunc()
	for key, w := range s.windows {
		if now.Sub(w.start) >= window {
			delete(s.windows, key)
		}
	}
}

// stop signals the cleanup goroutine to exit.
func (s *rateLimitStore) stop() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

// RateLimit returns middleware that enforces fixed-window rate limiting. Each
// unique key (by default the client IP) is allowed a configured number of
// requests per time window. Requests that exceed the limit receive a 429
// response with a Retry-After header indicating when the window resets.
//
// A background goroutine periodically evicts expired entries from the
// in-memory store. Call the returned stop function to terminate the goroutine
// (e.g. on graceful shutdown).
func RateLimit(cfg RateLimitConfig) (mw func(http.Handler) http.Handler, stop func()) {
	if cfg.Requests <= 0 {
		panic("dorman: RateLimitConfig.Requests must be greater than zero")
	}
	if cfg.Window <= 0 {
		panic("dorman: RateLimitConfig.Window must be greater than zero")
	}
	for path, rule := range cfg.PerPath {
		if rule.Requests <= 0 {
			panic(fmt.Sprintf("dorman: RateLimitConfig.PerPath[%q].Requests must be greater than zero", path))
		}
		if rule.Window <= 0 {
			panic(fmt.Sprintf("dorman: RateLimitConfig.PerPath[%q].Window must be greater than zero", path))
		}
	}

	keyFunc := cfg.KeyFunc
	if keyFunc == nil {
		keyFunc = IPKey
	}

	exemptPrefixes := make([]string, len(cfg.ExemptPaths))
	copy(exemptPrefixes, cfg.ExemptPaths)

	store := &rateLimitStore{
		windows: make(map[string]*window),
		nowFunc: time.Now,
		done:    make(chan struct{}),
	}

	cleanupInterval := cfg.CleanupInterval
	if cleanupInterval == 0 {
		cleanupInterval = cfg.Window
	}

	// Find the maximum window duration across all rules so the cleanup
	// goroutine does not evict entries from longer-lived PerPath rules.
	maxWindow := cfg.Window
	for _, rule := range cfg.PerPath {
		if rule.Window > maxWindow {
			maxWindow = rule.Window
		}
	}

	store.startCleanup(cleanupInterval, maxWindow)

	return buildRateLimitHandler(cfg, store, exemptPrefixes, keyFunc), store.stop
}

// buildRateLimitHandler constructs the rate limiting handler using the given
// store. This is separated from RateLimit so tests can inject a custom nowFunc.
func buildRateLimitHandler(cfg RateLimitConfig, store *rateLimitStore, exemptPrefixes []string, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, prefix := range exemptPrefixes {
				if strings.HasPrefix(r.URL.Path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
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
	// CleanupInterval is how often the background goroutine removes expired
	// entries from the in-memory store. When zero, it defaults to Cooldown.
	CleanupInterval time.Duration
}

// bruteForceEntry tracks failure attempts for a single key.
type bruteForceEntry struct {
	count     int
	blockedAt time.Time
	lastSeen  time.Time
}

// bruteForceStore holds the internal state for brute force protection.
type bruteForceStore struct {
	mu       sync.Mutex
	entries  map[string]*bruteForceEntry
	nowFunc  func() time.Time
	max      int
	cooldown time.Duration
	done     chan struct{}
}

// startCleanup launches a background goroutine that periodically removes
// expired entries from the store. An entry is considered expired when its
// cooldown has elapsed (if it was blocked) or when its blockedAt is zero
// and it has been sitting idle (entries that never reached max are removed
// after the cooldown duration as a conservative upper bound).
func (s *bruteForceStore) startCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				s.evict()
			}
		}
	}()
}

// evict removes brute force entries whose cooldown has expired. Blocked entries
// are evicted once the cooldown elapses from blockedAt. Sub-threshold entries
// that have been idle (no new failures) longer than the cooldown are also
// evicted to prevent unbounded memory growth.
func (s *bruteForceStore) evict() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFunc()
	for key, entry := range s.entries {
		if entry.count >= s.max && !entry.blockedAt.IsZero() {
			if now.Sub(entry.blockedAt) >= s.cooldown {
				delete(s.entries, key)
			}
		} else if entry.count < s.max && !entry.lastSeen.IsZero() {
			if now.Sub(entry.lastSeen) >= s.cooldown {
				delete(s.entries, key)
			}
		}
	}
}

// stop signals the cleanup goroutine to exit.
func (s *bruteForceStore) stop() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
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
// increment the failure counter. Failures are only counted against the first
// committed status: if a handler writes body bytes before calling WriteHeader,
// the effective status is 200 OK (per net/http), so a late WriteHeader(401)
// must not count.
type bruteForceWriter struct {
	http.ResponseWriter
	store      *bruteForceStore
	key        string
	failureSet map[int]bool
	once       sync.Once
	committed  bool
}

// recordFailure increments the counter for the wrapped key. It is only called
// when the committed status matches the failure set.
func (bw *bruteForceWriter) recordFailure() {
	bw.store.mu.Lock()
	entry, ok := bw.store.entries[bw.key]
	if !ok {
		entry = &bruteForceEntry{}
		bw.store.entries[bw.key] = entry
	}
	now := bw.store.nowFunc()
	entry.count++
	entry.lastSeen = now
	if entry.count >= bw.store.max {
		entry.blockedAt = now
	}
	bw.store.mu.Unlock()
}

func (bw *bruteForceWriter) WriteHeader(code int) {
	bw.once.Do(func() {
		// This is the first status to be committed. Record it and, if it is
		// a failure status, count it.
		bw.committed = true
		if bw.failureSet[code] {
			bw.recordFailure()
		}
	})
	bw.ResponseWriter.WriteHeader(code)
}

// Write commits an implicit 200 OK when no explicit status has been written.
// Subsequent WriteHeader calls are still forwarded to the underlying writer
// (net/http ignores them) but will not change brute-force accounting.
func (bw *bruteForceWriter) Write(b []byte) (int, error) {
	bw.once.Do(func() {
		// First write with no explicit status: commit effective status 200.
		// 200 is not a failure, so no counter update is needed.
		bw.committed = true
	})
	return bw.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter so that [http.NewResponseController]
// can access optional interfaces on the original writer.
func (bw *bruteForceWriter) Unwrap() http.ResponseWriter {
	return bw.ResponseWriter
}

// Flush delegates to the underlying ResponseWriter if it implements [http.Flusher].
func (bw *bruteForceWriter) Flush() {
	if f, ok := bw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack delegates to the underlying ResponseWriter if it implements [http.Hijacker].
func (bw *bruteForceWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := bw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("dorman: underlying ResponseWriter does not implement http.Hijacker")
}

// Push delegates to the underlying ResponseWriter if it implements [http.Pusher].
// When the underlying writer does not support HTTP/2 server push, it returns
// [http.ErrNotSupported] to match the standard library pattern.
func (bw *bruteForceWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := bw.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// BruteForceProtect returns middleware that tracks failed response status codes
// and blocks a key after it exceeds MaxAttempts failures. The downstream
// handler's response status is inspected via a wrapped ResponseWriter. Once
// blocked, the key is rejected with a 429 response until the Cooldown expires.
//
// A background goroutine periodically evicts expired entries from the
// in-memory store. Call the returned stop function to terminate the goroutine
// (e.g. on graceful shutdown).
func BruteForceProtect(cfg BruteForceConfig) (mw func(http.Handler) http.Handler, stop func()) {
	if cfg.MaxAttempts <= 0 {
		panic("dorman: BruteForceConfig.MaxAttempts must be greater than zero")
	}
	if cfg.Cooldown <= 0 {
		panic("dorman: BruteForceConfig.Cooldown must be greater than zero")
	}

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
		done:     make(chan struct{}),
	}

	cleanupInterval := cfg.CleanupInterval
	if cleanupInterval == 0 {
		cleanupInterval = cfg.Cooldown
	}

	store.startCleanup(cleanupInterval)

	return buildBruteForceHandler(cfg, store, failureSet, keyFunc), store.stop
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
