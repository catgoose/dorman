package dorman

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBruteForceWriter_Unwrap(t *testing.T) {
	inner := httptest.NewRecorder()
	w := &bruteForceWriter{ResponseWriter: inner}
	require.Equal(t, http.ResponseWriter(inner), w.Unwrap())
}

func TestBruteForceWriter_Flush_Delegates(t *testing.T) {
	inner := &flusherHijackerRecorder{ResponseWriter: httptest.NewRecorder()}
	w := &bruteForceWriter{ResponseWriter: inner}
	w.Flush()
	require.True(t, inner.flushed)
}

func TestBruteForceWriter_Flush_NoopWhenNotSupported(t *testing.T) {
	inner := newPlainResponseWriter()
	w := &bruteForceWriter{ResponseWriter: inner}
	w.Flush()
}

func TestBruteForceWriter_Hijack_Delegates(t *testing.T) {
	inner := &flusherHijackerRecorder{ResponseWriter: httptest.NewRecorder()}
	w := &bruteForceWriter{ResponseWriter: inner}
	_, _, err := w.Hijack()
	require.NoError(t, err)
	require.True(t, inner.hijacked)
}

func TestBruteForceWriter_Hijack_ErrorWhenNotSupported(t *testing.T) {
	inner := newPlainResponseWriter()
	w := &bruteForceWriter{ResponseWriter: inner}
	_, _, err := w.Hijack()
	require.Error(t, err)
	require.Contains(t, err.Error(), "http.Hijacker")
}

func TestBruteForceWriter_InterfacePreservation_ThroughMiddleware(t *testing.T) {
	inner := &flusherHijackerRecorder{ResponseWriter: httptest.NewRecorder()}

	var capturedWriter http.ResponseWriter
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedWriter = w
		w.WriteHeader(http.StatusOK)
	})

	store := &bruteForceStore{
		entries:  make(map[string]*bruteForceEntry),
		nowFunc:  time.Now,
		max:      5,
		cooldown: time.Minute,
	}
	failureSet := map[int]bool{http.StatusUnauthorized: true}
	mw := buildBruteForceHandler(BruteForceConfig{MaxAttempts: 5, Cooldown: time.Minute}, store, failureSet, IPKey)

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	mw(handler).ServeHTTP(inner, req)

	_, ok := capturedWriter.(http.Flusher)
	require.True(t, ok, "bruteForceWriter should implement http.Flusher")

	_, ok = capturedWriter.(http.Hijacker)
	require.True(t, ok, "bruteForceWriter should implement http.Hijacker")

	rc := http.NewResponseController(capturedWriter)
	require.NotNil(t, rc)
}

// Verify bruteForceWriter still tracks failures correctly with the new methods.
func TestBruteForceWriter_StillTracksFailures(t *testing.T) {
	store := &bruteForceStore{
		entries:  make(map[string]*bruteForceEntry),
		nowFunc:  time.Now,
		max:      2,
		cooldown: time.Minute,
	}
	w := &bruteForceWriter{
		ResponseWriter: httptest.NewRecorder(),
		store:          store,
		key:            "testkey",
		failureSet:     map[int]bool{401: true},
		once:           sync.Once{},
	}
	w.WriteHeader(401)

	store.mu.Lock()
	entry := store.entries["testkey"]
	store.mu.Unlock()

	require.NotNil(t, entry)
	require.Equal(t, 1, entry.count)
}

// okHandler writes a 200 response.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// statusHandler writes the given status code.
func statusHandler(code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	})
}

// fakeNow returns a nowFunc and a function to advance the clock.
func fakeNow() (func() time.Time, func(time.Duration)) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	return func() time.Time { return now },
		func(d time.Duration) { now = now.Add(d) }
}

// --- RateLimit validation tests ---

func TestRateLimit_PanicsOnZeroRequests(t *testing.T) {
	require.PanicsWithValue(t, "dorman: RateLimitConfig.Requests must be greater than zero", func() {
		RateLimit(RateLimitConfig{Requests: 0, Window: time.Minute})
	})
}

func TestRateLimit_PanicsOnZeroWindow(t *testing.T) {
	require.PanicsWithValue(t, "dorman: RateLimitConfig.Window must be greater than zero", func() {
		RateLimit(RateLimitConfig{Requests: 5, Window: 0})
	})
}

func TestRateLimit_PanicsOnInvalidPerPathRequests(t *testing.T) {
	require.Panics(t, func() {
		RateLimit(RateLimitConfig{
			Requests: 5,
			Window:   time.Minute,
			PerPath: map[string]RateRule{
				"/api": {Requests: 0, Window: time.Minute},
			},
		})
	})
}

func TestRateLimit_PanicsOnInvalidPerPathWindow(t *testing.T) {
	require.Panics(t, func() {
		RateLimit(RateLimitConfig{
			Requests: 5,
			Window:   time.Minute,
			PerPath: map[string]RateRule{
				"/api": {Requests: 10, Window: 0},
			},
		})
	})
}

// --- BruteForceProtect validation tests ---

func TestBruteForceProtect_PanicsOnZeroMaxAttempts(t *testing.T) {
	require.PanicsWithValue(t, "dorman: BruteForceConfig.MaxAttempts must be greater than zero", func() {
		BruteForceProtect(BruteForceConfig{MaxAttempts: 0, Cooldown: time.Minute})
	})
}

func TestBruteForceProtect_PanicsOnZeroCooldown(t *testing.T) {
	require.PanicsWithValue(t, "dorman: BruteForceConfig.Cooldown must be greater than zero", func() {
		BruteForceProtect(BruteForceConfig{MaxAttempts: 5, Cooldown: 0})
	})
}

// --- RateLimit tests ---

func TestRateLimit_UnderLimit_Passes(t *testing.T) {
	mw, stop := RateLimit(RateLimitConfig{Requests: 5, Window: time.Minute})
	defer stop()
	handler := mw(okHandler())

	for range 5 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestRateLimit_AtLimit_Blocks(t *testing.T) {
	mw, stop := RateLimit(RateLimitConfig{Requests: 2, Window: time.Minute})
	defer stop()
	handler := mw(okHandler())

	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestRateLimit_RetryAfterHeader(t *testing.T) {
	nowFn, advance := fakeNow()
	cfg := RateLimitConfig{Requests: 1, Window: time.Minute}
	store := &rateLimitStore{
		windows: make(map[string]*window),
		nowFunc: nowFn,
		done:    make(chan struct{}),
	}

	handler := buildRateLimitHandler(cfg, store, nil, IPKey)(okHandler())

	// First request passes.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Advance 20 seconds, second request should be blocked.
	advance(20 * time.Second)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, "40", rec.Header().Get("Retry-After"))
}

func TestRateLimit_WindowResets(t *testing.T) {
	nowFn, advance := fakeNow()
	cfg := RateLimitConfig{Requests: 1, Window: time.Minute}
	store := &rateLimitStore{
		windows: make(map[string]*window),
		nowFunc: nowFn,
		done:    make(chan struct{}),
	}

	handler := buildRateLimitHandler(cfg, store, nil, IPKey)(okHandler())

	// First request passes.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Second request blocked.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	// Advance past window, should reset.
	advance(61 * time.Second)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRateLimit_PerPath_Override(t *testing.T) {
	mw, stop := RateLimit(RateLimitConfig{
		Requests: 10,
		Window:   time.Minute,
		PerPath: map[string]RateRule{
			"/login": {Requests: 1, Window: time.Minute},
		},
	})
	defer stop()
	handler := mw(okHandler())

	// First request to /login passes.
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Second request to /login blocked.
	req = httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	// Default path still has room.
	req = httptest.NewRequest(http.MethodGet, "/other", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRateLimit_ExemptPaths_Bypass(t *testing.T) {
	mw, stop := RateLimit(RateLimitConfig{
		Requests:    1,
		Window:      time.Minute,
		ExemptPaths: []string{"/health"},
	})
	defer stop()
	handler := mw(okHandler())

	// Exhaust limit on normal path.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Exempt path always passes.
	for range 5 {
		req = httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestRateLimit_ExemptPaths_PrefixMatch(t *testing.T) {
	mw, stop := RateLimit(RateLimitConfig{
		Requests:    1,
		Window:      time.Minute,
		ExemptPaths: []string{"/public/"},
	})
	defer stop()
	handler := mw(okHandler())

	// Exhaust limit on normal path.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Paths under /public/ are exempt via prefix match.
	for _, p := range []string{"/public/js/htmx.min.js", "/public/css/style.css", "/public/"} {
		req = httptest.NewRequest(http.MethodGet, p, nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, "expected exempt for %s", p)
	}

	// Non-matching path is still rate limited.
	req = httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestRateLimit_ExemptFunc_Bypass(t *testing.T) {
	mw, stop := RateLimit(RateLimitConfig{
		Requests: 1,
		Window:   time.Minute,
		ExemptFunc: func(r *http.Request) bool {
			return r.Header.Get("X-API-Key") == "secret"
		},
	})
	defer stop()
	handler := mw(okHandler())

	// Exhaust limit.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Without key, blocked.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	// With key, passes.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-API-Key", "secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRateLimit_CustomErrorHandler(t *testing.T) {
	var called bool
	mw, stop := RateLimit(RateLimitConfig{
		Requests: 1,
		Window:   time.Minute,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("custom: rate limited"))
		},
	})
	defer stop()
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.True(t, called)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, "custom: rate limited", rec.Body.String())
}

func TestRateLimit_DefaultKeyFunc_UsesIP(t *testing.T) {
	mw, stop := RateLimit(RateLimitConfig{Requests: 1, Window: time.Minute})
	defer stop()
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Same IP, different port: blocked.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5678"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestRateLimit_DifferentKeys_IndependentLimits(t *testing.T) {
	mw, stop := RateLimit(RateLimitConfig{Requests: 1, Window: time.Minute})
	defer stop()
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Different IP: should pass independently.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// First IP is still blocked.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}

// --- IPKey edge-case tests ---

func TestIPKey_RemoteAddr_NoPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1" // no port — net.SplitHostPort fails
	require.Equal(t, "192.168.1.1", IPKey(req))
}

func TestIPKey_RemoteAddr_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ""
	require.Equal(t, "", IPKey(req))
}

func TestIPKey_RemoteAddr_IPv6_WithPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::1]:8080"
	require.Equal(t, "::1", IPKey(req))
}

func TestIPKey_RemoteAddr_IPv6_NoPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "::1" // bare IPv6 — SplitHostPort fails
	require.Equal(t, "::1", IPKey(req))
}

func TestIPKey_RemoteAddr_IPv6_Full(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[2001:db8::1]:443"
	require.Equal(t, "2001:db8::1", IPKey(req))
}

func TestIPKey_XForwardedFor_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "")
	req.RemoteAddr = "10.0.0.1:1234"
	// Empty header value — should fall through to RemoteAddr.
	require.Equal(t, "10.0.0.1", IPKey(req))
}

func TestIPKey_XForwardedFor_Whitespace(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "  ,10.0.0.2")
	req.RemoteAddr = "10.0.0.99:1234"
	// First element after split is whitespace-only → trimmed to "".
	// Since ip == "", the empty check triggers and falls through to
	// X-Real-IP / RemoteAddr.
	require.Equal(t, "10.0.0.99", IPKey(req))
}

func TestIPKey_XRealIP_Whitespace(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "  198.51.100.5  ")
	req.RemoteAddr = "10.0.0.99:1234"
	require.Equal(t, "198.51.100.5", IPKey(req))
}

// --- IPKey tests ---

func TestIPKey_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.1")
	req.RemoteAddr = "10.0.0.99:1234"
	require.Equal(t, "203.0.113.1", IPKey(req))
}

func TestIPKey_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "198.51.100.5")
	req.RemoteAddr = "10.0.0.99:1234"
	require.Equal(t, "198.51.100.5", IPKey(req))
}

func TestIPKey_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:8080"
	require.Equal(t, "192.168.1.1", IPKey(req))
}

// --- BruteForceProtect tests ---

func TestBruteForceProtect_UnderThreshold_Passes(t *testing.T) {
	mw, stop := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 3,
		Cooldown:    time.Minute,
	})
	defer stop()
	handler := mw(statusHandler(http.StatusUnauthorized))

	// Two failures should not block.
	for range 2 {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	}

	// Third attempt still reaches the handler (failure is counted on response).
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestBruteForceProtect_AtThreshold_Blocks(t *testing.T) {
	mw, stop := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 2,
		Cooldown:    time.Minute,
	})
	defer stop()
	handler := mw(statusHandler(http.StatusUnauthorized))

	// Trigger 2 failures.
	for range 2 {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	}

	// Next request should be blocked before reaching handler.
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestBruteForceProtect_CooldownExpires_Unblocks(t *testing.T) {
	nowFn, advance := fakeNow()
	cfg := BruteForceConfig{
		MaxAttempts: 1,
		Cooldown:    time.Minute,
	}

	store := &bruteForceStore{
		entries:  make(map[string]*bruteForceEntry),
		nowFunc:  nowFn,
		max:      cfg.MaxAttempts,
		cooldown: cfg.Cooldown,
		done:     make(chan struct{}),
	}

	handler := buildBruteForceHandler(cfg, store, map[int]bool{http.StatusUnauthorized: true}, IPKey)(statusHandler(http.StatusUnauthorized))

	// One failure triggers block.
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	// Blocked.
	req = httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	// Advance past cooldown.
	advance(61 * time.Second)
	req = httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestBruteForceProtect_SuccessDoesNotCount(t *testing.T) {
	mw, stop := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 2,
		Cooldown:    time.Minute,
	})
	defer stop()
	handler := mw(statusHandler(http.StatusOK))

	// 200 responses should not count as failures.
	for range 5 {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestBruteForceProtect_CustomFailureStatus(t *testing.T) {
	mw, stop := BruteForceProtect(BruteForceConfig{
		MaxAttempts:   1,
		Cooldown:      time.Minute,
		FailureStatus: []int{http.StatusForbidden},
	})
	defer stop()
	handler := mw(statusHandler(http.StatusForbidden))

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)

	// Should be blocked now.
	req = httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestBruteForceProtect_CustomErrorHandler(t *testing.T) {
	var called bool
	mw, stop := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 1,
		Cooldown:    time.Minute,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("custom: blocked"))
		},
	})
	defer stop()
	handler := mw(statusHandler(http.StatusUnauthorized))

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	req = httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.True(t, called)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, "custom: blocked", rec.Body.String())
}

func TestBruteForceProtect_RetryAfterHeader(t *testing.T) {
	nowFn, advance := fakeNow()
	cfg := BruteForceConfig{
		MaxAttempts: 1,
		Cooldown:    time.Minute,
	}

	store := &bruteForceStore{
		entries:  make(map[string]*bruteForceEntry),
		nowFunc:  nowFn,
		max:      cfg.MaxAttempts,
		cooldown: cfg.Cooldown,
		done:     make(chan struct{}),
	}

	handler := buildBruteForceHandler(cfg, store, map[int]bool{http.StatusUnauthorized: true}, IPKey)(statusHandler(http.StatusUnauthorized))

	// One failure.
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	// Advance 15 seconds, then check Retry-After.
	advance(15 * time.Second)
	req = httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, "45", rec.Header().Get("Retry-After"))
}

func TestResetFailures_ClearsCounter(t *testing.T) {
	mw, stop := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 2,
		Cooldown:    time.Minute,
	})
	defer stop()

	// Handler that returns 401, but on the third call, returns 200 and resets.
	callCount := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 3 {
			ResetFailures(r)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	handler := mw(inner)

	// Two failures.
	for range 2 {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	}

	// Blocked.
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	// Hmm, we need to test ResetFailures differently since we're blocked.
	// Reset callCount and test with a flow that resets before blocking.
	callCount = 0

	// Use a fresh middleware instance.
	mw2, stop2 := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 3,
		Cooldown:    time.Minute,
	})
	defer stop2()
	callCount2 := 0
	inner2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount2++
		if callCount2 == 2 {
			// Successful login: reset counter.
			ResetFailures(r)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	handler2 := mw2(inner2)

	// First attempt: failure.
	req = httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler2.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	// Second attempt: success + reset.
	req = httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler2.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Third and fourth: two more failures should be fine (counter was reset).
	for range 2 {
		req = httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec = httptest.NewRecorder()
		handler2.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	}

	// Fifth: would be the 3rd failure post-reset, so still not blocked
	// (reaches handler but triggers block).
	req = httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler2.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	// Sixth: now blocked.
	req = httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler2.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}

// TestBruteForceProtect_ImplicitOK_NoWriteHeader verifies that a handler which
// writes a body without calling WriteHeader explicitly (Go implicitly sends 200)
// does not count as a failure. The bruteForceWriter's WriteHeader is only called
// when the handler (or Go's implicit flush) triggers it, so implicit 200 should
// behave the same as an explicit 200.
func TestBruteForceProtect_ImplicitOK_NoWriteHeader(t *testing.T) {
	mw, stop := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 1,
		Cooldown:    time.Minute,
	})
	defer stop()
	// Handler writes a body without calling WriteHeader — Go sends 200 implicitly.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	handler := mw(inner)

	// Multiple requests should all succeed because implicit 200 is not a failure.
	for range 5 {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, "ok", rec.Body.String())
	}
}

// TestBruteForceProtect_ImplicitOK_ThenFailure verifies that implicit 200
// responses don't interfere with subsequent real failures being tracked.
func TestBruteForceProtect_ImplicitOK_ThenFailure(t *testing.T) {
	callCount := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 2 {
			// First two calls: write body without explicit WriteHeader (implicit 200).
			_, _ = w.Write([]byte("ok"))
			return
		}
		// Subsequent calls: explicit 401.
		w.WriteHeader(http.StatusUnauthorized)
	})

	mw, stop := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 1,
		Cooldown:    time.Minute,
	})
	defer stop()
	handler := mw(inner)

	// Two implicit-200 requests should not count as failures.
	for range 2 {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	}

	// Third request returns 401 — counts as failure.
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	// Fourth request should be blocked.
	req = httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}

// --- Eviction tests ---

func TestRateLimitStore_Evict_RemovesExpiredWindows(t *testing.T) {
	nowFn, advance := fakeNow()
	store := &rateLimitStore{
		windows: make(map[string]*window),
		nowFunc: nowFn,
		done:    make(chan struct{}),
	}

	// Seed two windows: one just started, one already old.
	store.windows["fresh"] = &window{count: 1, start: nowFn()}
	advance(2 * time.Minute)
	store.windows["recent"] = &window{count: 1, start: nowFn()}

	// Evict with a 1-minute window. "fresh" started 2 minutes ago, so it
	// should be removed. "recent" started at the current fake time, so it
	// should remain.
	store.evict(time.Minute)

	require.NotContains(t, store.windows, "fresh")
	require.Contains(t, store.windows, "recent")
}

func TestRateLimitStore_Stop_TerminatesGoroutine(t *testing.T) {
	store := &rateLimitStore{
		windows: make(map[string]*window),
		nowFunc: time.Now,
		done:    make(chan struct{}),
	}

	store.startCleanup(50*time.Millisecond, time.Nanosecond)

	// Add an entry that is already expired.
	store.mu.Lock()
	store.windows["old"] = &window{count: 1, start: time.Now().Add(-time.Hour)}
	store.mu.Unlock()

	// Give the goroutine time to run at least one tick.
	time.Sleep(150 * time.Millisecond)

	store.mu.Lock()
	_, exists := store.windows["old"]
	store.mu.Unlock()
	require.False(t, exists, "expired entry should have been evicted")

	// Stop should not panic even when called twice.
	store.stop()
	store.stop()
}

func TestBruteForceStore_Evict_RemovesExpiredEntries(t *testing.T) {
	nowFn, advance := fakeNow()
	store := &bruteForceStore{
		entries:  make(map[string]*bruteForceEntry),
		nowFunc:  nowFn,
		max:      3,
		cooldown: time.Minute,
		done:     make(chan struct{}),
	}

	// blocked entry whose cooldown has expired.
	store.entries["expired"] = &bruteForceEntry{count: 3, blockedAt: nowFn()}
	advance(2 * time.Minute)

	// blocked entry whose cooldown has NOT expired.
	store.entries["active"] = &bruteForceEntry{count: 3, blockedAt: nowFn()}

	// entry below max (not blocked) with recent activity should NOT be removed.
	store.entries["partial"] = &bruteForceEntry{count: 1, lastSeen: nowFn()}

	store.evict()

	require.NotContains(t, store.entries, "expired")
	require.Contains(t, store.entries, "active")
	require.Contains(t, store.entries, "partial")
}

func TestBruteForceStore_Evict_RemovesStaleSubThresholdEntries(t *testing.T) {
	nowFn, advance := fakeNow()
	store := &bruteForceStore{
		entries:  make(map[string]*bruteForceEntry),
		nowFunc:  nowFn,
		max:      5,
		cooldown: time.Minute,
		done:     make(chan struct{}),
	}

	// Sub-threshold entry last seen at the start.
	store.entries["stale"] = &bruteForceEntry{count: 2, lastSeen: nowFn()}

	// Advance past cooldown.
	advance(2 * time.Minute)

	store.evict()

	require.NotContains(t, store.entries, "stale",
		"sub-threshold entry idle past cooldown should be evicted")
}

func TestBruteForceStore_Evict_KeepsActiveSubThresholdEntries(t *testing.T) {
	nowFn, advance := fakeNow()
	store := &bruteForceStore{
		entries:  make(map[string]*bruteForceEntry),
		nowFunc:  nowFn,
		max:      5,
		cooldown: time.Minute,
		done:     make(chan struct{}),
	}

	// Sub-threshold entry last seen 30 seconds ago (within cooldown).
	advance(30 * time.Second)
	store.entries["recent"] = &bruteForceEntry{count: 2, lastSeen: nowFn()}
	advance(20 * time.Second) // total 50 seconds from start, 20 seconds since lastSeen

	store.evict()

	require.Contains(t, store.entries, "recent",
		"sub-threshold entry still within cooldown should not be evicted")
}

func TestBruteForceStore_Evict_BlockedEntriesStillEvictCorrectly(t *testing.T) {
	nowFn, advance := fakeNow()
	store := &bruteForceStore{
		entries:  make(map[string]*bruteForceEntry),
		nowFunc:  nowFn,
		max:      3,
		cooldown: time.Minute,
		done:     make(chan struct{}),
	}

	// Blocked entry whose cooldown has expired.
	store.entries["blocked-expired"] = &bruteForceEntry{
		count: 3, blockedAt: nowFn(), lastSeen: nowFn(),
	}

	// Blocked entry whose cooldown has NOT expired.
	advance(30 * time.Second)
	store.entries["blocked-active"] = &bruteForceEntry{
		count: 3, blockedAt: nowFn(), lastSeen: nowFn(),
	}

	advance(45 * time.Second) // 75s from start; blocked-expired is 75s old, blocked-active is 45s old

	store.evict()

	require.NotContains(t, store.entries, "blocked-expired",
		"blocked entry past cooldown should be evicted")
	require.Contains(t, store.entries, "blocked-active",
		"blocked entry within cooldown should not be evicted")
}

func TestBruteForceStore_Stop_TerminatesGoroutine(t *testing.T) {
	store := &bruteForceStore{
		entries:  make(map[string]*bruteForceEntry),
		nowFunc:  time.Now,
		max:      1,
		cooldown: time.Nanosecond,
		done:     make(chan struct{}),
	}

	store.startCleanup(50 * time.Millisecond)

	// Add an entry that is already expired.
	store.mu.Lock()
	store.entries["old"] = &bruteForceEntry{count: 1, blockedAt: time.Now().Add(-time.Hour)}
	store.mu.Unlock()

	// Give the goroutine time to run at least one tick.
	time.Sleep(150 * time.Millisecond)

	store.mu.Lock()
	_, exists := store.entries["old"]
	store.mu.Unlock()
	require.False(t, exists, "expired entry should have been evicted")

	store.stop()
	store.stop() // safe to call twice
}

func TestRateLimit_CleanupInterval_Config(t *testing.T) {
	mw, stop := RateLimit(RateLimitConfig{
		Requests:        1,
		Window:          time.Minute,
		CleanupInterval: 30 * time.Second,
	})
	defer stop()

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestBruteForce_CleanupInterval_Config(t *testing.T) {
	mw, stop := BruteForceProtect(BruteForceConfig{
		MaxAttempts:     3,
		Cooldown:        time.Minute,
		CleanupInterval: 30 * time.Second,
	})
	defer stop()

	handler := mw(statusHandler(http.StatusOK))
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}
