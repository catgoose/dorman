package dorman

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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

// --- RateLimit tests ---

func TestRateLimit_UnderLimit_Passes(t *testing.T) {
	mw := RateLimit(RateLimitConfig{Requests: 5, Window: time.Minute})
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
	mw := RateLimit(RateLimitConfig{Requests: 2, Window: time.Minute})
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
	}

	exemptSet := make(map[string]bool)
	handler := buildRateLimitHandler(cfg, store, exemptSet, IPKey)(okHandler())

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
	}

	exemptSet := make(map[string]bool)
	handler := buildRateLimitHandler(cfg, store, exemptSet, IPKey)(okHandler())

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
	mw := RateLimit(RateLimitConfig{
		Requests: 10,
		Window:   time.Minute,
		PerPath: map[string]RateRule{
			"/login": {Requests: 1, Window: time.Minute},
		},
	})
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
	mw := RateLimit(RateLimitConfig{
		Requests:    1,
		Window:      time.Minute,
		ExemptPaths: []string{"/health"},
	})
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

func TestRateLimit_ExemptFunc_Bypass(t *testing.T) {
	mw := RateLimit(RateLimitConfig{
		Requests: 1,
		Window:   time.Minute,
		ExemptFunc: func(r *http.Request) bool {
			return r.Header.Get("X-API-Key") == "secret"
		},
	})
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
	mw := RateLimit(RateLimitConfig{
		Requests: 1,
		Window:   time.Minute,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("custom: rate limited"))
		},
	})
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
	mw := RateLimit(RateLimitConfig{Requests: 1, Window: time.Minute})
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
	mw := RateLimit(RateLimitConfig{Requests: 1, Window: time.Minute})
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
	mw := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 3,
		Cooldown:    time.Minute,
	})
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
	mw := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 2,
		Cooldown:    time.Minute,
	})
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
	mw := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 2,
		Cooldown:    time.Minute,
	})
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
	mw := BruteForceProtect(BruteForceConfig{
		MaxAttempts:   1,
		Cooldown:      time.Minute,
		FailureStatus: []int{http.StatusForbidden},
	})
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
	mw := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 1,
		Cooldown:    time.Minute,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("custom: blocked"))
		},
	})
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
	mw := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 2,
		Cooldown:    time.Minute,
	})

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
	mw2 := BruteForceProtect(BruteForceConfig{
		MaxAttempts: 3,
		Cooldown:    time.Minute,
	})
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
