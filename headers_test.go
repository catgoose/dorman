package porter

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// runSecurityHeaders applies the middleware and returns the recorded response headers.
func runSecurityHeaders(t *testing.T, mw func(http.Handler) http.Handler) http.Header {
	t.Helper()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Header()
}

func TestSecurityHeaders_NoArgs_UsesDefaults(t *testing.T) {
	h := runSecurityHeaders(t, SecurityHeaders())

	require.Equal(t, "SAMEORIGIN", h.Get("X-Frame-Options"))
	require.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	require.Equal(t, "0", h.Get("X-XSS-Protection"))
	require.Equal(t, "strict-origin-when-cross-origin", h.Get("Referrer-Policy"))
	require.Empty(t, h.Get("Strict-Transport-Security"), "HSTS should be disabled by default")
	require.Equal(t, "camera=(), microphone=(), geolocation=(), payment=(), usb=()", h.Get("Permissions-Policy"))
	require.Equal(t, "same-origin", h.Get("Cross-Origin-Opener-Policy"))
	require.Empty(t, h.Get("Content-Security-Policy"))
}

func TestSecurityHeaders_DefaultConfig_SetsAllExpectedHeaders(t *testing.T) {
	h := runSecurityHeaders(t, SecurityHeaders(DefaultSecurityHeadersConfig()))

	require.Equal(t, "SAMEORIGIN", h.Get("X-Frame-Options"))
	require.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	require.Equal(t, "0", h.Get("X-XSS-Protection"))
	require.Equal(t, "strict-origin-when-cross-origin", h.Get("Referrer-Policy"))
	require.Empty(t, h.Get("Strict-Transport-Security"), "HSTS should be disabled by default")
	require.Equal(t, "camera=(), microphone=(), geolocation=(), payment=(), usb=()", h.Get("Permissions-Policy"))
	require.Equal(t, "same-origin", h.Get("Cross-Origin-Opener-Policy"))
}

func TestSecurityHeaders_CustomConfig_OverridesIndividualHeaders(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()
	cfg.XFrameOptions = "DENY"
	cfg.ReferrerPolicy = "no-referrer"
	cfg.CrossOriginOpenerPolicy = "same-origin-allow-popups"

	h := runSecurityHeaders(t, SecurityHeaders(cfg))

	require.Equal(t, "DENY", h.Get("X-Frame-Options"))
	require.Equal(t, "no-referrer", h.Get("Referrer-Policy"))
	require.Equal(t, "same-origin-allow-popups", h.Get("Cross-Origin-Opener-Policy"))
	// Unchanged defaults still present.
	require.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	require.Equal(t, "0", h.Get("X-XSS-Protection"))
}

func TestSecurityHeaders_EmptyString_OmitsHeader(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()
	cfg.XFrameOptions = ""
	cfg.XXSSProtection = ""
	cfg.PermissionsPolicy = ""

	h := runSecurityHeaders(t, SecurityHeaders(cfg))

	require.Empty(t, h.Get("X-Frame-Options"))
	require.Empty(t, h.Get("X-XSS-Protection"))
	require.Empty(t, h.Get("Permissions-Policy"))
	// Others still set.
	require.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
}

func TestSecurityHeaders_HSTS_Nil_OmitsHeader(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()
	cfg.HSTS = nil

	h := runSecurityHeaders(t, SecurityHeaders(cfg))

	require.Empty(t, h.Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_HSTS_OptIn_WithDefaultHSTSConfig(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()
	cfg.HSTS = DefaultHSTSConfig()

	h := runSecurityHeaders(t, SecurityHeaders(cfg))

	require.Equal(t, "max-age=63072000; includeSubDomains", h.Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_HSTS_WithPreload(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()
	cfg.HSTS = &HSTSConfig{MaxAge: 31536000, IncludeSubDomains: true, Preload: true}

	h := runSecurityHeaders(t, SecurityHeaders(cfg))

	require.Equal(t, "max-age=31536000; includeSubDomains; preload", h.Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_HSTS_WithoutIncludeSubDomains(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()
	cfg.HSTS = &HSTSConfig{MaxAge: 86400, IncludeSubDomains: false, Preload: false}

	h := runSecurityHeaders(t, SecurityHeaders(cfg))

	require.Equal(t, "max-age=86400", h.Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_HSTS_WithPreloadNoSubDomains(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()
	cfg.HSTS = &HSTSConfig{MaxAge: 63072000, IncludeSubDomains: false, Preload: true}

	h := runSecurityHeaders(t, SecurityHeaders(cfg))

	require.Equal(t, "max-age=63072000; preload", h.Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_CSP_SetToValue(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()
	cfg.ContentSecurityPolicy = "default-src 'self'; script-src 'self' 'nonce-abc123'"

	h := runSecurityHeaders(t, SecurityHeaders(cfg))

	require.Equal(t, "default-src 'self'; script-src 'self' 'nonce-abc123'", h.Get("Content-Security-Policy"))
}

func TestSecurityHeaders_HeadersPresentOnResponse(t *testing.T) {
	mw := SecurityHeaders()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "hello", rec.Body.String())
	require.NotEmpty(t, rec.Header().Get("X-Frame-Options"))
	require.NotEmpty(t, rec.Header().Get("X-Content-Type-Options"))
	require.Empty(t, rec.Header().Get("Strict-Transport-Security"), "HSTS should be disabled by default")
}

func TestSecurityHeaders_ZeroValueHSTSMaxAge_UsesDefault(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()
	cfg.HSTS = &HSTSConfig{MaxAge: 0, IncludeSubDomains: true, Preload: false}

	h := runSecurityHeaders(t, SecurityHeaders(cfg))

	// MaxAge of 0 falls back to the 2-year default.
	require.Equal(t, "max-age=63072000; includeSubDomains", h.Get("Strict-Transport-Security"))
}
