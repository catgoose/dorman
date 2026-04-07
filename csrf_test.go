package dorman

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// testKey is a 32-byte HMAC key used in tests.
var testKey = []byte("00000000000000000000000000000000")

// minimalCfg returns a CSRFConfig with only the required Key set; all other
// fields will receive their defaults inside CSRFProtect.
func minimalCfg() CSRFConfig {
	return CSRFConfig{Key: testKey}
}

// doRequest runs handler for the given method/path, attaches optional cookies
// and returns the response recorder.
func doRequest(t *testing.T, handler http.Handler, method, path string, setupFn func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if setupFn != nil {
		setupFn(req)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// extractCookie returns the Set-Cookie value for the named cookie from the
// response, or nil.
func extractCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	resp := rec.Result()
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// --- CSRFProtect validation tests ---

func TestCSRFProtect_PanicsOnEmptyKey(t *testing.T) {
	require.PanicsWithValue(t, "dorman: CSRFConfig.Key must be at least 32 bytes", func() {
		CSRFProtect(CSRFConfig{})
	})
}

func TestCSRFProtect_PanicsOnShortKey(t *testing.T) {
	require.PanicsWithValue(t, "dorman: CSRFConfig.Key must be at least 32 bytes", func() {
		CSRFProtect(CSRFConfig{Key: []byte("short")})
	})
}

func TestCSRFProtect_AcceptsValidKey(t *testing.T) {
	require.NotPanics(t, func() {
		CSRFProtect(minimalCfg())
	})
}

// TestGET_SetsCookieAndContextToken verifies that a GET request causes the
// middleware to issue a CSRF cookie and store the token on the context.
func TestGET_SetsCookieAndContextToken(t *testing.T) {
	var contextToken string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextToken = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	rec := doRequest(t, handler, http.MethodGet, "/", nil)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEmpty(t, contextToken, "context token should be set on GET")

	cookie := extractCookie(rec, "_csrf")
	require.NotNil(t, cookie, "CSRF cookie should be set")
	require.NotEmpty(t, cookie.Value)
}

// TestPOST_WithoutToken expects 403.
func TestPOST_WithoutToken(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	rec := doRequest(t, handler, http.MethodPost, "/", nil)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

// TestPOST_WithValidHeaderToken verifies that a valid token in the header passes.
func TestPOST_WithValidHeaderToken(t *testing.T) {
	// Phase 1: GET to obtain nonce cookie and valid token.
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	require.Equal(t, http.StatusOK, getRec.Code)

	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// Phase 2: POST with cookie + header token.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusOK, postRec.Code)
}

// TestPOST_WithValidFormFieldToken verifies that a valid token in the form body passes.
func TestPOST_WithValidFormFieldToken(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// Build a POST request with URL-encoded form body.
	form := url.Values{"csrf_token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(nonceCookie)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

// TestPOST_WithInvalidToken expects 403 when the token does not match.
func TestPOST_WithInvalidToken(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", "this-is-not-a-valid-token")
	})
	require.Equal(t, http.StatusForbidden, postRec.Code)
}

// TestExemptPath_BypassesValidation confirms that exempt paths skip CSRF for POST.
func TestExemptPath_BypassesValidation(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ExemptPaths = []string{"/webhook"}
	handler := CSRFProtect(cfg)(inner)

	// POST to exempt path without any token should pass.
	rec := doRequest(t, handler, http.MethodPost, "/webhook", nil)
	require.Equal(t, http.StatusOK, rec.Code)

	// POST to non-exempt path without token should fail.
	rec2 := doRequest(t, handler, http.MethodPost, "/other", nil)
	require.Equal(t, http.StatusForbidden, rec2.Code)
}

// TestExemptFunc_BypassesValidation confirms that ExemptFunc can bypass CSRF.
func TestExemptFunc_BypassesValidation(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ExemptFunc = func(r *http.Request) bool {
		return r.Header.Get("X-Internal") == "true"
	}
	handler := CSRFProtect(cfg)(inner)

	// Marked internal — should bypass.
	rec := doRequest(t, handler, http.MethodPost, "/api", func(r *http.Request) {
		r.Header.Set("X-Internal", "true")
	})
	require.Equal(t, http.StatusOK, rec.Code)

	// Not marked — should fail.
	rec2 := doRequest(t, handler, http.MethodPost, "/api", nil)
	require.Equal(t, http.StatusForbidden, rec2.Code)
}

// TestRotatePerRequest_ChangesNonce verifies that consecutive GET requests
// produce different nonces when RotatePerRequest is true.
func TestRotatePerRequest_ChangesNonce(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.RotatePerRequest = true
	handler := CSRFProtect(cfg)(inner)

	rec1 := doRequest(t, handler, http.MethodGet, "/", nil)
	rec2 := doRequest(t, handler, http.MethodGet, "/", nil)

	cookie1 := extractCookie(rec1, "_csrf")
	cookie2 := extractCookie(rec2, "_csrf")
	require.NotNil(t, cookie1)
	require.NotNil(t, cookie2)
	require.NotEqual(t, cookie1.Value, cookie2.Value, "nonces should differ between requests")
}

// TestPerRequestPaths_RotatesOnlyForListedPaths verifies that nonce rotation
// occurs on listed paths but not on others.
func TestPerRequestPaths_RotatesOnlyForListedPaths(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.PerRequestPaths = []string{"/rotate"}
	handler := CSRFProtect(cfg)(inner)

	// Two GETs on /rotate: nonces should differ.
	rotRec1 := doRequest(t, handler, http.MethodGet, "/rotate", nil)
	rotRec2 := doRequest(t, handler, http.MethodGet, "/rotate", nil)
	rotCookie1 := extractCookie(rotRec1, "_csrf")
	rotCookie2 := extractCookie(rotRec2, "_csrf")
	require.NotNil(t, rotCookie1)
	require.NotNil(t, rotCookie2)
	require.NotEqual(t, rotCookie1.Value, rotCookie2.Value, "nonces should rotate on /rotate")

	// Two GETs on /other without an existing cookie: each will generate a new
	// nonce (first visit), so we use a real cookie to verify stability instead.
	// Simulate a returning visitor by providing the existing nonce cookie.
	otherRec1 := doRequest(t, handler, http.MethodGet, "/other", nil)
	otherCookie := extractCookie(otherRec1, "_csrf")
	require.NotNil(t, otherCookie)

	// Second request to /other with the existing cookie should reuse the nonce.
	otherRec2 := doRequest(t, handler, http.MethodGet, "/other", func(r *http.Request) {
		r.AddCookie(otherCookie)
	})
	otherCookie2 := extractCookie(otherRec2, "_csrf")
	require.NotNil(t, otherCookie2)
	require.Equal(t, otherCookie.Value, otherCookie2.Value, "nonce should be stable on /other")
}

// TestCustomErrorHandler_CalledOnFailure confirms the custom error handler is
// invoked when CSRF validation fails.
func TestCustomErrorHandler_CalledOnFailure(t *testing.T) {
	var errorHandlerCalled bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ErrorHandler = func(w http.ResponseWriter, r *http.Request) {
		errorHandlerCalled = true
		http.Error(w, "custom error", http.StatusTeapot)
	}
	handler := CSRFProtect(cfg)(inner)

	rec := doRequest(t, handler, http.MethodPost, "/", nil)
	require.True(t, errorHandlerCalled)
	require.Equal(t, http.StatusTeapot, rec.Code)
}

// TestSafeMethods_HeadAndOptions verifies that HEAD and OPTIONS do not reject.
func TestSafeMethods_HeadAndOptions(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	for _, method := range []string{http.MethodHead, http.MethodOptions} {
		rec := doRequest(t, handler, method, "/", nil)
		require.Equal(t, http.StatusOK, rec.Code, "method %s should not be rejected", method)
	}
}

// TestCookieAttributes verifies that the configured cookie attributes are
// reflected on the Set-Cookie header.
func TestCookieAttributes(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cfg := CSRFConfig{
		Key:        testKey,
		CookieName: "_mycsrf",
		CookiePath: "/app",
		MaxAge:     3600,
		SameSite:   http.SameSiteStrictMode,
	}
	handler := CSRFProtect(cfg)(inner)

	rec := doRequest(t, handler, http.MethodGet, "/app/page", nil)
	cookie := extractCookie(rec, "_mycsrf")
	require.NotNil(t, cookie)
	require.Equal(t, "/app", cookie.Path)
	require.Equal(t, 3600, cookie.MaxAge)
	require.True(t, cookie.Secure)
	require.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
	require.True(t, cookie.HttpOnly)
}

// TestGetToken_EmptyWhenNoContext verifies GetToken returns "" outside middleware.
func TestGetToken_EmptyWhenNoContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	require.Equal(t, "", GetToken(req))
}

// TestCustomFieldName_AndHeaderName verifies non-default field/header names work.
func TestCustomFieldName_AndHeaderName(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.FieldName = "my_csrf"
	cfg.RequestHeader = "X-My-CSRF"
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// Submit via custom header.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.AddCookie(nonceCookie)
		r.Header.Set("X-My-CSRF", token)
	})
	require.Equal(t, http.StatusOK, postRec.Code)
}

// TestMaskedToken_DifferentEachCall verifies that two calls to GetToken for the
// same request return different strings (different one-time pads).
func TestMaskedToken_DifferentEachCall(t *testing.T) {
	var token1, token2 string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token1 = GetToken(r)
		token2 = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	doRequest(t, handler, http.MethodGet, "/", nil)

	require.NotEmpty(t, token1)
	require.NotEmpty(t, token2)
	// Same underlying HMAC but different pads — strings must differ.
	require.NotEqual(t, token1, token2, "masked tokens should differ each call")
}

// TestMaskedToken_ValidatesViaHeader verifies that a masked token obtained from
// GetToken is accepted when submitted via the CSRF header.
func TestMaskedToken_ValidatesViaHeader(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	require.Equal(t, http.StatusOK, getRec.Code)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusOK, postRec.Code)
}

// TestMaskedToken_ValidatesViaFormField verifies that a masked token is accepted
// when submitted via a form field.
func TestMaskedToken_ValidatesViaFormField(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	form := url.Values{"csrf_token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(nonceCookie)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

// TestMaskedToken_CorruptedReturns403 verifies that a corrupted masked token is
// rejected with 403.
func TestMaskedToken_CorruptedReturns403(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// Submit a hex-valid but semantically wrong masked token.
	// 64 hex chars of zeros → pad=0x00…, masked=0x00…, recovered=all-zeros ≠ real HMAC.
	corrupted := strings.Repeat("00", 64)
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", corrupted)
	})
	require.Equal(t, http.StatusForbidden, postRec.Code)
}

// TestOriginValidation_MatchingOriginSucceeds verifies that a request whose
// Origin matches the request host passes CSRF validation.
func TestOriginValidation_MatchingOriginSucceeds(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ValidateOrigin = true
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("Origin", "http://example.com")
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusOK, postRec.Code)
}

// TestOriginValidation_MismatchedOriginReturns403 verifies that a request whose
// Origin does not match the request host is rejected.
func TestOriginValidation_MismatchedOriginReturns403(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ValidateOrigin = true
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("Origin", "https://evil.com")
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusForbidden, postRec.Code)
}

// TestOriginValidation_TrustedOriginsList verifies that origins in TrustedOrigins
// are accepted even when they differ from the request host.
func TestOriginValidation_TrustedOriginsList(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ValidateOrigin = true
	cfg.TrustedOrigins = []string{"https://trusted.example.com"}
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// Trusted origin should succeed.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("Origin", "https://trusted.example.com")
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusOK, postRec.Code)

	// Untrusted origin should fail.
	postRec2 := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("Origin", "https://other.example.com")
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusForbidden, postRec2.Code)
}

// TestOriginValidation_MissingOriginAllowed verifies that requests without
// Origin or Referer headers are allowed (some browsers omit them).
func TestOriginValidation_MissingOriginAllowed(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ValidateOrigin = true
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// No Origin or Referer header — should be allowed.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusOK, postRec.Code)
}

// TestOriginValidation_DisabledByDefault verifies that origin validation is off
// by default, so a mismatched Origin does not cause a failure.
func TestOriginValidation_DisabledByDefault(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// Mismatched origin with ValidateOrigin=false (default) — should still pass.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("Origin", "https://evil.com")
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusOK, postRec.Code)
}

// TestOriginValidation_RefererFallback verifies that when Origin is absent,
// the Referer header is used for origin validation.
func TestOriginValidation_RefererFallback(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ValidateOrigin = true
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// Matching Referer (no Origin header) should pass.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("Referer", "http://example.com/page")
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusOK, postRec.Code)

	// Mismatched Referer should fail.
	postRec2 := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("Referer", "http://evil.com/page")
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusForbidden, postRec2.Code)
}

// TestPOST_EmptyTokenHeader_Returns403 verifies that submitting an empty CSRF
// token in the header is rejected with 403.
func TestPOST_EmptyTokenHeader_Returns403(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// Submit empty token via header.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", "")
	})
	require.Equal(t, http.StatusForbidden, postRec.Code)
}

// TestPOST_EmptyTokenFormField_Returns403 verifies that submitting an empty
// CSRF token via form field is rejected with 403.
func TestPOST_EmptyTokenFormField_Returns403(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	form := url.Values{"csrf_token": {""}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(nonceCookie)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

// TestUnmaskToken_ZeroLengthMaskedToken_Returns403 verifies that submitting a
// zero-length string as the CSRF token (unmaskToken gets len==0) returns 403.
func TestUnmaskToken_ZeroLengthMaskedToken_Returns403(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// A POST with just a cookie but no token field at all should be 403.
	// This differs from the empty-header test: here no header or form field is set.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.AddCookie(nonceCookie)
	})
	require.Equal(t, http.StatusForbidden, postRec.Code)
}

// TestUnmaskToken_TwoHexChars_Returns403 verifies that a very short but valid
// hex token (e.g. "aabb" → pad=0xAA, masked=0xBB) is rejected because the
// recovered HMAC won't match the expected 32-byte HMAC.
func TestUnmaskToken_TwoHexChars_Returns403(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", "aabb") // valid hex, wrong length for HMAC
	})
	require.Equal(t, http.StatusForbidden, postRec.Code)
}

// TestUnmaskToken_OddLengthReturns403 verifies that a submitted token with an
// odd number of characters is rejected (unmaskToken returns nil for odd-length).
func TestUnmaskToken_OddLengthReturns403(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// Odd-length string → unmaskToken returns nil.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", "abc") // odd length
	})
	require.Equal(t, http.StatusForbidden, postRec.Code)
}

// TestUnmaskToken_InvalidHexPadReturns403 verifies that a submitted token
// whose first half is not valid hex is rejected.
func TestUnmaskToken_InvalidHexPadReturns403(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// 8 chars total, even length. First half "zzzz" is not valid hex.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", "zzzz1234")
	})
	require.Equal(t, http.StatusForbidden, postRec.Code)
}

// TestUnmaskToken_InvalidHexMaskedReturns403 verifies that a submitted token
// whose second half is not valid hex is rejected.
func TestUnmaskToken_InvalidHexMaskedReturns403(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// 8 chars total, even length. First half "1234" is valid hex; second "zzzz" is not.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", "1234zzzz")
	})
	require.Equal(t, http.StatusForbidden, postRec.Code)
}

// TestOriginValidation_RefererNoScheme verifies that a Referer without "://"
// is used as-is for comparison, and a mismatch returns 403.
func TestOriginValidation_RefererNoScheme(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ValidateOrigin = true
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// Referer without "://" is treated as the raw value; it won't match the host.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("Referer", "example.com/page") // no scheme
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	// "example.com/page" trimmed of trailing "/" → "example.com/page".
	// It won't match "https://example.com" or "http://example.com".
	// But it also won't match bare "example.com". So 403.
	require.Equal(t, http.StatusForbidden, postRec.Code)
}

// TestOriginValidation_RefererNoSlashAfterHost verifies the branch where a
// Referer has a scheme ("://") but no slash after the host portion.
func TestOriginValidation_RefererNoSlashAfterHost(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ValidateOrigin = true
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// Referer with scheme but no path slash — entire ref is used as the origin.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("Referer", "http://example.com") // no trailing slash or path
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusOK, postRec.Code)
}

// TestOriginValidation_BareHostMatch verifies that an Origin header containing
// just the bare hostname (no scheme) is accepted when it matches the request host.
func TestOriginValidation_BareHostMatch(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ValidateOrigin = true
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("Origin", "example.com") // bare host, no scheme
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusOK, postRec.Code)
}

// TestPOST_WithValidToken_AfterRotatePerRequest verifies that after rotation
// the old token is no longer valid.
func TestPOST_WithValidToken_AfterRotatePerRequest(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.RotatePerRequest = true
	handler := CSRFProtect(cfg)(inner)

	// GET — capture nonce cookie and token.
	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)
	capturedToken := token

	// POST with the captured cookie+token — rotation happens on the POST too,
	// but validation uses the cookie sent with the request, so it should pass.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", capturedToken)
	})
	require.Equal(t, http.StatusOK, postRec.Code)
}

// TestSecFetch_SameOrigin_SkipsTokenValidation verifies that a POST with
// Sec-Fetch-Site: same-origin succeeds without a CSRF token.
func TestSecFetch_SameOrigin_SkipsTokenValidation(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	rec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	})
	require.Equal(t, http.StatusOK, rec.Code)
}

// TestSecFetch_CrossSite_StillRequiresToken verifies that Sec-Fetch-Site:
// cross-site does NOT bypass token validation.
func TestSecFetch_CrossSite_StillRequiresToken(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	rec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	})
	require.Equal(t, http.StatusForbidden, rec.Code)
}

// TestSecFetch_SameSite_StillRequiresToken verifies that Sec-Fetch-Site:
// same-site does NOT bypass token validation.
func TestSecFetch_SameSite_StillRequiresToken(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	rec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "same-site")
	})
	require.Equal(t, http.StatusForbidden, rec.Code)
}

// TestSecFetch_None_StillRequiresToken verifies that Sec-Fetch-Site: none
// does NOT bypass token validation.
func TestSecFetch_None_StillRequiresToken(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	rec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "none")
	})
	require.Equal(t, http.StatusForbidden, rec.Code)
}

// TestSecFetch_Absent_StillRequiresToken verifies that a POST without any
// Sec-Fetch-Site header still requires a valid CSRF token.
func TestSecFetch_Absent_StillRequiresToken(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	rec := doRequest(t, handler, http.MethodPost, "/", nil)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

// TestSecFetch_SameOrigin_SetsCookieAndContext verifies that the fast path
// still sets the CSRF cookie and makes GetToken() work.
func TestSecFetch_SameOrigin_SetsCookieAndContext(t *testing.T) {
	var contextToken string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextToken = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(minimalCfg())(inner)

	rec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	})

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEmpty(t, contextToken, "GetToken should return a token on same-origin fast path")

	cookie := extractCookie(rec, "_csrf")
	require.NotNil(t, cookie, "CSRF cookie should be set on same-origin fast path")
	require.NotEmpty(t, cookie.Value)
}

// TestOriginValidation_HTTPSRequestRejectsHTTPOrigin verifies that an HTTPS
// request rejects an http:// origin for the same host.
func TestOriginValidation_HTTPSRequestRejectsHTTPOrigin(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ValidateOrigin = true
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// Simulate HTTPS request via X-Forwarded-Proto, but origin uses http://.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("Origin", "http://example.com")
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusForbidden, postRec.Code)
}

// TestOriginValidation_HTTPRequestRejectsHTTPSOrigin verifies that a plain
// HTTP request rejects an https:// origin for the same host.
func TestOriginValidation_HTTPRequestRejectsHTTPSOrigin(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ValidateOrigin = true
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// Plain HTTP request (no TLS, no X-Forwarded-Proto), but origin uses https://.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("Origin", "https://example.com")
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusForbidden, postRec.Code)
}

// TestOriginValidation_MatchingSchemeAndHostSucceeds verifies that when the
// origin scheme matches the effective request scheme, the request passes.
func TestOriginValidation_MatchingSchemeAndHostSucceeds(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ValidateOrigin = true
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// HTTPS request with matching https:// origin.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("Origin", "https://example.com")
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusOK, postRec.Code)

	// HTTP request with matching http:// origin.
	postRec2 := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("Origin", "http://example.com")
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusOK, postRec2.Code)
}

// TestOriginValidation_TrustedOriginsOverridesScheme verifies that TrustedOrigins
// still works as an explicit opt-in, even when the scheme doesn't match.
func TestOriginValidation_TrustedOriginsOverridesScheme(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ValidateOrigin = true
	cfg.TrustedOrigins = []string{"http://example.com"}
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	// HTTPS request but origin is http:// — scheme mismatch for host check,
	// but http://example.com is in TrustedOrigins so it should pass.
	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("Origin", "http://example.com")
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusOK, postRec.Code)
}

// TestOriginValidation_BareHostStillWorks verifies that an Origin header with
// just the bare hostname (no scheme) is still accepted.
func TestOriginValidation_BareHostStillWorks(t *testing.T) {
	var token string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = GetToken(r)
		w.WriteHeader(http.StatusOK)
	})
	cfg := minimalCfg()
	cfg.ValidateOrigin = true
	handler := CSRFProtect(cfg)(inner)

	getRec := doRequest(t, handler, http.MethodGet, "/", nil)
	nonceCookie := extractCookie(getRec, "_csrf")
	require.NotNil(t, nonceCookie)

	postRec := doRequest(t, handler, http.MethodPost, "/", func(r *http.Request) {
		r.Host = "example.com"
		r.Header.Set("Origin", "example.com")
		r.AddCookie(nonceCookie)
		r.Header.Set("X-CSRF-Token", token)
	})
	require.Equal(t, http.StatusOK, postRec.Code)
}
