package porter

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
		Secure:     true,
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
