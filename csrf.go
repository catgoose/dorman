// Package porter provides authorization middleware, CSRF protection, and
// session settings for Echo applications.
//
// Porter is designed around small interfaces so that each concern (session
// storage, identity, authorization) can be satisfied by different backends.
// Crooner's SessionManager, for example, directly satisfies [CSRFSessionStore],
// but any implementation that can get and set string values will work.
package porter

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

const csrfTokenSessionKey = "csrf_token"
const csrfContextKey = "csrf_token"

var safeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodTrace:   true,
}

// CSRFSessionStore provides get/set for string session values.
// Any session implementation (crooner, SCS, cookie-based, etc.) can satisfy this.
type CSRFSessionStore interface {
	Get(c echo.Context, key string) (any, error)
	Set(c echo.Context, key string, value any) error
}

// CookieCSRFStore stores CSRF tokens in an HTTP cookie.
// Use this for apps that rely on HMAC-signed session cookies
// and have no server-side session store to pass to [CSRF].
type CookieCSRFStore struct{}

func (CookieCSRFStore) Get(c echo.Context, key string) (any, error) {
	cookie, err := c.Cookie("_csrf")
	if err != nil {
		return nil, err
	}
	return cookie.Value, nil
}

func (CookieCSRFStore) Set(c echo.Context, key string, value any) error {
	c.SetCookie(&http.Cookie{
		Name:     "_csrf",
		Value:    value.(string),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// CSRFConfig holds CSRF middleware configuration.
type CSRFConfig struct {
	// PerRequestPaths lists URL paths that receive a fresh CSRF token on
	// every safe (GET/HEAD/OPTIONS) request, useful for one-time-use forms.
	PerRequestPaths []string

	// ExemptPaths lists URL paths that skip CSRF validation entirely.
	// Typically includes OAuth callback and logout endpoints.
	ExemptPaths []string

	// RotatePerRequest, when true, generates a new token on every safe
	// request regardless of path. When false, the token is reused until
	// a per-request path triggers rotation.
	RotatePerRequest bool
}

// CSRF returns Echo middleware that generates and validates CSRF tokens using a session store.
// When ss is nil the middleware is a no-op.
func CSRF(ss CSRFSessionStore, cfg CSRFConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if ss == nil {
				return next(c)
			}
			path := c.Request().URL.Path
			if pathExempt(cfg.ExemptPaths, path) {
				return next(c)
			}
			if safeMethods[c.Request().Method] {
				token, err := getOrCreateToken(c, ss, cfg, path)
				if err != nil {
					return err
				}
				c.Set(csrfContextKey, token)
				return next(c)
			}
			reqToken := c.Request().Header.Get("X-CSRF-Token")
			if reqToken == "" {
				reqToken = c.Request().FormValue("_csrf")
			}
			sessionToken, _ := getSessionString(ss, c, csrfTokenSessionKey)
			if sessionToken == "" || subtle.ConstantTimeCompare([]byte(sessionToken), []byte(reqToken)) != 1 {
				return c.NoContent(http.StatusForbidden)
			}
			return next(c)
		}
	}
}

func pathExempt(exempt []string, path string) bool {
	for _, e := range exempt {
		if path == e || strings.HasPrefix(path, strings.TrimSuffix(e, "/")+"/") {
			return true
		}
	}
	return false
}

func pathPerRequest(paths []string, path string) bool {
	for _, p := range paths {
		if path == p {
			return true
		}
	}
	return false
}

func getOrCreateToken(c echo.Context, ss CSRFSessionStore, cfg CSRFConfig, path string) (string, error) {
	rotate := cfg.RotatePerRequest || pathPerRequest(cfg.PerRequestPaths, path)
	if !rotate {
		existing, err := getSessionString(ss, c, csrfTokenSessionKey)
		if err == nil && existing != "" {
			return existing, nil
		}
	}
	token, err := generateToken()
	if err != nil {
		return "", err
	}
	if err := ss.Set(c, csrfTokenSessionKey, token); err != nil {
		return "", err
	}
	return token, nil
}

func getSessionString(ss CSRFSessionStore, c echo.Context, key string) (string, error) {
	val, err := ss.Get(c, key)
	if err != nil {
		return "", err
	}
	s, _ := val.(string)
	return s, nil
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
