// Package porter provides authorization middleware, CSRF protection, and
// session settings for net/http applications.
//
// Porter is designed around small interfaces so that each concern (session
// storage, identity, authorization) can be satisfied by different backends.
// Crooner's SessionManager, for example, directly satisfies [CSRFSessionStore],
// but any implementation that can get and set string values will work.
package porter

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
)

const csrfTokenSessionKey = "csrf_token"

type csrfTokenKeyType struct{}

var csrfTokenCtxKey csrfTokenKeyType

var safeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodTrace:   true,
}

// CSRFSessionStore provides get/set for string session values.
// Any session implementation (crooner, SCS, cookie-based, etc.) can satisfy this.
type CSRFSessionStore interface {
	Get(r *http.Request, key string) (any, error)
	Set(w http.ResponseWriter, r *http.Request, key string, value any) error
}

// CookieCSRFStore stores CSRF tokens in an HTTP cookie.
// Use this for apps that rely on HMAC-signed session cookies
// and have no server-side session store to pass to [CSRF].
type CookieCSRFStore struct{}

func (CookieCSRFStore) Get(r *http.Request, key string) (any, error) {
	cookie, err := r.Cookie("_csrf")
	if err != nil {
		return nil, err
	}
	return cookie.Value, nil
}

func (CookieCSRFStore) Set(w http.ResponseWriter, _ *http.Request, _ string, value any) error {
	http.SetCookie(w, &http.Cookie{
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

// GetCSRFToken returns the CSRF token from the request context.
// Returns an empty string when no token has been set by the CSRF middleware.
func GetCSRFToken(r *http.Request) string {
	if v, ok := r.Context().Value(csrfTokenCtxKey).(string); ok {
		return v
	}
	return ""
}

// CSRF returns middleware that generates and validates CSRF tokens using a session store.
// When ss is nil the middleware is a no-op.
func CSRF(ss CSRFSessionStore, cfg CSRFConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ss == nil {
				next.ServeHTTP(w, r)
				return
			}
			path := r.URL.Path
			if pathExempt(cfg.ExemptPaths, path) {
				next.ServeHTTP(w, r)
				return
			}
			if safeMethods[r.Method] {
				token, err := getOrCreateToken(w, r, ss, cfg, path)
				if err != nil {
					http.Error(w, "internal server error", http.StatusInternalServerError)
					return
				}
				r = r.WithContext(context.WithValue(r.Context(), csrfTokenCtxKey, token))
				next.ServeHTTP(w, r)
				return
			}
			reqToken := r.Header.Get("X-CSRF-Token")
			if reqToken == "" {
				reqToken = r.FormValue("_csrf")
			}
			sessionToken, _ := getSessionString(ss, r, csrfTokenSessionKey)
			if sessionToken == "" || subtle.ConstantTimeCompare([]byte(sessionToken), []byte(reqToken)) != 1 {
				http.Error(w, "", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
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

func getOrCreateToken(w http.ResponseWriter, r *http.Request, ss CSRFSessionStore, cfg CSRFConfig, path string) (string, error) {
	rotate := cfg.RotatePerRequest || pathPerRequest(cfg.PerRequestPaths, path)
	if !rotate {
		existing, err := getSessionString(ss, r, csrfTokenSessionKey)
		if err == nil && existing != "" {
			return existing, nil
		}
	}
	token, err := generateToken()
	if err != nil {
		return "", err
	}
	if err := ss.Set(w, r, csrfTokenSessionKey, token); err != nil {
		return "", err
	}
	return token, nil
}

func getSessionString(ss CSRFSessionStore, r *http.Request, key string) (string, error) {
	val, err := ss.Get(r, key)
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
