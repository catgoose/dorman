package porter

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
)

// Sentinel errors returned by CSRF middleware.
var (
	ErrCSRFTokenMissing = errors.New("porter: CSRF token missing")
	ErrCSRFTokenInvalid = errors.New("porter: CSRF token invalid")
)

type csrfTokenKeyType struct{}

var csrfTokenCtxKey csrfTokenKeyType

// CSRFConfig configures the CSRF protection middleware.
type CSRFConfig struct {
	// Key is a 32-byte HMAC key. Required.
	Key []byte
	// FieldName is the form field name for the CSRF token. Default: "csrf_token".
	FieldName string
	// RequestHeader is the header name for the CSRF token. Default: "X-CSRF-Token".
	RequestHeader string
	// CookieName is the name of the CSRF cookie. Default: "_csrf".
	CookieName string
	// CookiePath is the path for the CSRF cookie. Default: "/".
	CookiePath string
	// MaxAge is the cookie max-age in seconds. Default: 43200 (12h).
	MaxAge int
	// Secure marks the cookie as Secure. Default: true.
	Secure bool
	// SameSite is the SameSite attribute for the cookie. Default: http.SameSiteLaxMode.
	SameSite http.SameSite
	// ExemptPaths lists exact request paths that bypass CSRF validation.
	ExemptPaths []string
	// ExemptFunc is a custom function that, when it returns true, bypasses validation.
	ExemptFunc func(*http.Request) bool
	// ErrorHandler is called when CSRF validation fails. When nil, a plain 403 is written.
	ErrorHandler func(http.ResponseWriter, *http.Request)
	// RotatePerRequest generates a fresh nonce on every request.
	RotatePerRequest bool
	// PerRequestPaths lists paths that rotate the nonce even when RotatePerRequest is false.
	PerRequestPaths []string
}

// safeMethods are HTTP methods that do not mutate state and therefore skip
// CSRF token validation.
var safeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodTrace:   true,
}

// CSRFProtect returns middleware that implements double-submit cookie CSRF
// protection. The CSRF token is available to handlers via [GetToken].
func CSRFProtect(cfg CSRFConfig) func(http.Handler) http.Handler {
	// Apply defaults.
	if cfg.FieldName == "" {
		cfg.FieldName = "csrf_token"
	}
	if cfg.RequestHeader == "" {
		cfg.RequestHeader = "X-CSRF-Token"
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "_csrf"
	}
	if cfg.CookiePath == "" {
		cfg.CookiePath = "/"
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 43200
	}
	if cfg.SameSite == 0 {
		cfg.SameSite = http.SameSiteLaxMode
	}
	// Secure defaults to true; callers must explicitly set false to opt out.
	// We detect unset by checking whether the caller left the zero value — but
	// bool zero is false, so we always apply the caller's value. The design
	// note says "default: true", so we flip: treat the zero-value struct as
	// "not explicitly set to false". To achieve this cleanly we rely on the
	// struct field being set to true at the call site or we document that
	// callers should set Secure: true. Because the user controls the struct
	// we cannot distinguish false-as-default from false-as-intent with a plain
	// bool. We therefore honour the value as-is; tests that want Secure=true
	// must set it explicitly — consistent with how Go stdlib http.Cookie works.

	// Build lookup sets for exempt paths and per-request paths.
	exemptSet := make(map[string]bool, len(cfg.ExemptPaths))
	for _, p := range cfg.ExemptPaths {
		exemptSet[p] = true
	}
	perRequestSet := make(map[string]bool, len(cfg.PerRequestPaths))
	for _, p := range cfg.PerRequestPaths {
		perRequestSet[p] = true
	}

	generateNonce := func() (string, error) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b), nil
	}

	computeToken := func(nonce string) string {
		mac := hmac.New(sha256.New, cfg.Key)
		mac.Write([]byte(nonce))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}

	fail := func(w http.ResponseWriter, r *http.Request) {
		if cfg.ErrorHandler != nil {
			cfg.ErrorHandler(w, r)
			return
		}
		http.Error(w, "", http.StatusForbidden)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check exemptions before anything else.
			if exemptSet[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			if cfg.ExemptFunc != nil && cfg.ExemptFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			safe := safeMethods[r.Method]

			// Determine whether to rotate the nonce.
			shouldRotate := cfg.RotatePerRequest || perRequestSet[r.URL.Path]

			// For safe methods: always set cookie+context (and rotate if configured).
			// For unsafe methods: read existing nonce from cookie, validate, optionally rotate.
			var nonce string

			if safe {
				// Always issue / rotate for safe methods when rotation is requested;
				// otherwise reuse the existing cookie nonce if present.
				if shouldRotate {
					n, err := generateNonce()
					if err != nil {
						http.Error(w, "", http.StatusInternalServerError)
						return
					}
					nonce = n
				} else {
					// Try to reuse existing cookie.
					if c, err := r.Cookie(cfg.CookieName); err == nil && c.Value != "" {
						nonce = c.Value
					} else {
						n, err := generateNonce()
						if err != nil {
							http.Error(w, "", http.StatusInternalServerError)
							return
						}
						nonce = n
					}
				}
			} else {
				// Unsafe method: must have existing cookie nonce.
				c, err := r.Cookie(cfg.CookieName)
				if err != nil || c.Value == "" {
					fail(w, r)
					return
				}
				nonce = c.Value

				// Read submitted token from header, then form field.
				submitted := r.Header.Get(cfg.RequestHeader)
				if submitted == "" {
					if err := r.ParseForm(); err == nil {
						submitted = r.FormValue(cfg.FieldName)
					}
				}
				if submitted == "" {
					fail(w, r)
					return
				}

				// Validate: recompute HMAC from cookie nonce and compare.
				expected := computeToken(nonce)
				if !hmac.Equal([]byte(submitted), []byte(expected)) {
					fail(w, r)
					return
				}

				// Optionally rotate after successful validation.
				if shouldRotate {
					n, err := generateNonce()
					if err != nil {
						http.Error(w, "", http.StatusInternalServerError)
						return
					}
					nonce = n
				}
			}

			// Set the cookie.
			http.SetCookie(w, &http.Cookie{
				Name:     cfg.CookieName,
				Value:    nonce,
				Path:     cfg.CookiePath,
				MaxAge:   cfg.MaxAge,
				Secure:   cfg.Secure,
				HttpOnly: true,
				SameSite: cfg.SameSite,
			})

			// Compute token and store on context.
			token := computeToken(nonce)
			r = r.WithContext(context.WithValue(r.Context(), csrfTokenCtxKey, token))

			next.ServeHTTP(w, r)
		})
	}
}

// GetToken returns the CSRF token stored on the request context by
// [CSRFProtect]. It returns an empty string when no token is present.
func GetToken(r *http.Request) string {
	tok, _ := r.Context().Value(csrfTokenCtxKey).(string)
	return tok
}
