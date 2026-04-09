package dorman

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

// Sentinel errors returned by CSRF middleware.
var (
	ErrCSRFTokenMissing = errors.New("dorman: CSRF token missing")
	ErrCSRFTokenInvalid = errors.New("dorman: CSRF token invalid")
)

type csrfTokenKeyType struct{}

var csrfTokenCtxKey csrfTokenKeyType

type csrfErrorKeyType struct{}

var csrfErrorCtxKey csrfErrorKeyType

// csrfMasker is stored on the context; it holds the raw HMAC bytes and the
// maskToken function so that GetToken can apply a fresh pad on every call.
type csrfMasker struct {
	tokenBytes []byte
	mask       func([]byte) (string, error)
}

// CSRFConfig configures the CSRF protection middleware.
type CSRFConfig struct {
	// Key is the HMAC key used for token generation. Must be at least 32 bytes. Required.
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
	// InsecureCookie disables the Secure flag on the CSRF cookie. Default: false
	// (Secure=true). Set to true only for non-HTTPS environments (e.g. local dev).
	InsecureCookie bool
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
	// ValidateOrigin enables Origin header checking on unsafe methods.
	// When true, rejects requests where Origin doesn't match the request host.
	ValidateOrigin bool
	// TrustedOrigins is a list of allowed origins (e.g. "https://example.com").
	// Only used when ValidateOrigin is true. The request's own host is always trusted.
	TrustedOrigins []string
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
	if len(cfg.Key) < 32 {
		panic("dorman: CSRFConfig.Key must be at least 32 bytes")
	}

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

	// Build lookup sets for exempt paths and per-request paths.
	exemptSet := make(map[string]bool, len(cfg.ExemptPaths))
	for _, p := range cfg.ExemptPaths {
		exemptSet[p] = true
	}
	perRequestSet := make(map[string]bool, len(cfg.PerRequestPaths))
	for _, p := range cfg.PerRequestPaths {
		perRequestSet[p] = true
	}

	// Build trusted origins set for fast lookup.
	trustedOriginSet := make(map[string]bool, len(cfg.TrustedOrigins))
	for _, o := range cfg.TrustedOrigins {
		trustedOriginSet[strings.ToLower(strings.TrimRight(o, "/"))] = true
	}

	generateNonce := func() (string, error) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b), nil
	}

	// computeHMAC returns the raw HMAC-SHA256 bytes for the given nonce.
	computeHMAC := func(nonce string) []byte {
		mac := hmac.New(sha256.New, cfg.Key)
		mac.Write([]byte(nonce))
		return mac.Sum(nil)
	}

	// maskToken applies a random one-time pad to the HMAC bytes and returns
	// hex(pad) + hex(pad XOR token). This prevents BREACH attacks by ensuring
	// that the visible token is different on every call even for the same nonce.
	maskToken := func(tokenBytes []byte) (string, error) {
		pad := make([]byte, len(tokenBytes))
		if _, err := rand.Read(pad); err != nil {
			return "", err
		}
		masked := make([]byte, len(tokenBytes))
		for i := range tokenBytes {
			masked[i] = pad[i] ^ tokenBytes[i]
		}
		return hex.EncodeToString(pad) + hex.EncodeToString(masked), nil
	}

	// unmaskToken recovers the original HMAC bytes from a masked token string.
	// Returns nil if the token is malformed.
	unmaskToken := func(s string) []byte {
		// Each half is hex-encoded SHA-256 output (32 bytes = 64 hex chars).
		if len(s) == 0 || len(s)%2 != 0 {
			return nil
		}
		half := len(s) / 2
		padHex := s[:half]
		maskedHex := s[half:]
		pad, err := hex.DecodeString(padHex)
		if err != nil {
			return nil
		}
		masked, err := hex.DecodeString(maskedHex)
		if err != nil {
			return nil
		}
		if len(pad) != len(masked) {
			return nil
		}
		token := make([]byte, len(pad))
		for i := range pad {
			token[i] = pad[i] ^ masked[i]
		}
		return token
	}

	// fail writes the CSRF rejection response. When cause is non-nil, it is
	// attached to the request context so that the configured ErrorHandler can
	// retrieve it via [CSRFError].
	fail := func(w http.ResponseWriter, r *http.Request, cause error) {
		if cause != nil {
			r = r.WithContext(context.WithValue(r.Context(), csrfErrorCtxKey, cause))
		}
		if cfg.ErrorHandler != nil {
			cfg.ErrorHandler(w, r)
			return
		}
		http.Error(w, "", http.StatusForbidden)
	}

	// checkOrigin validates the Origin (or Referer) header against the request
	// host and TrustedOrigins. Returns true if the origin is acceptable.
	checkOrigin := func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// Fall back to Referer.
			ref := r.Header.Get("Referer")
			if ref == "" {
				// No origin information — allow (some browsers omit both headers).
				return true
			}
			// Strip path from referer to get origin-like prefix.
			// We only need scheme+host for comparison.
			if idx := strings.Index(ref, "://"); idx != -1 {
				// Find end of host (first slash after scheme://).
				rest := ref[idx+3:]
				if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
					origin = ref[:idx+3+slashIdx]
				} else {
					origin = ref
				}
			} else {
				origin = ref
			}
		}

		origin = strings.ToLower(strings.TrimRight(origin, "/"))

		// Always trust the request's own host with the correct scheme.
		requestHost := strings.ToLower(r.Host)
		// Derive the effective scheme from TLS state or X-Forwarded-Proto.
		scheme := "http://"
		if r.TLS != nil {
			scheme = "https://"
		} else if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
			scheme = "https://"
		}
		if origin == scheme+requestHost {
			return true
		}

		// Check trusted origins list.
		if trustedOriginSet[origin] {
			return true
		}

		return false
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
				// Unsafe method: validate Origin header if configured.
				if cfg.ValidateOrigin && !checkOrigin(r) {
					// Origin-check failures intentionally leave the cause unset:
					// there is no exported sentinel for origin-check failures
					// and inventing one is out of scope for #47.
					fail(w, r, nil)
					return
				}

				// Unsafe method: must have existing cookie nonce.
				c, err := r.Cookie(cfg.CookieName)
				if err != nil || c.Value == "" {
					fail(w, r, ErrCSRFTokenMissing)
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
					fail(w, r, ErrCSRFTokenMissing)
					return
				}

				// Unmask the submitted token to recover the real HMAC bytes.
				recoveredBytes := unmaskToken(submitted)
				if recoveredBytes == nil {
					fail(w, r, ErrCSRFTokenInvalid)
					return
				}

				// Recompute expected HMAC and compare.
				expected := computeHMAC(nonce)
				if !hmac.Equal(recoveredBytes, expected) {
					fail(w, r, ErrCSRFTokenInvalid)
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

			// Set the cookie. Secure is true by default; opt out with InsecureCookie.
			http.SetCookie(w, &http.Cookie{
				Name:     cfg.CookieName,
				Value:    nonce,
				Path:     cfg.CookiePath,
				MaxAge:   cfg.MaxAge,
				Secure:   !cfg.InsecureCookie,
				HttpOnly: true,
				SameSite: cfg.SameSite,
			})

			// Store the raw HMAC bytes and masking function on the context.
			// GetToken applies a fresh one-time pad on every call (BREACH protection).
			tokenBytes := computeHMAC(nonce)
			r = r.WithContext(context.WithValue(r.Context(), csrfTokenCtxKey, &csrfMasker{
				tokenBytes: tokenBytes,
				mask:       maskToken,
			}))

			next.ServeHTTP(w, r)
		})
	}
}

// GetToken returns the CSRF token stored on the request context by
// [CSRFProtect]. It returns an empty string when no token is present.
// Each call applies a fresh one-time pad (BREACH protection), so the returned
// string differs between calls even for the same underlying nonce.
func GetToken(r *http.Request) string {
	m, ok := r.Context().Value(csrfTokenCtxKey).(*csrfMasker)
	if !ok || m == nil {
		return ""
	}
	tok, err := m.mask(m.tokenBytes)
	if err != nil {
		return ""
	}
	return tok
}

// CSRFError returns the CSRF failure cause attached to the request context by
// [CSRFProtect] before it invokes [CSRFConfig.ErrorHandler]. It returns nil
// when no cause has been recorded (for example outside of an error handler,
// or when the failure was an origin-check rejection). Callers can use
// [errors.Is] to distinguish between [ErrCSRFTokenMissing] and
// [ErrCSRFTokenInvalid].
func CSRFError(r *http.Request) error {
	err, _ := r.Context().Value(csrfErrorCtxKey).(error)
	return err
}
