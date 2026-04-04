package porter

import (
	"fmt"
	"net/http"
)

// SecurityHeadersConfig configures which security headers are sent with every response.
// An empty string for any field omits that header. Use [DefaultSecurityHeadersConfig]
// for sensible defaults and override individual fields as needed.
type SecurityHeadersConfig struct {
	// XFrameOptions sets X-Frame-Options. Default: "SAMEORIGIN". Empty string omits.
	XFrameOptions string

	// XContentTypeOptions sets X-Content-Type-Options. Default: "nosniff". Empty string omits.
	XContentTypeOptions string

	// XXSSProtection sets X-XSS-Protection. Default: "0" (disabled). Empty string omits.
	// OWASP recommends disabling legacy XSS auditors to avoid introducing new vulnerabilities.
	XXSSProtection string

	// ReferrerPolicy sets Referrer-Policy. Default: "strict-origin-when-cross-origin". Empty string omits.
	ReferrerPolicy string

	// HSTS configures Strict-Transport-Security. nil = omit header.
	HSTS *HSTSConfig

	// PermissionsPolicy sets Permissions-Policy. Default: "camera=(), microphone=(), geolocation=(), payment=(), usb=()". Empty string omits.
	PermissionsPolicy string

	// CrossOriginOpenerPolicy sets Cross-Origin-Opener-Policy. Default: "same-origin". Empty string omits.
	CrossOriginOpenerPolicy string

	// ContentSecurityPolicy sets Content-Security-Policy. Default: "" (omitted). App-specific.
	ContentSecurityPolicy string
}

// HSTSConfig controls the Strict-Transport-Security header.
type HSTSConfig struct {
	// MaxAge is the max-age in seconds. Default: 63072000 (2 years).
	MaxAge int
	// IncludeSubDomains adds the includeSubDomains directive. Default: true.
	IncludeSubDomains bool
	// Preload adds the preload directive. Default: false.
	Preload bool
}

// DefaultSecurityHeadersConfig returns a [SecurityHeadersConfig] with sensible defaults.
// HSTS is nil (disabled) by default because it can break development environments
// without TLS. Enable it explicitly with [DefaultHSTSConfig] when serving over HTTPS.
func DefaultSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		XFrameOptions:           "SAMEORIGIN",
		XContentTypeOptions:     "nosniff",
		XXSSProtection:          "0",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		PermissionsPolicy:       "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
		CrossOriginOpenerPolicy: "same-origin",
	}
}

// DefaultHSTSConfig returns an [HSTSConfig] with sensible defaults:
// max-age=63072000 (2 years), includeSubDomains=true, preload=false.
func DefaultHSTSConfig() *HSTSConfig {
	return &HSTSConfig{MaxAge: 63072000, IncludeSubDomains: true}
}

// SecurityHeaders returns middleware that sets security response headers before
// passing the request to the next handler. With no arguments it uses
// [DefaultSecurityHeadersConfig]. Pass a [SecurityHeadersConfig] to override.
func SecurityHeaders(cfgs ...SecurityHeadersConfig) func(http.Handler) http.Handler {
	cfg := DefaultSecurityHeadersConfig()
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}

	var hstsValue string
	if cfg.HSTS != nil {
		h := cfg.HSTS
		maxAge := h.MaxAge
		if maxAge == 0 {
			maxAge = 63072000
		}
		hstsValue = fmt.Sprintf("max-age=%d", maxAge)
		if h.IncludeSubDomains {
			hstsValue += "; includeSubDomains"
		}
		if h.Preload {
			hstsValue += "; preload"
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			if cfg.XFrameOptions != "" {
				h.Set("X-Frame-Options", cfg.XFrameOptions)
			}
			if cfg.XContentTypeOptions != "" {
				h.Set("X-Content-Type-Options", cfg.XContentTypeOptions)
			}
			if cfg.XXSSProtection != "" {
				h.Set("X-XSS-Protection", cfg.XXSSProtection)
			}
			if cfg.ReferrerPolicy != "" {
				h.Set("Referrer-Policy", cfg.ReferrerPolicy)
			}
			if hstsValue != "" {
				h.Set("Strict-Transport-Security", hstsValue)
			}
			if cfg.PermissionsPolicy != "" {
				h.Set("Permissions-Policy", cfg.PermissionsPolicy)
			}
			if cfg.CrossOriginOpenerPolicy != "" {
				h.Set("Cross-Origin-Opener-Policy", cfg.CrossOriginOpenerPolicy)
			}
			if cfg.ContentSecurityPolicy != "" {
				h.Set("Content-Security-Policy", cfg.ContentSecurityPolicy)
			}
			next.ServeHTTP(w, r)
		})
	}
}
