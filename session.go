package porter

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type settingsKeyType struct{}

var settingsCtxKey settingsKeyType

// SessionConfig holds session middleware configuration.
type SessionConfig struct {
	// CookieName is the name of the cookie used to store the session ID.
	// Defaults to "porter_session_id" when empty.
	CookieName string

	// Logger is used for error reporting during session loading.
	// Defaults to slog.Default() when nil.
	Logger *slog.Logger
}

func (cfg SessionConfig) cookieName() string {
	if cfg.CookieName != "" {
		return cfg.CookieName
	}
	return "porter_session_id"
}

func (cfg SessionConfig) logger() *slog.Logger {
	if cfg.Logger != nil {
		return cfg.Logger
	}
	return slog.Default()
}

// SessionSettingsProvider is the interface for session-settings persistence.
// Implementations typically back this with a database table keyed on the
// session UUID. The middleware calls [SessionSettingsProvider.GetByUUID] on
// every request, [SessionSettingsProvider.Upsert] when creating defaults, and
// [SessionSettingsProvider.Touch] to bump the timestamp once per day.
type SessionSettingsProvider interface {
	GetByUUID(ctx context.Context, uuid string) (*SessionSettings, error)
	Upsert(ctx context.Context, s *SessionSettings) error
	Touch(ctx context.Context, uuid string) error
}

// SessionIDFunc returns the session identifier for the current request.
// Pass a function that extracts the session ID from an external auth provider
// (e.g. crooner.SessionID). When nil or when the function returns an empty
// string, the middleware falls back to a random cookie-based session ID.
type SessionIDFunc func(r *http.Request) string

// SessionSettingsMiddleware returns middleware that loads per-session
// settings and stores them on the request context for downstream handlers.
//
// The session ID comes from idFunc (e.g. crooner's session token). When idFunc
// is nil or returns an empty string, the middleware creates a random
// cookie-based session ID automatically. Pass optional [SessionConfig] to
// override the cookie name or logger.
func SessionSettingsMiddleware(repo SessionSettingsProvider, idFunc SessionIDFunc, cfgs ...SessionConfig) func(http.Handler) http.Handler {
	var cfg SessionConfig
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			sessionID := ""
			if idFunc != nil {
				sessionID = idFunc(r)
			}
			if sessionID == "" {
				sessionID = getOrCreateSessionCookie(w, r, cfg.cookieName())
			}

			settings, err := repo.GetByUUID(ctx, sessionID)
			if err != nil {
				cfg.logger().ErrorContext(ctx, "Failed to load session settings", "error", err)
				settings = NewDefaultSettings(sessionID)
			}
			if settings == nil {
				settings = NewDefaultSettings(sessionID)
				if err := repo.Upsert(ctx, settings); err != nil {
					cfg.logger().ErrorContext(ctx, "Failed to create session settings", "error", err)
				}
			}

			if time.Since(settings.UpdatedAt) > 24*time.Hour {
				_ = repo.Touch(ctx, sessionID)
			}

			r = r.WithContext(context.WithValue(r.Context(), settingsCtxKey, settings))
			next.ServeHTTP(w, r)
		})
	}
}

// GetSessionSettings returns the session settings from the request context.
func GetSessionSettings(r *http.Request) *SessionSettings {
	if s, ok := r.Context().Value(settingsCtxKey).(*SessionSettings); ok {
		return s
	}
	return NewDefaultSettings("")
}

// getOrCreateSessionCookie reads the session cookie or creates a new random one.
func getOrCreateSessionCookie(w http.ResponseWriter, r *http.Request, cookieName string) string {
	if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	id := randomUUID()
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    id,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return id
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
