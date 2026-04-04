package porter

import (
	"context"
	"errors"
	"net/http"
)

type identityKeyType struct{}

var identityCtxKey identityKeyType

// Sentinel errors returned by authorization middleware and identity providers.
var (
	ErrNoIdentity      = errors.New("porter: no identity in context")
	ErrInvalidIdentity = errors.New("porter: identity value is not a porter.Identity")
	ErrForbidden       = errors.New("porter: forbidden")
	ErrUnauthorized    = errors.New("porter: unauthorized")
)

// Identity represents an authenticated subject with roles.
type Identity interface {
	// Subject returns the unique identifier for this identity (user ID, email, etc.).
	Subject() string
	// Roles returns the roles assigned to this identity.
	Roles() []string
}

// SimpleIdentity is a basic [Identity] implementation.
type SimpleIdentity struct {
	ID       string
	RoleList []string
}

func (s SimpleIdentity) Subject() string { return s.ID }
func (s SimpleIdentity) Roles() []string { return s.RoleList }

// IdentityProvider extracts identity from a request.
// Crooner's session satisfies this; porter also ships [ContextIdentityProvider]
// for reading identity set by external auth middleware.
type IdentityProvider interface {
	GetIdentity(r *http.Request) (Identity, error)
}

// ContextIdentityProvider reads identity from the request context using a typed key.
// Use this when your auth middleware stores identity on the request context.
type ContextIdentityProvider struct {
	// ContextKey is the context key used by auth middleware to store identity.
	ContextKey any
}

func (p ContextIdentityProvider) GetIdentity(r *http.Request) (Identity, error) {
	val := r.Context().Value(p.ContextKey)
	if val == nil {
		return nil, ErrNoIdentity
	}
	id, ok := val.(Identity)
	if !ok {
		return nil, ErrInvalidIdentity
	}
	return id, nil
}

// GetIdentity retrieves the [Identity] from the request context. Returns nil when
// no identity has been set by authorization middleware.
func GetIdentity(r *http.Request) Identity {
	id, _ := r.Context().Value(identityCtxKey).(Identity)
	return id
}

// AuthErrorFunc is a callback invoked when auth middleware rejects a request.
// The err argument is one of the sentinel errors ([ErrUnauthorized] or
// [ErrForbidden]) so callers can distinguish 401 vs 403 cases.
type AuthErrorFunc func(w http.ResponseWriter, r *http.Request, err error)

// AuthOption configures optional behavior for auth middleware.
type AuthOption func(*authConfig)

type authConfig struct {
	errorHandler AuthErrorFunc
}

func buildAuthConfig(opts []AuthOption) authConfig {
	var cfg authConfig
	for _, o := range opts {
		o(&cfg)
	}
	return cfg
}

// AuthErrorHandler returns an [AuthOption] that sets a custom error handler
// for auth middleware. When set, the handler is called instead of the default
// bare status-code response.
func AuthErrorHandler(fn AuthErrorFunc) AuthOption {
	return func(cfg *authConfig) {
		cfg.errorHandler = fn
	}
}

// authFail writes the appropriate error response. If a custom handler is
// configured it delegates to that; otherwise it writes a bare status code.
func authFail(w http.ResponseWriter, r *http.Request, err error, statusCode int, cfg authConfig) {
	if cfg.errorHandler != nil {
		cfg.errorHandler(w, r, err)
		return
	}
	http.Error(w, "", statusCode)
}

// RequireAuth returns middleware that rejects unauthenticated requests with
// 401 Unauthorized. Authenticated identities are stored on the request context
// for downstream handlers via [GetIdentity].
func RequireAuth(provider IdentityProvider, opts ...AuthOption) func(http.Handler) http.Handler {
	cfg := buildAuthConfig(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := provider.GetIdentity(r)
			if err != nil || id == nil {
				authFail(w, r, ErrUnauthorized, http.StatusUnauthorized, cfg)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), identityCtxKey, id))
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole returns middleware that requires the identity to have the given
// role. Unauthenticated requests receive 401; authenticated requests missing the
// role receive 403.
func RequireRole(provider IdentityProvider, role string, opts ...AuthOption) func(http.Handler) http.Handler {
	return RequireAnyRole(provider, []string{role}, opts...)
}

// RequireAllRoles returns middleware that requires the identity to have all of
// the given roles. Unauthenticated requests receive 401; authenticated requests
// missing any role receive 403.
func RequireAllRoles(provider IdentityProvider, roles ...string) func(http.Handler) http.Handler {
	want := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		want[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := provider.GetIdentity(r)
			if err != nil || id == nil {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}
			have := make(map[string]struct{}, len(id.Roles()))
			for _, role := range id.Roles() {
				have[role] = struct{}{}
			}
			for needed := range want {
				if _, ok := have[needed]; !ok {
					http.Error(w, "", http.StatusForbidden)
					return
				}
			}
			r = r.WithContext(context.WithValue(r.Context(), identityCtxKey, id))
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole returns middleware that requires the identity to have at least
// one of the given roles. Unauthenticated requests receive 401; authenticated
// requests missing all roles receive 403.
func RequireAnyRole(provider IdentityProvider, roles []string, opts ...AuthOption) func(http.Handler) http.Handler {
	cfg := buildAuthConfig(opts)
	want := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		want[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := provider.GetIdentity(r)
			if err != nil || id == nil {
				authFail(w, r, ErrUnauthorized, http.StatusUnauthorized, cfg)
				return
			}
			for _, role := range id.Roles() {
				if _, ok := want[role]; ok {
					r = r.WithContext(context.WithValue(r.Context(), identityCtxKey, id))
					next.ServeHTTP(w, r)
					return
				}
			}
			authFail(w, r, ErrForbidden, http.StatusForbidden, cfg)
		})
	}
}
