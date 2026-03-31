package porter

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
)

// IdentityContextKey is the echo.Context key where authorization middleware
// stores the resolved [Identity]. Use [GetIdentity] to retrieve it.
const IdentityContextKey = "porter.identity"

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

// IdentityProvider extracts identity from a request context.
// Crooner's session satisfies this; porter also ships [ContextIdentityProvider]
// for reading identity set by external auth middleware.
type IdentityProvider interface {
	GetIdentity(c echo.Context) (Identity, error)
}

// ContextIdentityProvider reads identity from a key on [echo.Context].
// Use this when your auth middleware (like crooner) stores identity on the context.
type ContextIdentityProvider struct {
	// ContextKey is the key used by auth middleware to store identity.
	ContextKey string
}

func (p ContextIdentityProvider) GetIdentity(c echo.Context) (Identity, error) {
	val := c.Get(p.ContextKey)
	if val == nil {
		return nil, ErrNoIdentity
	}
	id, ok := val.(Identity)
	if !ok {
		return nil, ErrInvalidIdentity
	}
	return id, nil
}

// GetIdentity retrieves the [Identity] from the echo context. Returns nil when
// no identity has been set by authorization middleware.
func GetIdentity(c echo.Context) Identity {
	id, _ := c.Get(IdentityContextKey).(Identity)
	return id
}

// RequireAuth returns middleware that rejects unauthenticated requests with
// 401 Unauthorized. Authenticated identities are stored on the context at
// [IdentityContextKey] for downstream handlers.
func RequireAuth(provider IdentityProvider) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			id, err := provider.GetIdentity(c)
			if err != nil || id == nil {
				return c.NoContent(http.StatusUnauthorized)
			}
			c.Set(IdentityContextKey, id)
			return next(c)
		}
	}
}

// RequireRole returns middleware that requires the identity to have the given
// role. Unauthenticated requests receive 401; authenticated requests missing the
// role receive 403.
func RequireRole(provider IdentityProvider, role string) echo.MiddlewareFunc {
	return RequireAnyRole(provider, role)
}

// RequireAnyRole returns middleware that requires the identity to have at least
// one of the given roles. Unauthenticated requests receive 401; authenticated
// requests missing all roles receive 403.
func RequireAnyRole(provider IdentityProvider, roles ...string) echo.MiddlewareFunc {
	want := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		want[r] = struct{}{}
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			id, err := provider.GetIdentity(c)
			if err != nil || id == nil {
				return c.NoContent(http.StatusUnauthorized)
			}
			for _, r := range id.Roles() {
				if _, ok := want[r]; ok {
					c.Set(IdentityContextKey, id)
					return next(c)
				}
			}
			return c.NoContent(http.StatusForbidden)
		}
	}
}
