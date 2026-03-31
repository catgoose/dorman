package porter

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// staticProvider always returns the configured identity (or error).
type staticProvider struct {
	identity Identity
	err      error
}

func (p *staticProvider) GetIdentity(echo.Context) (Identity, error) {
	return p.identity, p.err
}

func newTestContext() (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func TestRequireAuth_NoIdentity(t *testing.T) {
	provider := &staticProvider{err: ErrNoIdentity}
	mw := RequireAuth(provider)

	c, rec := newTestContext()
	handler := mw(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireAuth_WithIdentity(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"viewer"}}
	provider := &staticProvider{identity: id}
	mw := RequireAuth(provider)

	c, rec := newTestContext()
	handler := mw(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "ok", rec.Body.String())
}

func TestRequireRole_HasRole(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"admin", "viewer"}}
	provider := &staticProvider{identity: id}
	mw := RequireRole(provider, "admin")

	c, rec := newTestContext()
	handler := mw(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireRole_MissingRole(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"viewer"}}
	provider := &staticProvider{identity: id}
	mw := RequireRole(provider, "admin")

	c, rec := newTestContext()
	handler := mw(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireAnyRole_HasOneOf(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"editor"}}
	provider := &staticProvider{identity: id}
	mw := RequireAnyRole(provider, "admin", "editor")

	c, rec := newTestContext()
	handler := mw(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireAnyRole_HasNone(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"viewer"}}
	provider := &staticProvider{identity: id}
	mw := RequireAnyRole(provider, "admin", "editor")

	c, rec := newTestContext()
	handler := mw(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestGetIdentity_FromContext(t *testing.T) {
	id := SimpleIdentity{ID: "user-42", RoleList: []string{"admin"}}
	provider := &staticProvider{identity: id}
	mw := RequireAuth(provider)

	c, _ := newTestContext()
	handler := mw(func(c echo.Context) error {
		got := GetIdentity(c)
		require.NotNil(t, got)
		require.Equal(t, "user-42", got.Subject())
		require.Equal(t, []string{"admin"}, got.Roles())
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	require.NoError(t, err)
}

func TestGetIdentity_NilWhenNotSet(t *testing.T) {
	c, _ := newTestContext()
	got := GetIdentity(c)
	require.Nil(t, got)
}

func TestContextIdentityProvider(t *testing.T) {
	provider := ContextIdentityProvider{ContextKey: "my_auth_identity"}

	t.Run("reads identity from context", func(t *testing.T) {
		c, _ := newTestContext()
		id := SimpleIdentity{ID: "ctx-user", RoleList: []string{"member"}}
		c.Set("my_auth_identity", id)

		got, err := provider.GetIdentity(c)
		require.NoError(t, err)
		require.Equal(t, "ctx-user", got.Subject())
		require.Equal(t, []string{"member"}, got.Roles())
	})

	t.Run("returns ErrNoIdentity when key is missing", func(t *testing.T) {
		c, _ := newTestContext()
		got, err := provider.GetIdentity(c)
		require.ErrorIs(t, err, ErrNoIdentity)
		require.Nil(t, got)
	})

	t.Run("returns ErrInvalidIdentity when value is wrong type", func(t *testing.T) {
		c, _ := newTestContext()
		c.Set("my_auth_identity", "not-an-identity")
		got, err := provider.GetIdentity(c)
		require.ErrorIs(t, err, ErrInvalidIdentity)
		require.Nil(t, got)
	})
}

// Compile-time interface checks.
var (
	_ Identity         = SimpleIdentity{}
	_ IdentityProvider = ContextIdentityProvider{}
)
