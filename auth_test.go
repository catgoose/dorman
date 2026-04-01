package porter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// staticProvider always returns the configured identity (or error).
type staticProvider struct {
	identity Identity
	err      error
}

func (p *staticProvider) GetIdentity(_ *http.Request) (Identity, error) {
	return p.identity, p.err
}

func TestRequireAuth_NoIdentity(t *testing.T) {
	provider := &staticProvider{err: ErrNoIdentity}
	mw := RequireAuth(provider)

	var called bool
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.False(t, called)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireAuth_WithIdentity(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"viewer"}}
	provider := &staticProvider{identity: id}
	mw := RequireAuth(provider)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "ok", rec.Body.String())
}

func TestRequireRole_HasRole(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"admin", "viewer"}}
	provider := &staticProvider{identity: id}
	mw := RequireRole(provider, "admin")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireRole_MissingRole(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"viewer"}}
	provider := &staticProvider{identity: id}
	mw := RequireRole(provider, "admin")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireAnyRole_HasOneOf(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"editor"}}
	provider := &staticProvider{identity: id}
	mw := RequireAnyRole(provider, "admin", "editor")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireAnyRole_HasNone(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"viewer"}}
	provider := &staticProvider{identity: id}
	mw := RequireAnyRole(provider, "admin", "editor")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestGetIdentity_FromContext(t *testing.T) {
	id := SimpleIdentity{ID: "user-42", RoleList: []string{"admin"}}
	provider := &staticProvider{identity: id}
	mw := RequireAuth(provider)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := GetIdentity(r)
		require.NotNil(t, got)
		require.Equal(t, "user-42", got.Subject())
		require.Equal(t, []string{"admin"}, got.Roles())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
}

func TestGetIdentity_NilWhenNotSet(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got := GetIdentity(req)
	require.Nil(t, got)
}

type testCtxKey struct{}

func TestContextIdentityProvider(t *testing.T) {
	key := testCtxKey{}
	provider := ContextIdentityProvider{ContextKey: key}

	t.Run("reads identity from context", func(t *testing.T) {
		id := SimpleIdentity{ID: "ctx-user", RoleList: []string{"member"}}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), key, id))

		got, err := provider.GetIdentity(req)
		require.NoError(t, err)
		require.Equal(t, "ctx-user", got.Subject())
		require.Equal(t, []string{"member"}, got.Roles())
	})

	t.Run("returns ErrNoIdentity when key is missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		got, err := provider.GetIdentity(req)
		require.ErrorIs(t, err, ErrNoIdentity)
		require.Nil(t, got)
	})

	t.Run("returns ErrInvalidIdentity when value is wrong type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), key, "not-an-identity"))
		got, err := provider.GetIdentity(req)
		require.ErrorIs(t, err, ErrInvalidIdentity)
		require.Nil(t, got)
	})
}

// Compile-time interface checks.
var (
	_ Identity         = SimpleIdentity{}
	_ IdentityProvider = ContextIdentityProvider{}
)
