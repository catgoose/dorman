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
		_, _ = w.Write([]byte("ok"))
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
		_, _ = w.Write([]byte("ok"))
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
		_, _ = w.Write([]byte("ok"))
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
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireAnyRole_HasOneOf(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"editor"}}
	provider := &staticProvider{identity: id}
	mw := RequireAnyRole(provider, []string{"admin", "editor"})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireAnyRole_HasNone(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"viewer"}}
	provider := &staticProvider{identity: id}
	mw := RequireAnyRole(provider, []string{"admin", "editor"})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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
		_, _ = w.Write([]byte("ok"))
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

// TestRequireAnyRole_NilIdentityNoError covers the branch where the provider
// returns nil identity with no error, which should result in 401.
func TestRequireAnyRole_NilIdentityNoError(t *testing.T) {
	provider := &staticProvider{identity: nil, err: nil}
	mw := RequireAnyRole(provider, []string{"admin"})

	var called bool
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.False(t, called)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuthErrorHandler_RequireAuth(t *testing.T) {
	provider := &staticProvider{err: ErrNoIdentity}

	var gotErr error
	handler := RequireAuth(provider, AuthErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
		gotErr = err
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("please log in"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	require.ErrorIs(t, gotErr, ErrUnauthorized)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Equal(t, "please log in", rec.Body.String())
}

func TestAuthErrorHandler_RequireRole_Forbidden(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"viewer"}}
	provider := &staticProvider{identity: id}

	var gotErr error
	handler := RequireRole(provider, "admin", AuthErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
		gotErr = err
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("no access"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	require.ErrorIs(t, gotErr, ErrForbidden)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, "no access", rec.Body.String())
}

func TestAuthErrorHandler_RequireRole_Unauthorized(t *testing.T) {
	provider := &staticProvider{err: ErrNoIdentity}

	var gotErr error
	handler := RequireRole(provider, "admin", AuthErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
		gotErr = err
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("login required"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	require.ErrorIs(t, gotErr, ErrUnauthorized)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Equal(t, "login required", rec.Body.String())
}

func TestAuthErrorHandler_RequireAnyRole(t *testing.T) {
	id := SimpleIdentity{ID: "user-1", RoleList: []string{"viewer"}}
	provider := &staticProvider{identity: id}

	var gotErr error
	handler := RequireAnyRole(provider, []string{"admin", "editor"}, AuthErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
		gotErr = err
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("insufficient role"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	require.ErrorIs(t, gotErr, ErrForbidden)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, "insufficient role", rec.Body.String())
}

func TestAuthErrorHandler_DefaultBehaviorUnchanged(t *testing.T) {
	t.Run("RequireAuth without options", func(t *testing.T) {
		provider := &staticProvider{err: ErrNoIdentity}
		mw := RequireAuth(provider)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)

		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("RequireRole without options", func(t *testing.T) {
		id := SimpleIdentity{ID: "user-1", RoleList: []string{"viewer"}}
		provider := &staticProvider{identity: id}
		mw := RequireRole(provider, "admin")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)

		require.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("RequireAnyRole without options", func(t *testing.T) {
		id := SimpleIdentity{ID: "user-1", RoleList: []string{"viewer"}}
		provider := &staticProvider{identity: id}
		mw := RequireAnyRole(provider, []string{"admin"})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)

		require.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestRequireAllRoles(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	tests := []struct {
		name     string
		provider *staticProvider
		roles    []string
		wantCode int
	}{
		{
			name:     "has all roles",
			provider: &staticProvider{identity: SimpleIdentity{ID: "u1", RoleList: []string{"admin", "editor", "viewer"}}},
			roles:    []string{"admin", "editor"},
			wantCode: http.StatusOK,
		},
		{
			name:     "missing one role",
			provider: &staticProvider{identity: SimpleIdentity{ID: "u1", RoleList: []string{"editor"}}},
			roles:    []string{"admin", "editor"},
			wantCode: http.StatusForbidden,
		},
		{
			name:     "no identity returns 401",
			provider: &staticProvider{err: ErrNoIdentity},
			roles:    []string{"admin"},
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "nil identity no error returns 401",
			provider: &staticProvider{identity: nil, err: nil},
			roles:    []string{"admin"},
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "empty roles list allows any authenticated user",
			provider: &staticProvider{identity: SimpleIdentity{ID: "u1", RoleList: []string{"viewer"}}},
			roles:    []string{},
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := RequireAllRoles(tt.provider, tt.roles...)
			handler := mw(ok)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			require.Equal(t, tt.wantCode, rec.Code)
		})
	}
}

// Compile-time interface checks.
var (
	_ Identity         = SimpleIdentity{}
	_ IdentityProvider = ContextIdentityProvider{}
)
