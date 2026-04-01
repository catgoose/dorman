package porter

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockSessionManager struct {
	data map[string]any
}

func (m *mockSessionManager) Get(_ *http.Request, key string) (any, error) {
	if m.data == nil {
		return nil, nil
	}
	return m.data[key], nil
}

func (m *mockSessionManager) Set(_ http.ResponseWriter, _ *http.Request, key string, value any) error {
	if m.data == nil {
		m.data = make(map[string]any)
	}
	m.data[key] = value
	return nil
}

func applyMiddleware(mw func(http.Handler) http.Handler, handler http.HandlerFunc) http.Handler {
	return mw(handler)
}

func TestCSRF_NilSessionManager_NoOp(t *testing.T) {
	handler := applyMiddleware(CSRF(nil, CSRFConfig{}), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "ok", rec.Body.String())
}

func TestCSRF_GET_CreatesToken(t *testing.T) {
	sm := &mockSessionManager{data: make(map[string]any)}
	var gotToken string
	handler := applyMiddleware(CSRF(sm, CSRFConfig{}), func(w http.ResponseWriter, r *http.Request) {
		gotToken = GetCSRFToken(r)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(gotToken))
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEmpty(t, gotToken)
	token := rec.Body.String()
	require.Len(t, token, 64)
	sessionToken, _ := sm.Get(nil, csrfTokenSessionKey)
	require.Equal(t, token, sessionToken)
}

func TestCSRF_POST_WithoutToken_403(t *testing.T) {
	sm := &mockSessionManager{data: make(map[string]any)}
	handler := applyMiddleware(CSRF(sm, CSRFConfig{}), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCSRF_POST_WithValidToken_200(t *testing.T) {
	sm := &mockSessionManager{data: make(map[string]any)}
	require.NoError(t, sm.Set(nil, nil, csrfTokenSessionKey, "abc123token"))
	handler := applyMiddleware(CSRF(sm, CSRFConfig{}), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-CSRF-Token", "abc123token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
}

func TestCSRF_POST_WithWrongToken_403(t *testing.T) {
	sm := &mockSessionManager{data: make(map[string]any)}
	require.NoError(t, sm.Set(nil, nil, csrfTokenSessionKey, "righttoken"))
	handler := applyMiddleware(CSRF(sm, CSRFConfig{}), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-CSRF-Token", "wrongtoken")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCSRF_ExemptPath_SkipsValidation(t *testing.T) {
	sm := &mockSessionManager{data: make(map[string]any)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	handler := CSRF(sm, CSRFConfig{ExemptPaths: []string{"/login", "/callback", "/logout"}})(mux)

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
}

func TestCSRF_PerRequestPath_RotatesToken(t *testing.T) {
	sm := &mockSessionManager{data: make(map[string]any)}
	var lastToken string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /form", func(w http.ResponseWriter, r *http.Request) {
		lastToken = GetCSRFToken(r)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(lastToken))
	})
	handler := CSRF(sm, CSRFConfig{PerRequestPaths: []string{"/form"}})(mux)

	req1 := httptest.NewRequest(http.MethodGet, "/form", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code)
	token1 := rec1.Body.String()

	req2 := httptest.NewRequest(http.MethodGet, "/form", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code)
	token2 := rec2.Body.String()

	require.NotEqual(t, token1, token2)
}

func Test_pathExempt(t *testing.T) {
	exempt := []string{"/login", "/callback", "/logout"}
	require.True(t, pathExempt(exempt, "/login"))
	require.True(t, pathExempt(exempt, "/callback"))
	require.True(t, pathExempt(exempt, "/logout"))
	require.False(t, pathExempt(exempt, "/"))
	require.False(t, pathExempt(exempt, "/api/login"))
}

func Test_pathPerRequest(t *testing.T) {
	paths := []string{"/form", "/edit"}
	require.True(t, pathPerRequest(paths, "/form"))
	require.True(t, pathPerRequest(paths, "/edit"))
	require.False(t, pathPerRequest(paths, "/"))
	require.False(t, pathPerRequest(paths, "/form/1"))
}

var _ CSRFSessionStore = (*mockSessionManager)(nil)
