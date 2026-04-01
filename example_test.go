package porter_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/catgoose/porter"
)

// memorySettingsRepo is a minimal in-memory SessionSettingsProvider for examples.
type memorySettingsRepo struct {
	store map[string]*porter.SessionSettings
}

func (m *memorySettingsRepo) GetByUUID(_ context.Context, uuid string) (*porter.SessionSettings, error) {
	s, ok := m.store[uuid]
	if !ok {
		return nil, nil
	}
	return s, nil
}

func (m *memorySettingsRepo) Upsert(_ context.Context, s *porter.SessionSettings) error {
	m.store[s.SessionUUID] = s
	return nil
}

func (m *memorySettingsRepo) Touch(_ context.Context, uuid string) error {
	return nil
}

// memoryCSRFStore is a minimal in-memory CSRFSessionStore for examples.
type memoryCSRFStore struct {
	data map[string]any
}

func (m *memoryCSRFStore) Get(_ *http.Request, key string) (any, error) {
	return m.data[key], nil
}

func (m *memoryCSRFStore) Set(_ http.ResponseWriter, _ *http.Request, key string, value any) error {
	m.data[key] = value
	return nil
}

func ExampleCSRF() {
	store := &memoryCSRFStore{data: make(map[string]any)}
	handler := porter.CSRF(store, porter.CSRFConfig{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := porter.GetCSRFToken(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "token_length=%d", len(token))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// token_length=64
}

func ExampleCSRF_exemptPaths() {
	store := &memoryCSRFStore{data: make(map[string]any)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /webhook", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("accepted"))
	})
	handler := porter.CSRF(store, porter.CSRFConfig{
		ExemptPaths: []string{"/webhook"},
	})(mux)

	req := httptest.NewRequest(http.MethodPost, "/webhook", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// accepted
}

func ExampleCSRF_nilStore() {
	handler := porter.CSRF(nil, porter.CSRFConfig{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("no csrf"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// no csrf
}

func ExampleCookieCSRFStore() {
	handler := porter.CSRF(porter.CookieCSRFStore{}, porter.CSRFConfig{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := porter.GetCSRFToken(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "token_length=%d", len(token))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// token_length=64
}

func ExampleSessionSettingsMiddleware() {
	repo := &memorySettingsRepo{store: make(map[string]*porter.SessionSettings)}
	handler := porter.SessionSettingsMiddleware(repo, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := porter.GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "theme=%s layout=%s", s.Theme, s.Layout)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// theme=light layout=classic
}

func ExampleSessionSettingsMiddleware_customConfig() {
	repo := &memorySettingsRepo{store: make(map[string]*porter.SessionSettings)}
	cfg := porter.SessionConfig{
		CookieName: "my_app_session",
		Logger:     slog.Default(),
	}
	handler := porter.SessionSettingsMiddleware(repo, nil, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := porter.GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "theme=%s", s.Theme)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// theme=light
}

func ExampleSessionSettingsMiddleware_withIDFunc() {
	repo := &memorySettingsRepo{store: make(map[string]*porter.SessionSettings)}

	// Use a custom function to extract the session ID from the request.
	idFunc := func(r *http.Request) string {
		return r.Header.Get("X-Session-ID")
	}
	handler := porter.SessionSettingsMiddleware(repo, idFunc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := porter.GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "uuid=%s theme=%s", s.SessionUUID, s.Theme)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Session-ID", "user-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// uuid=user-123 theme=light
}

func ExampleGetSessionSettings() {
	repo := &memorySettingsRepo{store: make(map[string]*porter.SessionSettings)}
	handler := porter.SessionSettingsMiddleware(repo, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := porter.GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(s.Theme))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	fmt.Println(rec.Body.String())
	// Output:
	// light
}

func ExampleNewDefaultSettings() {
	s := porter.NewDefaultSettings("abc-123")
	fmt.Println(s.SessionUUID)
	fmt.Println(s.Theme)
	fmt.Println(s.Layout)
	// Output:
	// abc-123
	// light
	// classic
}
