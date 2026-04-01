package porter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mockSettingsRepo is an in-memory SessionSettingsProvider for tests.
type mockSettingsRepo struct {
	store      map[string]*SessionSettings
	upsertErr  error
	touchErr   error
	getErr     error
	touchCalls []string
}

func newMockRepo() *mockSettingsRepo {
	return &mockSettingsRepo{store: make(map[string]*SessionSettings)}
}

func (m *mockSettingsRepo) GetByUUID(_ context.Context, uuid string) (*SessionSettings, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	s, ok := m.store[uuid]
	if !ok {
		return nil, nil
	}
	return s, nil
}

func (m *mockSettingsRepo) Upsert(_ context.Context, s *SessionSettings) error {
	if m.upsertErr != nil {
		return m.upsertErr
	}
	m.store[s.SessionUUID] = s
	return nil
}

func (m *mockSettingsRepo) Touch(_ context.Context, uuid string) error {
	m.touchCalls = append(m.touchCalls, uuid)
	return m.touchErr
}

// uuidPattern validates the UUID v4 format produced by randomUUID.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// --- SessionSettingsMiddleware ---

func TestSessionSettingsMiddleware_NilIDFunc_CreatesCookie(t *testing.T) {
	repo := newMockRepo()
	mw := SessionSettingsMiddleware(repo, nil)

	var capturedSettings *SessionSettings
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSettings = GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, capturedSettings)
	require.True(t, uuidPattern.MatchString(capturedSettings.SessionUUID),
		"expected UUID v4, got %q", capturedSettings.SessionUUID)

	// Cookie should have been set.
	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "porter_session_id" {
			sessionCookie = c
		}
	}
	require.NotNil(t, sessionCookie, "expected porter_session_id cookie")
	require.Equal(t, capturedSettings.SessionUUID, sessionCookie.Value)
}

func TestSessionSettingsMiddleware_NilIDFunc_CustomCookieName(t *testing.T) {
	repo := newMockRepo()
	cfg := SessionConfig{CookieName: "my_app_session"}
	mw := SessionSettingsMiddleware(repo, nil, cfg)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "my_app_session" {
			found = true
		}
	}
	require.True(t, found, "expected my_app_session cookie")
}

func TestSessionSettingsMiddleware_CustomIDFunc(t *testing.T) {
	repo := newMockRepo()
	idFunc := func(r *http.Request) string {
		return r.Header.Get("X-Session-ID")
	}
	mw := SessionSettingsMiddleware(repo, idFunc)

	var capturedSettings *SessionSettings
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSettings = GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Session-ID", "user-session-abc")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "user-session-abc", capturedSettings.SessionUUID)

	// No session cookie should be set since idFunc returned a non-empty string.
	for _, c := range rec.Result().Cookies() {
		require.NotEqual(t, "porter_session_id", c.Name,
			"unexpected porter_session_id cookie when idFunc provides session ID")
	}
}

func TestSessionSettingsMiddleware_IDFunc_EmptyStringFallback(t *testing.T) {
	repo := newMockRepo()
	// idFunc always returns empty — middleware must fall back to cookie.
	idFunc := func(r *http.Request) string { return "" }
	mw := SessionSettingsMiddleware(repo, idFunc)

	var capturedSettings *SessionSettings
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSettings = GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.True(t, uuidPattern.MatchString(capturedSettings.SessionUUID),
		"expected UUID v4 fallback, got %q", capturedSettings.SessionUUID)

	// Cookie must be set.
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "porter_session_id" {
			found = true
		}
	}
	require.True(t, found, "expected porter_session_id cookie as fallback")
}

func TestSessionSettingsMiddleware_NewSession_UpsertsCookie(t *testing.T) {
	repo := newMockRepo()
	mw := SessionSettingsMiddleware(repo, nil)

	var capturedSettings *SessionSettings
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSettings = GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, DefaultTheme, capturedSettings.Theme)
	require.Equal(t, DefaultLayout, capturedSettings.Layout)
	// Repo should have the settings after upsert.
	stored := repo.store[capturedSettings.SessionUUID]
	require.NotNil(t, stored)
}

func TestSessionSettingsMiddleware_ExistingSession_ReturnedFromRepo(t *testing.T) {
	const sessionID = "existing-session-id"
	existing := &SessionSettings{
		SessionUUID: sessionID,
		Theme:       "dark",
		Layout:      LayoutApp,
		Extra:       map[string]string{"key": "val"},
		UpdatedAt:   time.Now(),
	}
	repo := newMockRepo()
	repo.store[sessionID] = existing

	idFunc := func(r *http.Request) string { return sessionID }
	mw := SessionSettingsMiddleware(repo, idFunc)

	var capturedSettings *SessionSettings
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSettings = GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "dark", capturedSettings.Theme)
	require.Equal(t, LayoutApp, capturedSettings.Layout)
	require.Equal(t, "val", capturedSettings.GetExtra("key"))
}

func TestSessionSettingsMiddleware_ExistingCookieUsed(t *testing.T) {
	const sessionID = "cookie-session-id"
	existing := &SessionSettings{
		SessionUUID: sessionID,
		Theme:       "dark",
		Layout:      DefaultLayout,
		UpdatedAt:   time.Now(),
	}
	repo := newMockRepo()
	repo.store[sessionID] = existing

	mw := SessionSettingsMiddleware(repo, nil)

	var capturedSettings *SessionSettings
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSettings = GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "porter_session_id", Value: sessionID})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, "dark", capturedSettings.Theme)
	// No new cookie should be set since an existing one was present.
	for _, c := range rec.Result().Cookies() {
		require.NotEqual(t, "porter_session_id", c.Name,
			"unexpected new cookie when existing session cookie was sent")
	}
}

func TestSessionSettingsMiddleware_GetErrorFallsBackToDefault(t *testing.T) {
	repo := newMockRepo()
	repo.getErr = errors.New("db unavailable")

	idFunc := func(r *http.Request) string { return "some-id" }
	mw := SessionSettingsMiddleware(repo, idFunc)

	var capturedSettings *SessionSettings
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSettings = GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	// Falls back to defaults, does not panic.
	require.Equal(t, DefaultTheme, capturedSettings.Theme)
	require.Equal(t, DefaultLayout, capturedSettings.Layout)
}

func TestSessionSettingsMiddleware_TouchCalledForStaleSession(t *testing.T) {
	const sessionID = "stale-session"
	stale := &SessionSettings{
		SessionUUID: sessionID,
		Theme:       DefaultTheme,
		Layout:      DefaultLayout,
		UpdatedAt:   time.Now().Add(-25 * time.Hour), // older than 24 h
	}
	repo := newMockRepo()
	repo.store[sessionID] = stale

	idFunc := func(r *http.Request) string { return sessionID }
	mw := SessionSettingsMiddleware(repo, idFunc)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, repo.touchCalls, sessionID)
}

func TestSessionSettingsMiddleware_TouchNotCalledForFreshSession(t *testing.T) {
	const sessionID = "fresh-session"
	fresh := &SessionSettings{
		SessionUUID: sessionID,
		Theme:       DefaultTheme,
		Layout:      DefaultLayout,
		UpdatedAt:   time.Now(), // fresh
	}
	repo := newMockRepo()
	repo.store[sessionID] = fresh

	idFunc := func(r *http.Request) string { return sessionID }
	mw := SessionSettingsMiddleware(repo, idFunc)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Empty(t, repo.touchCalls)
}

// --- GetSessionSettings ---

func TestGetSessionSettings_ReturnsFromContext(t *testing.T) {
	const sessionID = "ctx-session"
	repo := newMockRepo()
	repo.store[sessionID] = &SessionSettings{
		SessionUUID: sessionID,
		Theme:       "dark",
		Layout:      LayoutApp,
		UpdatedAt:   time.Now(),
	}

	idFunc := func(r *http.Request) string { return sessionID }
	mw := SessionSettingsMiddleware(repo, idFunc)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := GetSessionSettings(r)
		require.NotNil(t, s)
		require.Equal(t, sessionID, s.SessionUUID)
		require.Equal(t, "dark", s.Theme)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
}

func TestGetSessionSettings_NoContextReturnsDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	s := GetSessionSettings(req)
	require.NotNil(t, s)
	require.Equal(t, DefaultTheme, s.Theme)
	require.Equal(t, DefaultLayout, s.Layout)
	require.Equal(t, "", s.SessionUUID)
}

// --- NewDefaultSettings ---

func TestNewDefaultSettings(t *testing.T) {
	s := NewDefaultSettings("test-uuid")
	require.Equal(t, "test-uuid", s.SessionUUID)
	require.Equal(t, DefaultTheme, s.Theme)
	require.Equal(t, DefaultLayout, s.Layout)
	require.NotNil(t, s.Extra)
	require.Empty(t, s.Extra)
}

func TestNewDefaultSettings_EmptyUUID(t *testing.T) {
	s := NewDefaultSettings("")
	require.Equal(t, "", s.SessionUUID)
	require.Equal(t, DefaultTheme, s.Theme)
}

// --- SessionSettings helpers ---

func TestGetExtra_NilMap(t *testing.T) {
	s := &SessionSettings{}
	require.Equal(t, "", s.GetExtra("anything"))
}

func TestGetExtra_MissingKey(t *testing.T) {
	s := NewDefaultSettings("x")
	require.Equal(t, "", s.GetExtra("nonexistent"))
}

func TestGetExtra_PresentKey(t *testing.T) {
	s := NewDefaultSettings("x")
	s.Extra["foo"] = "bar"
	require.Equal(t, "bar", s.GetExtra("foo"))
}

func TestSetExtra_InitializesNilMap(t *testing.T) {
	s := &SessionSettings{}
	s.SetExtra("key", "value")
	require.NotNil(t, s.Extra)
	require.Equal(t, "value", s.Extra["key"])
}

func TestSetExtra_OverwritesExistingKey(t *testing.T) {
	s := NewDefaultSettings("x")
	s.SetExtra("key", "first")
	s.SetExtra("key", "second")
	require.Equal(t, "second", s.GetExtra("key"))
}

func TestSetExtra_MultipleKeys(t *testing.T) {
	s := NewDefaultSettings("x")
	s.SetExtra("a", "1")
	s.SetExtra("b", "2")
	require.Equal(t, "1", s.GetExtra("a"))
	require.Equal(t, "2", s.GetExtra("b"))
}

func TestMarshalExtra_NilMap(t *testing.T) {
	s := &SessionSettings{}
	data, err := s.MarshalExtra()
	require.NoError(t, err)
	require.Equal(t, "{}", data)
}

func TestMarshalExtra_EmptyMap(t *testing.T) {
	s := NewDefaultSettings("x")
	data, err := s.MarshalExtra()
	require.NoError(t, err)
	require.Equal(t, "{}", data)
}

func TestMarshalExtra_WithData(t *testing.T) {
	s := NewDefaultSettings("x")
	s.SetExtra("lang", "en")
	data, err := s.MarshalExtra()
	require.NoError(t, err)
	require.Equal(t, `{"lang":"en"}`, data)
}

func TestUnmarshalExtra_EmptyString(t *testing.T) {
	s := &SessionSettings{}
	err := s.UnmarshalExtra("")
	require.NoError(t, err)
	require.NotNil(t, s.Extra)
	require.Empty(t, s.Extra)
}

func TestUnmarshalExtra_ValidJSON(t *testing.T) {
	s := &SessionSettings{}
	err := s.UnmarshalExtra(`{"lang":"fr","tz":"UTC"}`)
	require.NoError(t, err)
	require.Equal(t, "fr", s.GetExtra("lang"))
	require.Equal(t, "UTC", s.GetExtra("tz"))
}

func TestUnmarshalExtra_InvalidJSON(t *testing.T) {
	s := &SessionSettings{}
	err := s.UnmarshalExtra(`not-json`)
	require.Error(t, err)
}

func TestMarshalUnmarshalExtra_RoundTrip(t *testing.T) {
	s := NewDefaultSettings("x")
	s.SetExtra("sidebar", "collapsed")
	s.SetExtra("page_size", "50")

	data, err := s.MarshalExtra()
	require.NoError(t, err)

	s2 := &SessionSettings{}
	err = s2.UnmarshalExtra(data)
	require.NoError(t, err)
	require.Equal(t, "collapsed", s2.GetExtra("sidebar"))
	require.Equal(t, "50", s2.GetExtra("page_size"))
}

// Compile-time interface check.
var _ SessionSettingsProvider = (*mockSettingsRepo)(nil)
