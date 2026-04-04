package porter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// echoBodyHandler reads the full request body and writes it back. If the read
// fails (e.g. MaxBytesReader limit hit), it writes a 413 response.
func echoBodyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
}

func TestMaxRequestBody_UnderLimit_PassesThrough(t *testing.T) {
	mw := MaxRequestBody(MaxBodyConfig{Default: 1024})
	handler := mw(echoBodyHandler())

	payload := strings.Repeat("a", 512)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, payload, rec.Body.String())
}

func TestMaxRequestBody_OverDefaultLimit_Returns413(t *testing.T) {
	mw := MaxRequestBody(MaxBodyConfig{Default: 64})
	handler := mw(echoBodyHandler())

	payload := strings.Repeat("a", 128)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestMaxRequestBody_PerPathAllowsLargerBody(t *testing.T) {
	mw := MaxRequestBody(MaxBodyConfig{
		Default: 64,
		PerPath: map[string]int64{
			"/upload": 1024,
		},
	})
	handler := mw(echoBodyHandler())

	payload := strings.Repeat("a", 512)
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, payload, rec.Body.String())
}

func TestMaxRequestBody_PerPathSmallerLimit(t *testing.T) {
	mw := MaxRequestBody(MaxBodyConfig{
		Default: 1024,
		PerPath: map[string]int64{
			"/tiny": 16,
		},
	})
	handler := mw(echoBodyHandler())

	payload := strings.Repeat("a", 64)
	req := httptest.NewRequest(http.MethodPost, "/tiny", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestMaxRequestBody_CustomErrorHandler(t *testing.T) {
	var called bool
	mw := MaxRequestBody(MaxBodyConfig{
		Default: 32,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.Header().Set("X-Custom-Error", "true")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_, _ = w.Write([]byte("custom: payload too large"))
		},
	})
	handler := mw(echoBodyHandler())

	payload := strings.Repeat("a", 128)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.True(t, called)
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	require.Equal(t, "true", rec.Header().Get("X-Custom-Error"))
	require.Equal(t, "custom: payload too large", rec.Body.String())
}

func TestMaxRequestBody_DefaultErrorHandler(t *testing.T) {
	mw := MaxRequestBody(MaxBodyConfig{Default: 16})
	handler := mw(echoBodyHandler())

	payload := strings.Repeat("a", 64)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestMaxRequestBody_ZeroDefault_NoLimit(t *testing.T) {
	mw := MaxRequestBody(MaxBodyConfig{})
	handler := mw(echoBodyHandler())

	payload := strings.Repeat("a", 10000)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, payload, rec.Body.String())
}

func TestMaxRequestBody_ZeroDefault_PerPathStillApplies(t *testing.T) {
	mw := MaxRequestBody(MaxBodyConfig{
		PerPath: map[string]int64{
			"/limited": 32,
		},
	})
	handler := mw(echoBodyHandler())

	// Unlimited path should pass.
	payload := strings.Repeat("a", 10000)
	req := httptest.NewRequest(http.MethodPost, "/other", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Limited path should enforce limit.
	req = httptest.NewRequest(http.MethodPost, "/limited", strings.NewReader(strings.Repeat("a", 64)))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}
