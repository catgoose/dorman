package porter

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// tagMiddleware returns a middleware that appends tag to the X-Order header on
// the way in and writes nothing else.
func tagMiddleware(tag string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("X-Order", tag)
			next.ServeHTTP(w, r)
		})
	}
}

func TestChain_ExecutionOrder(t *testing.T) {
	chain := Chain(tagMiddleware("A"), tagMiddleware("B"), tagMiddleware("C"))

	handler := chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// A is outermost, so it runs first, then B, then C.
	require.Equal(t, []string{"A", "B", "C"}, rec.Header().Values("X-Order"))
}

func TestChain_Empty_Passthrough(t *testing.T) {
	chain := Chain()

	handler := chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Inner", "reached")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "reached", rec.Header().Get("X-Inner"))
}

func TestChain_Single(t *testing.T) {
	chain := Chain(tagMiddleware("only"))

	handler := chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, []string{"only"}, rec.Header().Values("X-Order"))
}

func TestChain_MultipleMiddleware_Composition(t *testing.T) {
	addHeader := func(key, value string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(key, value)
				next.ServeHTTP(w, r)
			})
		}
	}

	chain := Chain(
		addHeader("X-First", "1"),
		addHeader("X-Second", "2"),
		addHeader("X-Third", "3"),
	)

	handler := chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, "1", rec.Header().Get("X-First"))
	require.Equal(t, "2", rec.Header().Get("X-Second"))
	require.Equal(t, "3", rec.Header().Get("X-Third"))
	require.Equal(t, "ok", rec.Body.String())
}
