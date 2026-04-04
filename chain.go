package porter

import "net/http"

// Chain composes middleware left-to-right so that the first argument is the
// outermost middleware (applied first on the request path). The returned
// function accepts a final http.Handler and returns the fully-wrapped handler.
//
//	handler := porter.Chain(logging, auth, csrf)(mux)
//
// is equivalent to:
//
//	handler := logging(auth(csrf(mux)))
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}
