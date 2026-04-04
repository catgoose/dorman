package porter

import (
	"io"
	"net/http"
	"sync"
)

// MaxBodyConfig configures the request body size limiting middleware.
type MaxBodyConfig struct {
	// Default is the maximum number of bytes allowed for request bodies.
	// When zero, no limit is applied unless a per-path limit matches.
	Default int64
	// PerPath maps exact request paths to their individual byte limits.
	// A per-path entry overrides Default for that path.
	PerPath map[string]int64
	// ErrorHandler is called when the request body exceeds the configured limit.
	// When nil, a bare 413 Request Entity Too Large response is written.
	ErrorHandler func(http.ResponseWriter, *http.Request)
}

// maxBodyWriter intercepts WriteHeader to detect when the downstream handler
// writes a 413 status after hitting the MaxBytesReader limit. When a custom
// ErrorHandler is configured, it takes over the response instead.
type maxBodyWriter struct {
	http.ResponseWriter
	errorHandler func(http.ResponseWriter, *http.Request)
	request      *http.Request
	intercepted  bool
	once         sync.Once
}

func (m *maxBodyWriter) WriteHeader(code int) {
	if code == http.StatusRequestEntityTooLarge && m.errorHandler != nil {
		m.once.Do(func() {
			m.intercepted = true
			m.errorHandler(m.ResponseWriter, m.request)
		})
		return
	}
	m.ResponseWriter.WriteHeader(code)
}

func (m *maxBodyWriter) Write(b []byte) (int, error) {
	if m.intercepted {
		return io.Discard.(io.Writer).Write(b)
	}
	return m.ResponseWriter.Write(b)
}

// MaxRequestBody returns middleware that limits request body size using
// [http.MaxBytesReader]. Each request's body is wrapped so that reading
// beyond the allowed number of bytes returns an error and closes the reader.
//
// When a request exceeds the limit and no ErrorHandler is set, the downstream
// handler receives the error from the reader and is responsible for writing the
// response (typically 413). When ErrorHandler is set, the middleware intercepts
// any 413 response from the downstream handler and calls ErrorHandler instead.
func MaxRequestBody(cfg MaxBodyConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit := cfg.Default
			if pathLimit, ok := cfg.PerPath[r.URL.Path]; ok {
				limit = pathLimit
			}
			if limit > 0 {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			if cfg.ErrorHandler != nil && limit > 0 {
				w = &maxBodyWriter{
					ResponseWriter: w,
					errorHandler:   cfg.ErrorHandler,
					request:        r,
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
