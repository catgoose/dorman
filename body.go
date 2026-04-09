package dorman

import (
	"bufio"
	"fmt"
	"io"
	"net"
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
		return io.Discard.Write(b)
	}
	return m.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter so that [http.NewResponseController]
// can access optional interfaces on the original writer.
func (m *maxBodyWriter) Unwrap() http.ResponseWriter {
	return m.ResponseWriter
}

// Flush delegates to the underlying ResponseWriter if it implements [http.Flusher].
func (m *maxBodyWriter) Flush() {
	if f, ok := m.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack delegates to the underlying ResponseWriter if it implements [http.Hijacker].
func (m *maxBodyWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := m.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("dorman: underlying ResponseWriter does not implement http.Hijacker")
}

// Push delegates to the underlying ResponseWriter if it implements [http.Pusher].
// When the underlying writer does not support HTTP/2 server push, it returns
// [http.ErrNotSupported] to match the standard library pattern.
func (m *maxBodyWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := m.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
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
