package dorman

import (
	"bufio"
	"net"
	"net/http"
)

// flusherHijackerRecorder is an httptest.ResponseRecorder-like type that also
// implements http.Flusher and http.Hijacker for testing interface forwarding.
type flusherHijackerRecorder struct {
	http.ResponseWriter
	flushed  bool
	hijacked bool
}

func (f *flusherHijackerRecorder) Flush() {
	f.flushed = true
}

func (f *flusherHijackerRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	f.hijacked = true
	return nil, nil, nil
}

// plainResponseWriter is a minimal ResponseWriter that does NOT implement
// http.Flusher or http.Hijacker. Used to test that delegation gracefully
// handles missing optional interfaces.
type plainResponseWriter struct {
	code   int
	header http.Header
}

func newPlainResponseWriter() *plainResponseWriter {
	return &plainResponseWriter{header: make(http.Header)}
}

func (p *plainResponseWriter) Header() http.Header         { return p.header }
func (p *plainResponseWriter) Write(b []byte) (int, error)  { return len(b), nil }
func (p *plainResponseWriter) WriteHeader(code int)         { p.code = code }
