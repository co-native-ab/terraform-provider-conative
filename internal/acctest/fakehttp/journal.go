// Package fakehttp holds what the in-repository fakes of external services share: a
// request journal and a TLS test server. The fakes are imported only from test files.
package fakehttp

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
)

// Entry is one request a fake served.
type Entry struct {
	Method  string
	Path    string
	IsWrite bool
}

func (e Entry) String() string { return e.Method + " " + e.Path }

// Journal records the requests a fake served so that tests can prove what was and was
// not written.
type Journal struct {
	mu      sync.Mutex
	entries []Entry
}

// Record adds a request.
func (j *Journal) Record(method, path string, write bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries = append(j.entries, Entry{Method: method, Path: path, IsWrite: write})
}

// Mark returns a position to pass to Since or WritesSince later.
func (j *Journal) Mark() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.entries)
}

// Since returns every request after the mark.
func (j *Journal) Since(mark int) []Entry {
	j.mu.Lock()
	defer j.mu.Unlock()
	if mark > len(j.entries) {
		mark = len(j.entries)
	}
	return append([]Entry(nil), j.entries[mark:]...)
}

// WritesSince returns the requests after the mark that changed something.
func (j *Journal) WritesSince(mark int) []Entry {
	var out []Entry
	for _, e := range j.Since(mark) {
		if e.IsWrite {
			out = append(out, e)
		}
	}
	return out
}

// Server is an HTTPS server on the loopback interface.
type Server struct {
	srv *httptest.Server
	// URL is "https://localhost:<port>", the form clients trust through the per-run
	// authority.
	URL  string
	port int
}

// StartTLS serves h over HTTPS with the certificate, which must be valid for localhost.
func StartTLS(h http.Handler, cert tls.Certificate) *Server {
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	s := &Server{srv: srv}
	s.port = srv.Listener.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // the listener is TCP
	s.URL = fmt.Sprintf("https://localhost:%d", s.port)
	return s
}

// Port returns the TCP port the server listens on.
func (s *Server) Port() int { return s.port }

// Close stops the server.
func (s *Server) Close() { s.srv.Close() }
