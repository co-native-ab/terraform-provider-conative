// Package cloudflarefake is an in-repository fake of the parts of the Cloudflare API v4
// the provider uses: zones by name and TXT records, writing into the shared DNS store.
package cloudflarefake

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/dnsstore"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/fakehttp"
)

type record struct {
	zoneID  string
	name    string
	content string
}

// Server is the fake.
type Server struct {
	*fakehttp.Server
	Journal *fakehttp.Journal

	store *dnsstore.Store

	mu         sync.Mutex
	zones      map[string]string          // name -> id
	tokens     map[string]map[string]bool // token -> zone IDs it may use
	records    map[string]record          // id -> record
	seq        int
	failWrites bool
	failDelete bool
	readOnly   map[string]bool // tokens that may only read
}

// Start serves the fake over HTTPS. The API path prefix is /client/v4.
func Start(cert tls.Certificate, store *dnsstore.Store) *Server {
	s := &Server{
		Journal: &fakehttp.Journal{}, store: store,
		readOnly: map[string]bool{}, zones: map[string]string{}, tokens: map[string]map[string]bool{}, records: map[string]record{},
	}
	s.Server = fakehttp.StartTLS(http.HandlerFunc(s.handle), cert)
	return s
}

// APIURL is the base URL a client uses, including the version path.
func (s *Server) APIURL() string { return s.URL + "/client/v4" }

// AddZone registers a zone (once) and returns its ID.
func (s *Server) AddZone(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.zones[strings.ToLower(name)]; ok {
		return id
	}
	s.seq++
	id := fmt.Sprintf("zone%04d", s.seq)
	s.zones[strings.ToLower(name)] = id
	return id
}

// AddToken registers a token that may read and edit the zones with the given names.
func (s *Server) AddToken(token string, zoneNames ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	allowed := map[string]bool{}
	for _, n := range zoneNames {
		allowed[s.zones[strings.ToLower(n)]] = true
	}
	s.tokens[token] = allowed
}

// AddReadOnlyToken registers a token that may read the zones with the given names but
// whose every write (POST, PUT, PATCH, DELETE) answers 403.
func (s *Server) AddReadOnlyToken(token string, zoneNames ...string) {
	s.AddToken(token, zoneNames...)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readOnly[token] = true
}

// FailWrites makes every write answer 500.
func (s *Server) FailWrites(b bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrites = b
}

// FailDeletes makes every record deletion answer 500, while creating still works.
func (s *Server) FailDeletes(b bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failDelete = b
}

// Reset removes every record and clears the failure controls; zones and tokens stay.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = map[string]record{}
	s.failWrites, s.failDelete = false, false
}

// Seed puts a TXT record into a zone from outside the provider and returns its ID.
func (s *Server) Seed(zoneName, fqdn, content string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	id := fmt.Sprintf("rec%04d", s.seq)
	s.records[id] = record{zoneID: s.zones[strings.ToLower(zoneName)], name: fqdn, content: content}
	s.store.Add(fqdn, content)
	return id
}

// RecordCount returns the number of TXT records in the zone.
func (s *Server) RecordCount(zoneName string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.records {
		if r.zoneID == s.zones[strings.ToLower(zoneName)] {
			n++
		}
	}
	return n
}

type envelope struct {
	Success  bool             `json:"success"`
	Errors   []map[string]any `json:"errors"`
	Messages []string         `json:"messages"`
	Result   any              `json:"result"`
}

func reply(w http.ResponseWriter, status int, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{Success: true, Errors: []map[string]any{}, Messages: []string{}, Result: result})
}

func fail(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{Success: false, Errors: []map[string]any{{"code": code, "message": msg}}, Messages: []string{}})
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.Journal.Record(r.Method, r.URL.Path, r.Method != http.MethodGet)
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	defer s.mu.Unlock()
	allowed, ok := s.tokens[token]
	if !ok || token == "" {
		fail(w, http.StatusUnauthorized, 10000, "Authentication error")
		return
	}
	if s.readOnly[token] && r.Method != http.MethodGet {
		fail(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource (the token can only read)")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case path == "/zones" && r.Method == http.MethodGet:
		var out []map[string]any
		if id, found := s.zones[strings.ToLower(r.URL.Query().Get("name"))]; found && allowed[id] {
			out = append(out, map[string]any{"id": id, "name": r.URL.Query().Get("name"), "name_servers": []string{"ns1.example.org"}})
		}
		reply(w, http.StatusOK, out)
	case len(parts) == 3 && parts[0] == "zones" && parts[2] == "dns_records" && r.Method == http.MethodPost:
		if !allowed[parts[1]] {
			fail(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")
			return
		}
		if s.failWrites {
			fail(w, http.StatusInternalServerError, 1000, "writes are failing (test control)")
			return
		}
		var b struct{ Type, Name, Content string }
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Type != "TXT" || b.Name == "" {
			fail(w, http.StatusBadRequest, 9005, "invalid record")
			return
		}
		s.seq++
		id := fmt.Sprintf("rec%04d", s.seq)
		s.records[id] = record{zoneID: parts[1], name: b.Name, content: b.Content}
		s.store.Add(b.Name, b.Content)
		reply(w, http.StatusOK, map[string]any{"id": id, "type": "TXT", "name": b.Name, "content": b.Content})
	case len(parts) == 4 && parts[0] == "zones" && parts[2] == "dns_records" && r.Method == http.MethodDelete:
		if !allowed[parts[1]] {
			fail(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")
			return
		}
		if s.failWrites || s.failDelete {
			fail(w, http.StatusInternalServerError, 1000, "writes are failing (test control)")
			return
		}
		rec, found := s.records[parts[3]]
		if !found || rec.zoneID != parts[1] {
			fail(w, http.StatusNotFound, 81044, "Record does not exist.")
			return
		}
		delete(s.records, parts[3])
		s.store.Remove(rec.name, rec.content)
		reply(w, http.StatusOK, map[string]any{"id": parts[3]})
	default:
		fail(w, http.StatusNotFound, 7003, "No route for the URI")
	}
}
