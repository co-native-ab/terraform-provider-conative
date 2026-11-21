// Package azurednsfake is an in-repository fake of the Azure Resource Manager DNS API:
// zones and TXT record sets with ETags, writing into the shared DNS store.
package azurednsfake

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/dnsstore"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/fakehttp"
)

type set struct {
	etag    int
	ttl     int
	records [][]string
}

type zone struct {
	sub, rg, name string
	sets          map[string]*set // by relative name
}

// Server is the fake.
type Server struct {
	*fakehttp.Server
	Journal *fakehttp.Journal

	token string
	store *dnsstore.Store

	mu         sync.Mutex
	zones      map[string]*zone
	failWrites bool
	failDelete bool
	etagSeq    int
	latency    atomic.Int64
}

// Start serves the fake over HTTPS. Only requests with the bearer token are accepted.
func Start(cert tls.Certificate, token string, store *dnsstore.Store) *Server {
	s := &Server{Journal: &fakehttp.Journal{}, token: token, store: store, zones: map[string]*zone{}}
	s.Server = fakehttp.StartTLS(http.HandlerFunc(s.handle), cert)
	return s
}

func key(sub, rg, name string) string { return strings.ToLower(sub + "/" + rg + "/" + name) }

// AddZone registers a zone (once).
func (s *Server) AddZone(sub, rg, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.zones[key(sub, rg, name)]; ok {
		return
	}
	s.zones[key(sub, rg, name)] = &zone{sub: sub, rg: rg, name: strings.ToLower(name), sets: map[string]*set{}}
}

// FailWrites makes every write answer 500.
func (s *Server) FailWrites(b bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrites = b
}

// FailDeletes makes every removal of a record set or value answer 500, while adding
// values still works.
func (s *Server) FailDeletes(b bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failDelete = b
}

// Reset removes every record set and clears the failure controls; zones stay.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, z := range s.zones {
		z.sets = map[string]*set{}
	}
	s.failWrites, s.failDelete = false, false
	s.latency.Store(0)
}

// Seed puts a record into a set from outside the provider, as another writer would.
func (s *Server) Seed(sub, rg, zoneName, relName string, values ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z := s.zones[key(sub, rg, zoneName)]
	st := z.sets[relName]
	if st == nil {
		st = &set{ttl: 3600}
		z.sets[relName] = st
	}
	for _, v := range values {
		st.records = append(st.records, []string{v})
	}
	s.bump(st)
	s.mirror(z, relName, st)
}

// Values returns the single-string values of a set.
func (s *Server) Values(sub, rg, zoneName, relName string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	z := s.zones[key(sub, rg, zoneName)]
	if z == nil || z.sets[relName] == nil {
		return nil
	}
	var out []string
	for _, r := range z.sets[relName].records {
		out = append(out, strings.Join(r, ""))
	}
	return out
}

func (s *Server) bump(st *set) { s.etagSeq++; st.etag = s.etagSeq }

func (s *Server) mirror(z *zone, rel string, st *set) {
	var vals []string
	if st != nil {
		for _, r := range st.records {
			vals = append(vals, strings.Join(r, ""))
		}
	}
	s.store.Set(rel+"."+z.name, vals)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// SetLatency delays every request, so that concurrent clients overlap between reading and
// writing a record set.
func (s *Server) SetLatency(d time.Duration) { s.latency.Store(int64(d)) }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if d := time.Duration(s.latency.Load()); d > 0 {
		time.Sleep(d)
	}
	write := r.Method != http.MethodGet
	s.Journal.Record(r.Method, r.URL.Path, write)
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		apiError(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "the access token is not accepted")
		return
	}
	if r.URL.Query().Get("api-version") != "2018-05-01" {
		apiError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "unexpected api-version")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// subscriptions/{s}/resourceGroups/{rg}/providers/Microsoft.Network/dnsZones/{zone}[/TXT/{rel}]
	if len(parts) < 8 || parts[0] != "subscriptions" || parts[2] != "resourceGroups" || parts[4] != "providers" ||
		parts[5] != "Microsoft.Network" || parts[6] != "dnsZones" {
		apiError(w, http.StatusNotFound, "NotFound", "unknown path")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	z := s.zones[key(parts[1], parts[3], parts[7])]
	if z == nil {
		apiError(w, http.StatusNotFound, "ResourceNotFound", "the DNS zone was not found")
		return
	}
	switch {
	case len(parts) == 8 && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"id": r.URL.Path, "name": z.name,
			"properties": map[string]any{"nameServers": []string{"ns1.example.org."}},
		})
	case len(parts) == 10 && parts[8] == "TXT":
		s.recordSet(w, r, z, parts[9])
	default:
		apiError(w, http.StatusNotFound, "NotFound", "unknown path")
	}
}

type setBody struct {
	Properties struct {
		TTL        int               `json:"TTL"`
		Metadata   map[string]string `json:"metadata,omitempty"`
		TXTRecords []struct {
			Value []string `json:"value"`
		} `json:"TXTRecords"`
	} `json:"properties"`
}

func (s *Server) recordSet(w http.ResponseWriter, r *http.Request, z *zone, rel string) {
	st := z.sets[rel]
	etag := func(st *set) string { return fmt.Sprintf("\"etag-%d\"", st.etag) }
	if r.Method != http.MethodGet && (s.failWrites || (s.failDelete && s.removes(r, st))) {
		apiError(w, http.StatusInternalServerError, "InternalServerError", "writes are failing (test control)")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if st == nil {
			apiError(w, http.StatusNotFound, "ResourceNotFound", "the record set was not found")
			return
		}
		body := map[string]any{"etag": etag(st), "properties": map[string]any{"TTL": st.ttl, "TXTRecords": recordsJSON(st.records)}}
		w.Header().Set("ETag", etag(st))
		writeJSON(w, http.StatusOK, body)
	case http.MethodPut:
		var b setBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			apiError(w, http.StatusBadRequest, "BadRequest", "invalid body")
			return
		}
		status := http.StatusOK
		if st == nil {
			if r.Header.Get("If-None-Match") != "*" {
				apiError(w, http.StatusPreconditionFailed, "PreconditionFailed", "If-None-Match: * is required to create a record set")
				return
			}
			st = &set{}
			z.sets[rel] = st
			status = http.StatusCreated
		} else if r.Header.Get("If-None-Match") == "*" || r.Header.Get("If-Match") != etag(st) {
			apiError(w, http.StatusPreconditionFailed, "PreconditionFailed", "the record set changed")
			return
		}
		st.ttl = b.Properties.TTL
		st.records = nil
		for _, rec := range b.Properties.TXTRecords {
			st.records = append(st.records, rec.Value)
		}
		s.bump(st)
		s.mirror(z, rel, st)
		w.Header().Set("ETag", etag(st))
		writeJSON(w, status, map[string]any{"etag": etag(st), "properties": map[string]any{"TTL": st.ttl, "TXTRecords": recordsJSON(st.records)}})
	case http.MethodDelete:
		if st == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Header.Get("If-Match") != etag(st) {
			apiError(w, http.StatusPreconditionFailed, "PreconditionFailed", "the record set changed")
			return
		}
		delete(z.sets, rel)
		s.mirror(z, rel, nil)
		w.WriteHeader(http.StatusOK)
	default:
		apiError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "unsupported method")
	}
}

// removes reports whether a write takes values away from a set: a delete, or a put with
// fewer records than the set holds.
func (s *Server) removes(r *http.Request, st *set) bool {
	if r.Method == http.MethodDelete {
		return true
	}
	if r.Method != http.MethodPut || st == nil {
		return false
	}
	var b setBody
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	if json.Unmarshal(body, &b) != nil {
		return false
	}
	return len(b.Properties.TXTRecords) < len(st.records)
}

func recordsJSON(records [][]string) []map[string][]string {
	out := make([]map[string][]string, len(records))
	for i, r := range records {
		out[i] = map[string][]string{"value": r}
	}
	return out
}
