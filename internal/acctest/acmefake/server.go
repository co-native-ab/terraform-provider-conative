// Package acmefake is an in-repository fake of an RFC 8555 certificate authority: it
// verifies every JWS, keeps accounts by key, runs orders with dns-01 challenges that it
// validates against the shared DNS store, finalizes with a signing request and issues
// from a per-run authority. It implements only the protocol subset the provider uses.
package acmefake

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/dnsstore"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/fakehttp"
)

// AccountInfo describes an account at the fake.
type AccountInfo struct {
	URL     string
	Contact []string
}

type account struct {
	id      string
	url     string
	pub     crypto.PublicKey
	thumb   string
	contact []string
}

type challenge struct {
	id, authzID, token string
	status             string
}

type authz struct {
	id, accountID string
	identifier    string // as ordered, possibly with *.
	status        string
	challenge     *challenge
	problem       string
}

type order struct {
	id, accountID string
	identifiers   []string
	authzIDs      []string
	certID        string
	finalized     bool
}

type issued struct {
	chain [][]byte
	leaf  *x509.Certificate
}

// Server is the fake.
type Server struct {
	*fakehttp.Server
	Journal *fakehttp.Journal

	store *dnsstore.Store
	ca    *CA

	mu           sync.Mutex
	nonces       map[string]bool
	accounts     map[string]*account // by thumbprint
	accountsByID map[string]*account
	orders       map[string]*order
	authzs       map[string]*authz
	challenges   map[string]*challenge
	certs        map[string]*issued
	revoked      map[string]bool
	seq          int

	validity       time.Duration
	failValidation map[string]bool
	wrongKey       bool
	failFinalize   bool
	fail5xx        int
	rejectNonce    bool
	revokeRefused  bool
}

// Start serves the fake over HTTPS.
func Start(cert tls.Certificate, store *dnsstore.Store) (*Server, error) {
	ca, err := NewCA()
	if err != nil {
		return nil, err
	}
	s := &Server{
		Journal: &fakehttp.Journal{}, store: store, ca: ca,
		nonces: map[string]bool{}, accounts: map[string]*account{}, accountsByID: map[string]*account{},
		orders: map[string]*order{}, authzs: map[string]*authz{}, challenges: map[string]*challenge{},
		certs: map[string]*issued{}, revoked: map[string]bool{}, validity: 90 * 24 * time.Hour,
		failValidation: map[string]bool{},
	}
	s.Server = fakehttp.StartTLS(http.HandlerFunc(s.handle), cert)
	return s, nil
}

// DirectoryURL is the ACME directory URL a configuration uses.
func (s *Server) DirectoryURL() string { return s.URL + "/directory" }

// SetValidity sets how long issued certificates are valid; zero or less issues
// certificates that have already expired.
func (s *Server) SetValidity(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.validity = d
}

// FailValidation makes validation of the identifier (as ordered, for example
// "*.example.com") fail.
func (s *Server) FailValidation(identifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failValidation[identifier] = true
}

// ClearFailures removes every failure control set by FailValidation, IssueWrongKey,
// FailFinalize, Fail5xx, RejectNextNonce and RevokeRefused.
func (s *Server) ClearFailures() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failValidation = map[string]bool{}
	s.wrongKey, s.failFinalize, s.fail5xx, s.rejectNonce, s.revokeRefused = false, false, 0, false, false
}

// IssueWrongKey makes the fake issue certificates for another key than the one in the
// signing request.
func (s *Server) IssueWrongKey(b bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wrongKey = b
}

// FailFinalize makes finalization answer badCSR.
func (s *Server) FailFinalize(b bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failFinalize = b
}

// Fail5xx makes the next n POST requests answer 503.
func (s *Server) Fail5xx(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail5xx = n
}

// RejectNextNonce makes the next POST answer badNonce although its nonce is fine.
func (s *Server) RejectNextNonce() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejectNonce = true
}

// RevokeRefused makes revocation answer unauthorized.
func (s *Server) RevokeRefused(b bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeRefused = b
}

// Revoked returns the serial numbers (decimal) of revoked certificates.
func (s *Server) Revoked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.revoked {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// MarkRevoked revokes a certificate by serial from outside the provider.
func (s *Server) MarkRevoked(serial string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[serial] = true
}

// Accounts returns the accounts at the fake.
func (s *Server) Accounts() []AccountInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []AccountInfo
	for _, a := range s.accountsByID {
		out = append(out, AccountInfo{URL: a.url, Contact: slices.Clone(a.contact)})
	}
	slices.SortFunc(out, func(a, b AccountInfo) int { return strings.Compare(a.URL, b.URL) })
	return out
}

// IssuedSerials returns the serial numbers (decimal) of every issued certificate.
func (s *Server) IssuedSerials() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, c := range s.certs {
		out = append(out, c.leaf.SerialNumber.String())
	}
	slices.Sort(out)
	return out
}

func (s *Server) newID(prefix string) string {
	s.seq++
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s%d-%x", prefix, s.seq, b)
}

func (s *Server) newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	n := b64.EncodeToString(b)
	s.nonces[n] = true
	return n
}

type problem struct {
	status int
	typ    string
	detail string
}

func (s *Server) problem(w http.ResponseWriter, p problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Replay-Nonce", s.newNonce())
	w.WriteHeader(p.status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:acme:error:" + p.typ, "detail": p.detail, "status": p.status})
}

func (s *Server) reply(w http.ResponseWriter, status int, headers map[string]string, body any) {
	w.Header().Set("Replay-Nonce", s.newNonce())
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.Journal.Record(r.Method, r.URL.Path, false)
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.URL.Path {
		case "/directory":
			s.reply(w, http.StatusOK, nil, map[string]any{
				"newNonce": s.URL + "/acme/new-nonce", "newAccount": s.URL + "/acme/new-acct", "newOrder": s.URL + "/acme/new-order",
				"revokeCert": s.URL + "/acme/revoke-cert", "meta": map[string]any{"termsOfService": s.URL + "/terms"},
			})
		case "/acme/new-nonce":
			status := http.StatusOK
			if r.Method == http.MethodGet {
				status = http.StatusNoContent
			}
			s.reply(w, status, nil, nil)
		default:
			s.problem(w, problem{http.StatusNotFound, "malformed", "unknown path"})
		}
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		s.problem(w, problem{http.StatusBadRequest, "malformed", "cannot read the request"})
		return
	}
	var j flattenedJWS
	if err := json.Unmarshal(body, &j); err != nil {
		s.Journal.Record(r.Method, r.URL.Path, true)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.problem(w, problem{http.StatusBadRequest, "malformed", "the request is not a flattened JWS"})
		return
	}
	payload, perr := b64.DecodeString(j.Payload)
	write := perr != nil || (len(payload) != 0 && !bytes.Contains(payload, []byte(`"onlyReturnExisting"`)))
	s.Journal.Record(r.Method, r.URL.Path, write)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail5xx > 0 {
		s.fail5xx--
		s.problem(w, problem{http.StatusServiceUnavailable, "serverInternal", "the server is failing (test control)"})
		return
	}
	hdr, acct, p := s.authenticate(r, j)
	if p != nil {
		s.problem(w, *p)
		return
	}
	if s.rejectNonce {
		s.rejectNonce = false
		s.problem(w, problem{http.StatusBadRequest, "badNonce", "the nonce was rejected (test control)"})
		return
	}
	_ = hdr
	s.route(w, r, j, payload, hdr, acct)
}

// authenticate verifies the JWS: nonce, url, key reference and signature. For a request
// that carries a jwk, acct is nil and hdr.JWK holds the key.
func (s *Server) authenticate(r *http.Request, j flattenedJWS) (protectedHeader, *account, *problem) {
	var hdr protectedHeader
	raw, err := b64.DecodeString(j.Protected)
	if err != nil || json.Unmarshal(raw, &hdr) != nil {
		return hdr, nil, &problem{http.StatusBadRequest, "malformed", "the protected header is invalid"}
	}
	if !s.nonces[hdr.Nonce] {
		return hdr, nil, &problem{http.StatusBadRequest, "badNonce", "the nonce is unknown or was used before"}
	}
	delete(s.nonces, hdr.Nonce)
	if want := "https://" + r.Host + r.URL.RequestURI(); hdr.URL != want {
		return hdr, nil, &problem{http.StatusUnauthorized, "unauthorized", fmt.Sprintf("the url header %q is not %q", hdr.URL, want)}
	}
	if (len(hdr.JWK) > 0) == (hdr.KID != "") {
		return hdr, nil, &problem{http.StatusBadRequest, "malformed", "exactly one of jwk and kid is required"}
	}
	if len(hdr.JWK) > 0 {
		if r.URL.Path != "/acme/new-acct" {
			return hdr, nil, &problem{http.StatusBadRequest, "malformed", "jwk is allowed for newAccount only"}
		}
		pub, _, err := parseJWK(hdr.JWK)
		if err != nil {
			return hdr, nil, &problem{http.StatusBadRequest, "malformed", "the jwk is invalid: " + err.Error()}
		}
		if err := verify(pub, hdr.Alg, j); err != nil {
			return hdr, nil, &problem{http.StatusUnauthorized, "malformed", "the signature is invalid: " + err.Error()}
		}
		return hdr, nil, nil
	}
	var acct *account
	for _, a := range s.accountsByID {
		if a.url == hdr.KID {
			acct = a
		}
	}
	if acct == nil {
		return hdr, nil, &problem{http.StatusBadRequest, "accountDoesNotExist", "the kid is not a known account"}
	}
	if err := verify(acct.pub, hdr.Alg, j); err != nil {
		return hdr, nil, &problem{http.StatusUnauthorized, "malformed", "the signature is invalid: " + err.Error()}
	}
	return hdr, acct, nil
}

func (s *Server) route(w http.ResponseWriter, r *http.Request, _ flattenedJWS, payload []byte, hdr protectedHeader, acct *account) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "acme" {
		s.problem(w, problem{http.StatusNotFound, "malformed", "unknown path"})
		return
	}
	if parts[1] == "new-acct" {
		s.newAccount(w, payload, hdr)
		return
	}
	if acct == nil {
		s.problem(w, problem{http.StatusBadRequest, "malformed", "a kid is required"})
		return
	}
	switch {
	case parts[1] == "new-order":
		s.newOrder(w, payload, acct)
	case parts[1] == "acct" && len(parts) == 3:
		s.updateAccount(w, payload, acct)
	case parts[1] == "order" && len(parts) == 3:
		s.getOrder(w, parts[2], acct)
	case parts[1] == "authz" && len(parts) == 3:
		s.getAuthz(w, parts[2], acct)
	case parts[1] == "chall" && len(parts) == 3:
		s.respond(w, parts[2], acct)
	case parts[1] == "finalize" && len(parts) == 3:
		s.finalize(w, parts[2], payload, acct)
	case parts[1] == "cert" && len(parts) == 3:
		s.download(w, parts[2])
	case parts[1] == "revoke-cert":
		s.revoke(w, payload)
	default:
		s.problem(w, problem{http.StatusNotFound, "malformed", "unknown path"})
	}
}

func (s *Server) accountJSON(a *account) map[string]any {
	return map[string]any{"status": "valid", "contact": a.contact, "orders": s.URL + "/acme/orders/" + a.id}
}

func (s *Server) newAccount(w http.ResponseWriter, payload []byte, hdr protectedHeader) {
	var req struct {
		Contact              []string `json:"contact"`
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		s.problem(w, problem{http.StatusBadRequest, "malformed", "invalid payload"})
		return
	}
	pub, thumb, _ := parseJWK(hdr.JWK)
	if a := s.accounts[thumb]; a != nil {
		s.reply(w, http.StatusOK, map[string]string{"Location": a.url}, s.accountJSON(a))
		return
	}
	if req.OnlyReturnExisting {
		s.problem(w, problem{http.StatusBadRequest, "accountDoesNotExist", "no account exists for this key"})
		return
	}
	if !req.TermsOfServiceAgreed {
		s.problem(w, problem{http.StatusForbidden, "userActionRequired", "the terms of service must be agreed to"})
		return
	}
	if err := checkContacts(req.Contact); err != nil {
		s.problem(w, problem{http.StatusBadRequest, "invalidContact", err.Error()})
		return
	}
	id := s.newID("a")
	a := &account{id: id, url: s.URL + "/acme/acct/" + id, pub: pub, thumb: thumb, contact: req.Contact}
	s.accounts[thumb] = a
	s.accountsByID[id] = a
	s.reply(w, http.StatusCreated, map[string]string{"Location": a.url}, s.accountJSON(a))
}

func checkContacts(c []string) error {
	for _, x := range c {
		if !strings.HasPrefix(x, "mailto:") || strings.Contains(x, ",") {
			return fmt.Errorf("the contact %q must be a mailto: URL", x)
		}
	}
	return nil
}

func (s *Server) updateAccount(w http.ResponseWriter, payload []byte, a *account) {
	if len(payload) > 0 {
		var req struct {
			Contact []string `json:"contact"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			s.problem(w, problem{http.StatusBadRequest, "malformed", "invalid payload"})
			return
		}
		if req.Contact != nil {
			if err := checkContacts(req.Contact); err != nil {
				s.problem(w, problem{http.StatusBadRequest, "invalidContact", err.Error()})
				return
			}
			a.contact = req.Contact
		}
	}
	s.reply(w, http.StatusOK, map[string]string{"Location": a.url}, s.accountJSON(a))
}

func (s *Server) newOrder(w http.ResponseWriter, payload []byte, a *account) {
	var req struct {
		Identifiers []struct{ Type, Value string } `json:"identifiers"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || len(req.Identifiers) == 0 {
		s.problem(w, problem{http.StatusBadRequest, "malformed", "identifiers are required"})
		return
	}
	o := &order{id: s.newID("o"), accountID: a.id}
	for _, id := range req.Identifiers {
		if id.Type != "dns" || id.Value == "" {
			s.problem(w, problem{http.StatusBadRequest, "unsupportedIdentifier", "only dns identifiers are supported"})
			return
		}
		z := &authz{id: s.newID("z"), accountID: a.id, identifier: id.Value, status: "pending"}
		ch := &challenge{id: s.newID("c"), authzID: z.id, token: s.newID("t"), status: "pending"}
		z.challenge = ch
		s.authzs[z.id] = z
		s.challenges[ch.id] = ch
		o.identifiers = append(o.identifiers, id.Value)
		o.authzIDs = append(o.authzIDs, z.id)
	}
	s.orders[o.id] = o
	s.reply(w, http.StatusCreated, map[string]string{"Location": s.URL + "/acme/order/" + o.id}, s.orderJSON(o))
}

func (s *Server) orderStatus(o *order) string {
	all := true
	for _, id := range o.authzIDs {
		switch s.authzs[id].status {
		case "invalid":
			return "invalid"
		case "valid":
		default:
			all = false
		}
	}
	switch {
	case o.certID != "":
		return "valid"
	case all:
		return "ready"
	}
	return "pending"
}

func (s *Server) orderJSON(o *order) map[string]any {
	ids := make([]map[string]string, len(o.identifiers))
	for i, v := range o.identifiers {
		ids[i] = map[string]string{"type": "dns", "value": v}
	}
	authzs := make([]string, len(o.authzIDs))
	for i, id := range o.authzIDs {
		authzs[i] = s.URL + "/acme/authz/" + id
	}
	m := map[string]any{
		"status": s.orderStatus(o), "expires": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"identifiers": ids, "authorizations": authzs, "finalize": s.URL + "/acme/finalize/" + o.id,
	}
	if o.certID != "" {
		m["certificate"] = s.URL + "/acme/cert/" + o.certID
	}
	if s.orderStatus(o) == "invalid" {
		m["error"] = map[string]any{"type": "urn:ietf:params:acme:error:unauthorized", "detail": "an authorization failed", "status": 403}
	}
	return m
}

func (s *Server) getOrder(w http.ResponseWriter, id string, a *account) {
	o := s.orders[id]
	if o == nil || o.accountID != a.id {
		s.problem(w, problem{http.StatusNotFound, "malformed", "no such order"})
		return
	}
	s.reply(w, http.StatusOK, map[string]string{"Location": s.URL + "/acme/order/" + id}, s.orderJSON(o))
}

func (s *Server) authzJSON(z *authz) map[string]any {
	value, wildcard := strings.TrimPrefix(z.identifier, "*."), strings.HasPrefix(z.identifier, "*.")
	m := map[string]any{
		"status": z.status, "identifier": map[string]string{"type": "dns", "value": value}, "wildcard": wildcard,
		"expires": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"challenges": []map[string]any{{
			"type": "dns-01", "url": s.URL + "/acme/chall/" + z.challenge.id, "token": z.challenge.token, "status": z.challenge.status,
		}},
	}
	if z.problem != "" {
		m["challenges"].([]map[string]any)[0]["error"] = map[string]any{"type": "urn:ietf:params:acme:error:unauthorized", "detail": z.problem, "status": 403}
	}
	return m
}

func (s *Server) getAuthz(w http.ResponseWriter, id string, a *account) {
	z := s.authzs[id]
	if z == nil || z.accountID != a.id {
		s.problem(w, problem{http.StatusNotFound, "malformed", "no such authorization"})
		return
	}
	s.reply(w, http.StatusOK, nil, s.authzJSON(z))
}

// respond validates a dns-01 challenge synchronously against the shared DNS store.
func (s *Server) respond(w http.ResponseWriter, id string, a *account) {
	ch := s.challenges[id]
	if ch == nil {
		s.problem(w, problem{http.StatusNotFound, "malformed", "no such challenge"})
		return
	}
	z := s.authzs[ch.authzID]
	if z.accountID != a.id {
		s.problem(w, problem{http.StatusUnauthorized, "unauthorized", "the challenge belongs to another account"})
		return
	}
	if z.status == "pending" {
		sum := sha256.Sum256([]byte(ch.token + "." + a.thumb))
		want := b64.EncodeToString(sum[:])
		fqdn := "_acme-challenge." + strings.TrimPrefix(z.identifier, "*.")
		switch {
		case s.failValidation[z.identifier]:
			z.status, ch.status, z.problem = "invalid", "invalid", "validation of "+z.identifier+" failed (test control)"
		case !slices.Contains(s.store.Values(fqdn), want):
			z.status, ch.status, z.problem = "invalid", "invalid", fmt.Sprintf("no TXT record with the expected value at %s", fqdn)
		default:
			z.status, ch.status = "valid", "valid"
		}
	}
	out := map[string]any{"type": "dns-01", "url": s.URL + "/acme/chall/" + ch.id, "token": ch.token, "status": ch.status}
	s.reply(w, http.StatusOK, nil, out)
}

func (s *Server) finalize(w http.ResponseWriter, id string, payload []byte, a *account) {
	o := s.orders[id]
	if o == nil || o.accountID != a.id {
		s.problem(w, problem{http.StatusNotFound, "malformed", "no such order"})
		return
	}
	if s.orderStatus(o) != "ready" {
		s.problem(w, problem{http.StatusForbidden, "orderNotReady", "the order is " + s.orderStatus(o)})
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		s.problem(w, problem{http.StatusBadRequest, "malformed", "invalid payload"})
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(req.CSR, "="))
	if err != nil {
		s.problem(w, problem{http.StatusBadRequest, "badCSR", "the csr is not base64url"})
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		s.problem(w, problem{http.StatusBadRequest, "badCSR", "the signing request is invalid"})
		return
	}
	want := slices.Clone(o.identifiers)
	got := slices.Clone(csr.DNSNames)
	slices.Sort(want)
	slices.Sort(got)
	if s.failFinalize || !slices.Equal(slices.Compact(want), slices.Compact(got)) {
		s.problem(w, problem{http.StatusBadRequest, "badCSR", "the names of the signing request do not match the order"})
		return
	}
	pub := csr.PublicKey
	if s.wrongKey {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub = &k.PublicKey
	}
	chain, leaf, err := s.ca.Issue(pub, csr.Subject.CommonName, csr.DNSNames, s.validity)
	if err != nil {
		s.problem(w, problem{http.StatusInternalServerError, "serverInternal", "cannot issue"})
		return
	}
	cid := s.newID("x")
	s.certs[cid] = &issued{chain: chain, leaf: leaf}
	o.certID = cid
	o.finalized = true
	s.reply(w, http.StatusOK, map[string]string{"Location": s.URL + "/acme/order/" + o.id}, s.orderJSON(o))
}

func (s *Server) download(w http.ResponseWriter, id string) {
	c := s.certs[id]
	if c == nil {
		s.problem(w, problem{http.StatusNotFound, "malformed", "no such certificate"})
		return
	}
	w.Header().Set("Replay-Nonce", s.newNonce())
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(ChainPEM(c.chain))
}

func (s *Server) revoke(w http.ResponseWriter, payload []byte) {
	var req struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		s.problem(w, problem{http.StatusBadRequest, "malformed", "invalid payload"})
		return
	}
	der, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(req.Certificate, "="))
	if err != nil {
		s.problem(w, problem{http.StatusBadRequest, "malformed", "the certificate is not base64url"})
		return
	}
	if s.revokeRefused {
		s.problem(w, problem{http.StatusForbidden, "unauthorized", "revocation is refused (test control)"})
		return
	}
	for _, c := range s.certs {
		if !bytes.Equal(c.leaf.Raw, der) {
			continue
		}
		serial := c.leaf.SerialNumber.String()
		if s.revoked[serial] {
			s.problem(w, problem{http.StatusBadRequest, "alreadyRevoked", "the certificate is already revoked"})
			return
		}
		s.revoked[serial] = true
		s.reply(w, http.StatusOK, nil, nil)
		return
	}
	s.problem(w, problem{http.StatusBadRequest, "malformed", "the certificate was not issued by this authority"})
}
