// Package keyvaultfake is an in-repository fake of the parts of the Azure Key Vault
// REST API the provider uses: keys (get, sign) and certificates (create with issuer
// Unknown, pending operations, merge, versions, soft delete). It models the published
// request and response shapes and nothing else.
package keyvaultfake

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/fakehttp"
)

type keyEntry struct {
	name, version string
	signer        crypto.Signer
	fakeCurve     string // a curve name the fake cannot generate (P-256K): the JWK claims it
	signOp        bool
	enabled       bool
}

// PolicyInfo is the policy of a certificate as the fake holds it.
type PolicyInfo struct {
	Issuer          string
	Exportable      bool
	KTY             string
	KeySize         int
	Curve           string
	ReuseKey        bool
	Subject         string
	DNSNames        []string
	LifetimeActions []string
	ContentType     string
}

// VersionInfo describes a certificate version.
type VersionInfo struct {
	Version string
	Issued  bool
	Created time.Time
}

type version struct {
	id      string
	cer     []byte
	created time.Time
	issued  bool
	key     crypto.Signer
	// disabled is a version whose pending operation was cancelled before it was issued.
	disabled bool
}

// pendingOp is the pending-operation record of a certificate. Like Key Vault, the fake
// keeps it after the operation completes, with status "completed".
type pendingOp struct {
	version *version
	issuer  string
	csr     []byte
	status  string
}

const (
	statusInProgress = "inProgress"
	statusCompleted  = "completed"
)

func (p *pendingOp) inProgress() bool { return p != nil && p.status == statusInProgress }

type certificate struct {
	name     string
	versions []*version
	policy   PolicyInfo
	pending  *pendingOp
	deleted  bool
}

// Server is the fake.
type Server struct {
	*fakehttp.Server
	Journal *fakehttp.Journal

	token string

	mu             sync.Mutex
	keys           map[string]*keyEntry // "name/version"
	keyList        []*keyEntry
	certs          map[string]*certificate
	allKeys        []crypto.Signer
	violations     []string
	failStatus     int
	granted        map[string]bool // data actions the caller may use; nil grants every one
	forbidden      []string        // requests answered 403 for a missing data action
	forbidKeyReads bool
	otherCA        *x509.Certificate
	otherKey       *ecdsa.PrivateKey
	serial         int64
}

// vaultHost is the name the fake is addressed by: the provider accepts only Key Vault
// names. Clients reach the loopback listener through a dialer that maps names under
// vault.azure.net (acctest.Certs.HTTPClientWithVault).
const vaultHost = "fake.vault.azure.net"

// Start serves the fake over HTTPS. Only requests with the bearer token are accepted.
func Start(cert tls.Certificate, token string) (*Server, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other test authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	s := &Server{
		Journal: &fakehttp.Journal{}, token: token, keys: map[string]*keyEntry{}, certs: map[string]*certificate{},
		otherCA: ca, otherKey: caKey,
	}
	s.Server = fakehttp.StartTLS(http.HandlerFunc(s.handle), cert)
	s.SetHost(vaultHost)
	return s, nil
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randomHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generate(kind string) (crypto.Signer, string, error) {
	switch kind {
	case "RSA1024":
		k, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // a weak key is the point of the refusal tests
		return k, "", err
	case "RSA2048", "RSA3072", "RSA4096":
		var bits int
		_, _ = fmt.Sscanf(kind, "RSA%d", &bits)
		k, err := rsa.GenerateKey(rand.Reader, bits)
		return k, "", err
	case "P224":
		k, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		return k, "", err
	case "P256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return k, "", err
	case "P256K":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return k, "P-256K", err
	case "P384":
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return k, "", err
	case "P521":
		k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		return k, "", err
	}
	return nil, "", fmt.Errorf("unknown key kind %q", kind)
}

// AddKey creates a key of kind RSA1024, RSA2048, RSA3072, RSA4096, P224, P256, P256K,
// P384 or P521 and returns its versioned ID. signOp says whether the key permits the
// sign operation.
func (s *Server) AddKey(name, kind string, signOp bool) string {
	signer, fakeCurve, err := generate(kind)
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := &keyEntry{name: name, version: randomHex(), signer: signer, fakeCurve: fakeCurve, signOp: signOp, enabled: true}
	s.keys[name+"/"+k.version] = k
	s.keyList = append(s.keyList, k)
	s.allKeys = append(s.allKeys, signer)
	return s.URL + "/keys/" + name + "/" + k.version
}

// SetKeyEnabled enables or disables a key by name (its latest version).
func (s *Server) SetKeyEnabled(name string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keyList {
		if k.name == name {
			k.enabled = enabled
		}
	}
}

// DeleteKey removes every version of a key from outside the provider, so that reading
// or using it answers 404.
func (s *Server) DeleteKey(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.keys {
		if e.name == name {
			delete(s.keys, k)
		}
	}
	s.keyList = slices.DeleteFunc(s.keyList, func(e *keyEntry) bool { return e.name == name })
}

// ForbidKeyReads makes reading a key answer 403, as a caller without the right to read
// keys gets. Everything else keeps working.
func (s *Server) ForbidKeyReads(b bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forbidKeyReads = b
}

// SetFailure makes every request answer with the given status (0 turns it off).
func (s *Server) SetFailure(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failStatus = status
}

// The Key Vault data actions (Azure RBAC) the fake authorises requests with.
const (
	ActionCertificatesRead   = "Microsoft.KeyVault/vaults/certificates/read"
	ActionCertificatesCreate = "Microsoft.KeyVault/vaults/certificates/create/action"
	ActionCertificatesUpdate = "Microsoft.KeyVault/vaults/certificates/update/action"
	ActionCertificatesDelete = "Microsoft.KeyVault/vaults/certificates/delete"
	ActionKeysRead           = "Microsoft.KeyVault/vaults/keys/read"
	ActionKeysSign           = "Microsoft.KeyVault/vaults/keys/sign/action"
	ActionSecretsGet         = "Microsoft.KeyVault/vaults/secrets/getSecret/action"
)

// dataActions maps a request to the data actions it needs; the caller must hold all of
// them. The list is empty for a request the fake does not know (for example listing keys
// or certificates, which the provider never does), which restricted rights refuse.
//
// For the pending operation of a certificate (/certificates/{name}/pending), Key Vault
// authorises reading it as certificates/create/action, although Microsoft's REST
// reference names the get permission for that request. For deleting (and updating) a
// pending operation the REST reference names the update permission; which data action
// Key Vault really checks is not documented, and the observed read shows that the REST
// reference is not a reliable guide for this endpoint. The documented permissions
// therefore list every candidate (create/action, update/action and delete), and the fake
// requires all of them, so that dropping any one from the documentation fails a test.
// Merging is authorised as certificates/create/action.
func dataActions(method, path string) []string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return nil
	}
	switch parts[0] {
	case "secrets":
		return []string{ActionSecretsGet}
	case "keys":
		switch {
		case len(parts) == 3 && method == http.MethodGet:
			return []string{ActionKeysRead}
		case len(parts) == 4 && parts[3] == "sign" && method == http.MethodPost:
			return []string{ActionKeysSign}
		}
	case "certificates":
		switch {
		case len(parts) >= 3 && parts[2] == "pending" && (method == http.MethodDelete || method == http.MethodPatch):
			return []string{ActionCertificatesCreate, ActionCertificatesUpdate, ActionCertificatesDelete}
		case len(parts) >= 3 && parts[2] == "pending":
			return []string{ActionCertificatesCreate} // read, merge
		case len(parts) == 3 && parts[2] == "create" && method == http.MethodPost:
			return []string{ActionCertificatesCreate}
		case method == http.MethodGet && (len(parts) == 2 || len(parts) == 3):
			return []string{ActionCertificatesRead} // the certificate, a version, the list of versions
		case method == http.MethodDelete && len(parts) == 2:
			return []string{ActionCertificatesDelete} // destroy; an order never deletes the certificate
		}
	}
	return nil
}

// missingAction returns the first data action the request needs that is not granted
// ("" when the request is allowed or every action is granted).
func (s *Server) missingAction(method, path string) string {
	if s.granted == nil {
		return ""
	}
	need := dataActions(method, path)
	if len(need) == 0 {
		return "unknown data action"
	}
	for _, a := range need {
		if !s.granted[a] {
			return a
		}
	}
	return ""
}

// SetReader switches the vault to the rights of a read-only caller: only
// certificates/read and keys/read are granted (as the Key Vault Reader role does), so
// the sign operation, every secrets request, every pending operation (even reading
// one), create, merge and delete answer 403. Requests are journaled as usual, so a test
// can prove the provider did not even try. SetReader(false) grants every action again.
func (s *Server) SetReader(on bool) {
	if on {
		s.SetDataActions(ActionCertificatesRead, ActionKeysRead)
		return
	}
	s.GrantAll()
}

// SetDataActions grants exactly the given data actions.
func (s *Server) SetDataActions(actions ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.granted = map[string]bool{}
	for _, a := range actions {
		s.granted[a] = true
	}
}

// GrantAll grants every data action (the default).
func (s *Server) GrantAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.granted = nil
}

// ForbiddenMark returns the position to pass to ForbiddenSince.
func (s *Server) ForbiddenMark() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.forbidden)
}

// ForbiddenSince lists the requests answered 403 for a missing data action since the
// mark, as "METHOD /path (data action)".
func (s *Server) ForbiddenSince(mark int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mark > len(s.forbidden) {
		mark = len(s.forbidden)
	}
	return slices.Clone(s.forbidden[mark:])
}

// Forbidden lists every request answered 403 for a missing data action.
func (s *Server) Forbidden() []string { return s.ForbiddenSince(0) }

// denyAction answers like Key Vault does when the caller lacks a data action, and
// records the request.
func (s *Server) denyAction(w http.ResponseWriter, r *http.Request, action string) {
	s.forbidden = append(s.forbidden, r.Method+" "+r.URL.Path+" ("+action+")")
	apiError(w, http.StatusForbidden, "Forbidden", "Caller is not authorized to perform action on resource.\r\n"+
		"If role assignments, deny assignments or role definitions were changed recently, please observe propagation time.\r\n"+
		"Caller: appid=00000000-0000-0000-0000-000000000000;oid=00000000-0000-0000-0000-000000000000\r\n"+
		"Action: '"+action+"'\r\n"+
		"Resource: '/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/example/providers/microsoft.keyvault/vaults/fake'\r\n"+
		"Assignment: (not found)\r\n"+
		"DecisionReason: 'DeniedWithNoValidRBAC'\r\n"+
		"Vault: fake;location=example")
}

// PrivateKeysDER returns every private key the fake generated or holds, as PKCS #8 DER.
func (s *Server) PrivateKeysDER() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][]byte
	for _, k := range s.allKeys {
		if der, err := x509.MarshalPKCS8PrivateKey(k); err == nil {
			out = append(out, der)
		}
	}
	return out
}

// PendingOperations returns the names of certificates with a pending operation in
// progress. A finished record is not listed; see PendingRecords.
func (s *Server) PendingOperations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for n, c := range s.certs {
		if c.pending.inProgress() && !c.deleted {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// PendingRecord returns the issuer and status of the pending-operation record of a
// certificate, finished or not; ok is false when there is none.
func (s *Server) PendingRecord(name string) (issuer, status string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.certs[name]
	if c == nil || c.deleted || c.pending == nil {
		return "", "", false
	}
	return c.pending.issuer, c.pending.status, true
}

// Violations lists requests the provider must never make: any secrets request, key
// export or certificate policy request.
func (s *Server) Violations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.violations)
}

// Policy returns the policy of a certificate.
func (s *Server) Policy(name string) PolicyInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.certs[name]; c != nil {
		return c.policy
	}
	return PolicyInfo{}
}

// Versions lists the versions of a certificate, oldest first.
func (s *Server) Versions(name string) []VersionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.certs[name]
	if c == nil {
		return nil
	}
	var out []VersionInfo
	for _, v := range c.versions {
		out = append(out, VersionInfo{Version: v.id, Issued: v.issued, Created: v.created})
	}
	return out
}

// Deleted reports whether the certificate is soft-deleted.
func (s *Server) Deleted(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.certs[name]
	return c != nil && c.deleted
}

// Exists reports whether the certificate exists and is not deleted.
func (s *Server) Exists(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.certs[name]
	return c != nil && !c.deleted
}

// SoftDelete deletes a certificate from outside the provider, as another client would.
func (s *Server) SoftDelete(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.certs[name]; c != nil {
		c.deleted = true
	}
}

// Purge forgets a certificate completely, deleted or not.
func (s *Server) Purge(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.certs, name)
}

// LeafDER returns the certificate of a version, or the latest issued one when version
// is empty.
func (s *Server) LeafDER(name, ver string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.certs[name]
	if c == nil {
		return nil
	}
	if ver == "" {
		if v := latestIssued(c); v != nil {
			return v.cer
		}
		return nil
	}
	for _, v := range c.versions {
		if v.id == ver {
			return v.cer
		}
	}
	return nil
}

// ImportOptions describe a certificate put in from outside the provider, as Key Vault's
// PFX import or an integrated CA would.
type ImportOptions struct {
	// Issuer is the issuer name of the policy, for example "Self" or "OtherCA".
	Issuer     string
	Exportable bool
	// Key is RSA1024, RSA2048, RSA3072, RSA4096, P224, P256, P384 or P521.
	Key string
	// CommonName is the subject common name; empty means the subject has none.
	CommonName      string
	DNSNames        []string
	IPAddresses     []net.IP
	Validity        time.Duration
	LifetimeActions []string
}

// ImportCertificate adds a certificate version from outside the provider. The leaf is
// signed by a separate authority, the key is held by the fake and the new version
// becomes the latest. It records nothing in the journal.
func (s *Server) ImportCertificate(name string, o ImportOptions) (string, error) {
	signer, _, err := generate(o.Key)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allKeys = append(s.allKeys, signer)
	der, err := s.issueOther(signer.Public(), o.CommonName, o.DNSNames, o.IPAddresses, o.Validity)
	if err != nil {
		return "", err
	}
	c := s.certs[name]
	if c == nil || c.deleted {
		c = &certificate{name: name}
		s.certs[name] = c
	}
	v := &version{id: randomHex(), cer: der, created: time.Now().UTC(), issued: true, key: signer}
	c.versions = append(c.versions, v)
	if o.Issuer == "Self" {
		// A certificate created with the Self issuer leaves a completed operation record.
		c.pending = &pendingOp{version: v, issuer: "Self", status: statusCompleted}
	}
	c.policy = PolicyInfo{
		Issuer: o.Issuer, Exportable: o.Exportable, Subject: subject(o.CommonName), DNSNames: slices.Clone(o.DNSNames),
		LifetimeActions: slices.Clone(o.LifetimeActions), ContentType: "application/x-pkcs12",
	}
	switch k := signer.Public().(type) {
	case *rsa.PublicKey:
		c.policy.KTY, c.policy.KeySize = "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		c.policy.KTY, c.policy.Curve = "EC", k.Curve.Params().Name
	}
	return v.id, nil
}

// AddExternalVersion adds a version outside the provider, with the names of the latest
// one, as an automatic renewal under another issuer would.
func (s *Server) AddExternalVersion(name string) (string, error) {
	s.mu.Lock()
	c := s.certs[name]
	if c == nil {
		s.mu.Unlock()
		return "", fmt.Errorf("no certificate %q", name)
	}
	cn := strings.TrimPrefix(c.policy.Subject, "CN=")
	dns := slices.Clone(c.policy.DNSNames)
	exportable, issuer := c.policy.Exportable, c.policy.Issuer
	policy := c.policy
	s.mu.Unlock()
	kind := "RSA2048"
	if policy.KTY == "EC" {
		kind = "P256"
	}
	id, err := s.ImportCertificate(name, ImportOptions{Issuer: issuer, Exportable: exportable, Key: kind, CommonName: cn, DNSNames: dns})
	if err != nil {
		return "", err
	}
	// Keep the policy as it was: an external version does not change it.
	s.mu.Lock()
	s.certs[name].policy = policy
	s.mu.Unlock()
	return id, nil
}

// AddSelfIssuedVersion adds a version outside the provider as `az keyvault certificate
// create` with the Self issuer would: the key and the self-signed certificate are
// generated by the vault, the policy becomes issuer Self, and Key Vault keeps a
// completed operation record behind. The names are those of the latest version.
func (s *Server) AddSelfIssuedVersion(name string) (string, error) {
	s.mu.Lock()
	c := s.certs[name]
	if c == nil {
		s.mu.Unlock()
		return "", fmt.Errorf("no certificate %q", name)
	}
	cn := strings.TrimPrefix(c.policy.Subject, "CN=")
	dns := slices.Clone(c.policy.DNSNames)
	exportable := c.policy.Exportable
	kind := "RSA2048"
	if c.policy.KTY == "EC" {
		kind = "P256"
	}
	s.mu.Unlock()
	return s.ImportCertificate(name, ImportOptions{Issuer: "Self", Exportable: exportable, Key: kind, CommonName: cn, DNSNames: dns})
}

// AddPendingOperation seeds a pending operation of any issuer on a certificate name,
// creating the certificate object when it does not exist.
func (s *Server) AddPendingOperation(name, issuer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.certs[name]
	if c == nil || c.deleted {
		c = &certificate{name: name}
		s.certs[name] = c
	}
	v := &version{id: randomHex(), created: time.Now().UTC()}
	c.versions = append(c.versions, v)
	c.pending = &pendingOp{version: v, issuer: issuer, status: statusInProgress}
}

// AddFinishedOperation seeds a finished pending-operation record (status "completed",
// "failed" or "cancelled") of any issuer on an existing certificate, as Key Vault keeps
// it after an operation ends. It adds no version.
func (s *Server) AddFinishedOperation(name, issuer, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.certs[name]
	if c == nil || c.deleted || len(c.versions) == 0 {
		return fmt.Errorf("no certificate %q", name)
	}
	c.pending = &pendingOp{version: c.versions[len(c.versions)-1], issuer: issuer, status: status}
	return nil
}

func subject(cn string) string {
	if cn == "" {
		return ""
	}
	return "CN=" + cn
}

func (s *Server) issueOther(pub crypto.PublicKey, cn string, dns []string, ips []net.IP, validity time.Duration) ([]byte, error) {
	if validity <= 0 {
		validity = 90 * 24 * time.Hour
	}
	s.serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1000 + s.serial), Subject: pkix.Name{CommonName: cn},
		DNSNames: dns, IPAddresses: ips,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(validity),
	}
	if !tmpl.NotAfter.After(tmpl.NotBefore) {
		tmpl.NotBefore = tmpl.NotAfter.Add(-time.Hour)
	}
	return x509.CreateCertificate(rand.Reader, tmpl, s.otherCA, pub, s.otherKey)
}

func latestIssued(c *certificate) *version {
	for i := len(c.versions) - 1; i >= 0; i-- {
		if c.versions[i].issued {
			return c.versions[i]
		}
	}
	return nil
}

func (s *Server) base() string { return s.URL }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	write := r.Method != http.MethodGet && !strings.HasSuffix(path, "/sign")
	s.Journal.Record(r.Method, path, write)

	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.Contains(path, "/secrets") || strings.Contains(path, "/export") || strings.Contains(path, "/policy") {
		s.violations = append(s.violations, r.Method+" "+path)
	}
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		apiError(w, http.StatusUnauthorized, "Unauthorized", "the access token is not accepted by this vault")
		return
	}
	if s.failStatus != 0 {
		apiError(w, s.failStatus, "ServiceUnavailable", "the vault is failing (test control)")
		return
	}
	// With restricted rights the fake fails closed: a request it cannot map to a data
	// action is refused, so a new kind of request cannot slip through a read-only test.
	if action := s.missingAction(r.Method, path); action != "" {
		s.denyAction(w, r, action)
		return
	}
	if r.URL.Query().Get("api-version") != "7.5" {
		apiError(w, http.StatusBadRequest, "BadParameter", "unexpected api-version")
		return
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case len(parts) == 3 && parts[0] == "keys" && r.Method == http.MethodGet:
		if s.forbidKeyReads {
			s.denyAction(w, r, ActionKeysRead)
			return
		}
		s.getKey(w, parts[1], parts[2])
	case len(parts) == 4 && parts[0] == "keys" && parts[3] == "sign" && r.Method == http.MethodPost:
		s.sign(w, r, parts[1], parts[2])
	case len(parts) >= 2 && parts[0] == "certificates":
		s.certificate(w, r, parts[1:])
	default:
		apiError(w, http.StatusNotFound, "NotFound", "unknown path "+path)
	}
}

func (s *Server) getKey(w http.ResponseWriter, name, ver string) {
	k := s.keys[name+"/"+ver]
	if k == nil {
		apiError(w, http.StatusNotFound, "KeyNotFound", "the key was not found")
		return
	}
	jwk := map[string]any{"kid": s.base() + "/keys/" + name + "/" + ver}
	if k.signOp {
		jwk["key_ops"] = []string{"sign", "verify"}
	} else {
		jwk["key_ops"] = []string{"verify"}
	}
	switch pub := k.signer.Public().(type) {
	case *rsa.PublicKey:
		jwk["kty"], jwk["n"], jwk["e"] = "RSA", b64u(pub.N.Bytes()), b64u(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		size := (pub.Curve.Params().BitSize + 7) / 8
		jwk["kty"] = "EC"
		jwk["crv"] = pub.Curve.Params().Name
		if k.fakeCurve != "" {
			jwk["crv"] = k.fakeCurve
		}
		point, _ := pub.Bytes() // 0x04 || X || Y
		jwk["x"], jwk["y"] = b64u(point[1:1+size]), b64u(point[1+size:])
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": jwk, "attributes": map[string]any{"enabled": k.enabled}})
}

func pad(b []byte, size int) []byte {
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func (s *Server) sign(w http.ResponseWriter, r *http.Request, name, ver string) {
	k := s.keys[name+"/"+ver]
	if k == nil {
		apiError(w, http.StatusNotFound, "KeyNotFound", "the key was not found")
		return
	}
	if !k.signOp || !k.enabled {
		apiError(w, http.StatusForbidden, "Forbidden", "the key does not permit the sign operation")
		return
	}
	var body struct{ Alg, Value string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, "BadParameter", "invalid body")
		return
	}
	digest, err := base64.RawURLEncoding.DecodeString(body.Value)
	if err != nil {
		apiError(w, http.StatusBadRequest, "BadParameter", "the value is not base64url")
		return
	}
	var sig []byte
	switch pub := k.signer.Public().(type) {
	case *rsa.PublicKey:
		if body.Alg != "RS256" || len(digest) != sha256.Size {
			apiError(w, http.StatusBadRequest, "BadParameter", "the algorithm or digest does not fit the key")
			return
		}
		sig, err = rsa.SignPKCS1v15(rand.Reader, k.signer.(*rsa.PrivateKey), crypto.SHA256, digest)
	case *ecdsa.PublicKey:
		want := map[string]struct {
			curve string
			size  int
		}{"ES256": {"P-256", sha256.Size}, "ES384": {"P-384", sha512.Size384}, "ES512": {"P-521", sha512.Size}}[body.Alg]
		if want.curve != pub.Curve.Params().Name || len(digest) != want.size {
			apiError(w, http.StatusBadRequest, "BadParameter", "the algorithm or digest does not fit the key")
			return
		}
		var rr, ss *big.Int
		rr, ss, err = ecdsa.Sign(rand.Reader, k.signer.(*ecdsa.PrivateKey), digest)
		if err == nil {
			size := (pub.Curve.Params().BitSize + 7) / 8
			sig = append(pad(rr.Bytes(), size), pad(ss.Bytes(), size)...)
		}
	}
	if err != nil {
		apiError(w, http.StatusInternalServerError, "InternalError", "cannot sign")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"kid": s.base() + "/keys/" + name + "/" + ver, "value": b64u(sig)})
}

func (s *Server) bundle(c *certificate, v *version) map[string]any {
	b := map[string]any{
		"id":         s.base() + "/certificates/" + c.name + "/" + v.id,
		"kid":        s.base() + "/keys/" + c.name + "/" + v.id,
		"sid":        s.base() + "/secrets/" + c.name + "/" + v.id,
		"attributes": map[string]any{"enabled": !v.disabled, "created": v.created.Unix()},
	}
	if v.issued {
		leaf, _ := x509.ParseCertificate(v.cer)
		sum := sha1Sum(v.cer)
		b["x5t"] = b64u(sum)
		b["cer"] = base64.StdEncoding.EncodeToString(v.cer)
		b["attributes"] = map[string]any{"enabled": true, "created": v.created.Unix(), "exp": leaf.NotAfter.Unix()}
	}
	return b
}

func (s *Server) pendingJSON(c *certificate) map[string]any {
	return map[string]any{
		"id": s.base() + "/certificates/" + c.name + "/pending", "issuer": map[string]string{"name": c.pending.issuer},
		"csr": base64.StdEncoding.EncodeToString(c.pending.csr), "status": c.pending.status, "request_id": randomHex(),
	}
}

func (s *Server) certificate(w http.ResponseWriter, r *http.Request, parts []string) {
	name := parts[0]
	c := s.certs[name]
	notFound := func() { apiError(w, http.StatusNotFound, "CertificateNotFound", "the certificate was not found") }
	switch {
	case len(parts) == 2 && parts[1] == "create" && r.Method == http.MethodPost:
		s.create(w, r, name)
	case len(parts) == 2 && parts[1] == "pending" && r.Method == http.MethodGet:
		if c == nil || c.deleted || c.pending == nil {
			apiError(w, http.StatusNotFound, "PendingCertificateNotFound", "there is no pending operation")
			return
		}
		writeJSON(w, http.StatusOK, s.pendingJSON(c))
	case len(parts) == 2 && parts[1] == "pending" && r.Method == http.MethodDelete:
		if c == nil || c.deleted || c.pending == nil {
			apiError(w, http.StatusNotFound, "PendingCertificateNotFound", "there is no pending operation")
			return
		}
		body := s.pendingJSON(c)
		if c.pending.inProgress() {
			// Cancelling drops the version that was waiting. A certificate that never had
			// an issued version keeps it, disabled and without a certificate, as Key Vault
			// does; deleting a finished record changes no version.
			if latestIssued(c) != nil {
				c.versions = slices.DeleteFunc(c.versions, func(v *version) bool { return v == c.pending.version })
			} else {
				c.pending.version.disabled = true
			}
		}
		c.pending = nil
		writeJSON(w, http.StatusOK, body)
	case len(parts) == 3 && parts[1] == "pending" && parts[2] == "merge" && r.Method == http.MethodPost:
		s.merge(w, r, c)
	case len(parts) == 2 && parts[1] == "versions" && r.Method == http.MethodGet:
		if c == nil || c.deleted {
			notFound()
			return
		}
		var list []map[string]any
		for _, v := range c.versions {
			item := s.bundle(c, v)
			delete(item, "cer")
			delete(item, "kid")
			delete(item, "sid")
			list = append(list, item)
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": list, "nextLink": nil})
	case len(parts) == 1 && r.Method == http.MethodGet:
		if c == nil || c.deleted || len(c.versions) == 0 {
			notFound()
			return
		}
		// Like Key Vault, answer with the latest version, even when it is still pending (it
		// then has no certificate).
		writeJSON(w, http.StatusOK, s.bundle(c, c.versions[len(c.versions)-1]))
	case len(parts) == 2 && r.Method == http.MethodGet:
		if c == nil || c.deleted {
			notFound()
			return
		}
		for _, v := range c.versions {
			if v.id == parts[1] {
				writeJSON(w, http.StatusOK, s.bundle(c, v))
				return
			}
		}
		notFound()
	case len(parts) == 1 && r.Method == http.MethodDelete:
		if c == nil || c.deleted {
			notFound()
			return
		}
		c.deleted = true
		var body map[string]any
		if v := latestIssued(c); v != nil {
			body = s.bundle(c, v)
		} else {
			body = map[string]any{"id": s.base() + "/certificates/" + name}
		}
		writeJSON(w, http.StatusOK, body)
	default:
		apiError(w, http.StatusNotFound, "NotFound", "unknown path "+r.URL.Path)
	}
}

type createBody struct {
	Policy struct {
		KeyProps struct {
			Exportable bool   `json:"exportable"`
			KTY        string `json:"kty"`
			KeySize    int    `json:"key_size"`
			Crv        string `json:"crv"`
			ReuseKey   bool   `json:"reuse_key"`
		} `json:"key_props"`
		SecretProps struct {
			ContentType string `json:"contentType"`
		} `json:"secret_props"`
		X509Props struct {
			Subject string `json:"subject"`
			SANs    struct {
				DNSNames []string `json:"dns_names"`
			} `json:"sans"`
		} `json:"x509_props"`
		Issuer          struct{ Name string } `json:"issuer"`
		LifetimeActions []json.RawMessage     `json:"lifetime_actions"`
	} `json:"policy"`
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, name string) {
	var b createBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		apiError(w, http.StatusBadRequest, "BadParameter", "invalid body")
		return
	}
	p := b.Policy
	if p.Issuer.Name != "Unknown" {
		apiError(w, http.StatusBadRequest, "BadParameter", "this vault supports only issuer Unknown")
		return
	}
	c := s.certs[name]
	if c != nil && c.deleted {
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{
			"code": "Conflict", "message": "the certificate is currently in a deleted but recoverable state, and its name cannot be reused; in this state, the certificate can only be recovered or purged",
			"innererror": map[string]string{"code": "ObjectIsDeletedButRecoverable"},
		}})
		return
	}
	if c != nil && c.pending.inProgress() {
		apiError(w, http.StatusConflict, "Conflict", "a certificate operation is already pending for this name")
		return
	}
	kind := ""
	switch p.KeyProps.KTY {
	case "RSA":
		kind = fmt.Sprintf("RSA%d", p.KeyProps.KeySize)
	case "EC":
		kind = map[string]string{"P-256": "P256", "P-384": "P384", "P-521": "P521"}[p.KeyProps.Crv]
	}
	if kind == "" || kind == "RSA1024" || kind == "RSA0" {
		apiError(w, http.StatusBadRequest, "BadParameter", "unsupported key properties")
		return
	}
	signer, _, err := generate(kind)
	if err != nil {
		apiError(w, http.StatusBadRequest, "BadParameter", err.Error())
		return
	}
	cn := strings.TrimPrefix(p.X509Props.Subject, "CN=")
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: p.X509Props.SANs.DNSNames,
	}, signer)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "InternalError", "cannot create the signing request")
		return
	}
	if c == nil {
		c = &certificate{name: name}
		s.certs[name] = c
	}
	s.allKeys = append(s.allKeys, signer)
	v := &version{id: randomHex(), created: time.Now().UTC(), key: signer}
	c.versions = append(c.versions, v)
	c.pending = &pendingOp{version: v, issuer: "Unknown", csr: csr, status: statusInProgress}
	c.policy = PolicyInfo{
		Issuer: "Unknown", Exportable: p.KeyProps.Exportable, KTY: p.KeyProps.KTY, KeySize: p.KeyProps.KeySize, Curve: p.KeyProps.Crv,
		ReuseKey: p.KeyProps.ReuseKey, Subject: p.X509Props.Subject, DNSNames: slices.Clone(p.X509Props.SANs.DNSNames),
		ContentType: p.SecretProps.ContentType,
	}
	for range p.LifetimeActions {
		c.policy.LifetimeActions = append(c.policy.LifetimeActions, "action")
	}
	writeJSON(w, http.StatusAccepted, s.pendingJSON(c))
}

func (s *Server) merge(w http.ResponseWriter, r *http.Request, c *certificate) {
	if c == nil || c.deleted || !c.pending.inProgress() {
		apiError(w, http.StatusNotFound, "PendingCertificateNotFound", "there is no pending operation in progress")
		return
	}
	var b struct {
		X5C []string `json:"x5c"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || len(b.X5C) == 0 {
		apiError(w, http.StatusBadRequest, "BadParameter", "x5c is required")
		return
	}
	var chain []*x509.Certificate
	for _, e := range b.X5C {
		der, err := base64.StdEncoding.DecodeString(e)
		if err != nil {
			apiError(w, http.StatusBadRequest, "BadParameter", "x5c holds a value that is not base64")
			return
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			apiError(w, http.StatusBadRequest, "BadParameter", "x5c holds a value that is not a certificate")
			return
		}
		chain = append(chain, cert)
	}
	pub, err := x509.MarshalPKIXPublicKey(c.pending.version.key.Public())
	if err != nil || !equal(pub, chain[0].RawSubjectPublicKeyInfo) {
		apiError(w, http.StatusBadRequest, "KeyMismatch", "the public key of the certificate does not match the key of the pending operation")
		return
	}
	v := c.pending.version
	v.cer = chain[0].Raw
	v.issued = true
	v.created = time.Now().UTC()
	c.pending.status = statusCompleted
	writeJSON(w, http.StatusCreated, s.bundle(c, v))
}

func equal(a, b []byte) bool { return slices.Equal(a, b) }
