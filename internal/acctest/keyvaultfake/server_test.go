package keyvaultfake_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/keyvaultfake"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/keyvault"
)

const token = "fake-test-token"

func start(t *testing.T) (*keyvaultfake.Server, *keyvault.Client) {
	t.Helper()
	certs, err := acctest.NewCerts(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := keyvaultfake.Start(certs.Server, token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	c, err := keyvault.New(srv.URL, token, certs.HTTPClientWithVault())
	if err != nil {
		t.Fatal(err)
	}
	return srv, c
}

func policy(t *testing.T, cn string, names []string, kt string) acme.Policy {
	t.Helper()
	p, err := acme.CreatePolicy(cn, names, kt)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func csrKeyMismatchChain(t *testing.T) [][]byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: bigOne(), Subject: pkix.Name{CommonName: "ca"}, IsCA: true, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &ca.PublicKey, ca)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leaf := &x509.Certificate{SerialNumber: bigOne(), Subject: pkix.Name{CommonName: "x.example.com"}, DNSNames: []string{"x.example.com"}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, ca)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{der}
}

func TestCreateMergeAndVersions(t *testing.T) {
	srv, c := start(t)
	ctx := context.Background()
	pending, err := c.CreateCertificate(ctx, "c1", policy(t, "x.example.com", []string{"x.example.com"}, "P256"))
	if err != nil || pending.Issuer != "Unknown" || len(pending.CSR) == 0 {
		t.Fatalf("create: %+v %v", pending, err)
	}
	if _, err := c.CreateCertificate(ctx, "c1", policy(t, "x.example.com", []string{"x.example.com"}, "P256")); err == nil {
		t.Error("a second create with a pending operation succeeded")
	}
	if got := srv.PendingOperations(); !slices.Equal(got, []string{"c1"}) {
		t.Errorf("pending: %v", got)
	}
	// A leaf for another key is refused.
	if _, err := c.Merge(ctx, "c1", csrKeyMismatchChain(t)); err == nil {
		t.Error("a leaf with another key was merged")
	}
	if err := c.DeletePending(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPending(ctx, "c1"); !errors.Is(err, keyvault.ErrNotFound) {
		t.Errorf("after deleting the pending operation: %v", err)
	}
	if len(srv.PrivateKeysDER()) == 0 {
		t.Error("the fake does not report its private keys")
	}
}

func TestImportedCertificatesAreNotInTheJournal(t *testing.T) {
	srv, c := start(t)
	ctx := context.Background()
	mark := srv.Journal.Mark()
	version, err := srv.ImportCertificate("imported", keyvaultfake.ImportOptions{
		Issuer: "Self", Key: "RSA2048", CommonName: "example.com", DNSNames: []string{"example.com"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.1")},
		LifetimeActions: []string{"AutoRenew"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(srv.Journal.Since(mark)); n != 0 {
		t.Errorf("an import is not a request, but %d were journaled", n)
	}
	b, err := c.GetCertificate(ctx, "imported")
	if err != nil || b.Version != version || len(b.Cer) == 0 {
		t.Fatalf("get: %+v %v", b, err)
	}
	if p := srv.Policy("imported"); p.Issuer != "Self" || p.Exportable || len(p.LifetimeActions) != 1 || p.KTY != "RSA" {
		t.Errorf("policy: %+v", p)
	}
	// An order on the name keeps the imported version and replaces the policy.
	if _, err := c.CreateCertificate(ctx, "imported", policy(t, "example.com", []string{"example.com"}, "P384")); err != nil {
		t.Fatal(err)
	}
	if p := srv.Policy("imported"); p.Issuer != "Unknown" || !p.Exportable || p.Curve != "P-384" || len(p.LifetimeActions) != 0 {
		t.Errorf("the policy was not replaced: %+v", p)
	}
	// Until the merge the versionless get returns the latest version, which is the pending
	// one and has no certificate; the imported version is still listed as issued.
	latest, _ := c.GetCertificate(ctx, "imported")
	if latest.Version == version || len(latest.Cer) != 0 || latest.Issued {
		t.Errorf("until the merge the versionless get returns the pending version, got %+v", latest)
	}
	if got := srv.LeafDER("imported", ""); len(got) == 0 {
		t.Error("the imported version is no longer the latest issued one")
	}
	if v := srv.Violations(); len(v) != 0 {
		t.Errorf("violations: %v", v)
	}
}

func TestSoftDeleteAndConflict(t *testing.T) {
	srv, c := start(t)
	ctx := context.Background()
	if _, err := srv.ImportCertificate("gone", keyvaultfake.ImportOptions{Issuer: "Self", Key: "P256", CommonName: "example.com", DNSNames: []string{"example.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteCertificate(ctx, "gone"); err != nil {
		t.Fatal(err)
	}
	if !srv.Deleted("gone") || srv.Exists("gone") {
		t.Error("the certificate is not soft-deleted")
	}
	if _, err := c.GetCertificate(ctx, "gone"); !errors.Is(err, keyvault.ErrNotFound) {
		t.Errorf("a deleted certificate must read as not found: %v", err)
	}
	if _, err := c.CreateCertificate(ctx, "gone", policy(t, "example.com", []string{"example.com"}, "P256")); err == nil {
		t.Error("creating over a soft-deleted name succeeded")
	}
	if err := c.DeleteCertificate(ctx, "never-existed"); err != nil {
		t.Errorf("deleting what is gone: %v", err)
	}
}

func TestViolationsAreRecorded(t *testing.T) {
	certs, err := acctest.NewCerts(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := keyvaultfake.Start(certs.Server, token)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if len(srv.Violations()) != 0 {
		t.Fatal("violations without requests")
	}
	for _, path := range []string{"/secrets/x", "/keys/x/export", "/certificates/x/policy"} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path+"?api-version=7.5", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := certs.HTTPClientWithVault().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if got := srv.Violations(); len(got) != 3 {
		t.Errorf("violations: %v", got)
	}
}

func TestReaderModeAuthorisesPerDataAction(t *testing.T) {
	srv, c := start(t)
	ctx := context.Background()
	keyID := srv.AddKey("k", "P256", true)
	key, err := acme.ParseKeyID(keyID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.ImportCertificate("c", keyvaultfake.ImportOptions{Issuer: "Self", Key: "P256", CommonName: "example.com", DNSNames: []string{"example.com"}}); err != nil {
		t.Fatal(err)
	}
	srv.AddPendingOperation("p", "Unknown")
	mark := srv.ForbiddenMark()
	srv.SetReader(true)

	// Reading certificates, versions and keys is allowed.
	if _, err := c.GetKey(ctx, key.Name, key.Version); err != nil {
		t.Errorf("reading a key: %v", err)
	}
	if _, err := c.GetCertificate(ctx, "c"); err != nil {
		t.Errorf("reading a certificate: %v", err)
	}
	if _, err := c.ListVersions(ctx, "c"); err != nil {
		t.Errorf("listing versions: %v", err)
	}
	if got := srv.ForbiddenSince(mark); len(got) != 0 {
		t.Errorf("reads were refused: %v", got)
	}

	// Reading a pending operation needs certificates/create/action, as in Key Vault.
	var api *keyvault.APIError
	_, err = c.GetPending(ctx, "c")
	if !errors.As(err, &api) || api.Status != http.StatusForbidden || api.Code != "Forbidden" ||
		!strings.Contains(api.Message, "Action: 'Microsoft.KeyVault/vaults/certificates/create/action'") {
		t.Errorf("get pending: %v", err)
	}
	refused := func(what string, err error, action string) {
		t.Helper()
		if !errors.As(err, &api) || api.Status != http.StatusForbidden || !strings.Contains(api.Message, "Action: '"+action+"'") {
			t.Errorf("%s: %v", what, err)
		}
	}
	refused("delete pending", c.DeletePending(ctx, "p"), keyvaultfake.ActionCertificatesCreate)
	_, err = c.Merge(ctx, "p", [][]byte{{1}})
	refused("merge", err, keyvaultfake.ActionCertificatesCreate)
	_, err = c.CreateCertificate(ctx, "n", policy(t, "example.com", []string{"example.com"}, "P256"))
	refused("create", err, keyvaultfake.ActionCertificatesCreate)
	refused("delete", c.DeleteCertificate(ctx, "c"), keyvaultfake.ActionCertificatesDelete)
	_, err = c.Sign(ctx, key.Name, key.Version, "ES256", make([]byte, 32))
	refused("sign", err, keyvaultfake.ActionKeysSign)
	if got := srv.ForbiddenSince(mark); len(got) != 6 {
		t.Errorf("recorded refusals: %v", got)
	}

	// Every right is back.
	srv.SetReader(false)
	if _, err := c.GetPending(ctx, "p"); err != nil {
		t.Errorf("get pending with every right: %v", err)
	}
	if _, err := c.Sign(ctx, key.Name, key.Version, "ES256", make([]byte, 32)); err != nil {
		t.Errorf("sign with every right: %v", err)
	}
	if err := c.DeletePending(ctx, "p"); err != nil {
		t.Errorf("delete pending with every right: %v", err)
	}
	if _, err := c.CreateCertificate(ctx, "n", policy(t, "example.com", []string{"example.com"}, "P256")); err != nil {
		t.Errorf("create with every right: %v", err)
	}
	if err := c.DeleteCertificate(ctx, "c"); err != nil {
		t.Errorf("delete with every right: %v", err)
	}
}

func TestSetDataActionsGrantsExactlyThose(t *testing.T) {
	srv, c := start(t)
	ctx := context.Background()
	srv.AddPendingOperation("p", "Unknown")
	srv.SetDataActions(keyvaultfake.ActionCertificatesRead, keyvaultfake.ActionCertificatesCreate)
	if _, err := c.GetPending(ctx, "p"); err != nil {
		t.Errorf("get pending: %v", err)
	}
	var api *keyvault.APIError
	// Every request to a pending operation, deleting it included, needs
	// certificates/create/action and nothing else, as in Key Vault: update/action and
	// delete neither replace nor add to it.
	srv.SetDataActions(keyvaultfake.ActionCertificatesRead, keyvaultfake.ActionCertificatesUpdate, keyvaultfake.ActionCertificatesDelete)
	if err := c.DeletePending(ctx, "p"); !errors.As(err, &api) || api.Status != http.StatusForbidden ||
		!strings.Contains(api.Message, "Action: '"+keyvaultfake.ActionCertificatesCreate+"'") {
		t.Errorf("delete pending without create/action: %v", err)
	}
	if _, err := c.GetPending(ctx, "p"); !errors.As(err, &api) || api.Status != http.StatusForbidden ||
		!strings.Contains(api.Message, "Action: '"+keyvaultfake.ActionCertificatesCreate+"'") {
		t.Errorf("get pending without create/action: %v", err)
	}
	srv.SetDataActions(keyvaultfake.ActionCertificatesCreate)
	if err := c.DeletePending(ctx, "p"); err != nil {
		t.Errorf("delete pending with create/action alone: %v", err)
	}
	srv.SetDataActions(keyvaultfake.ActionCertificatesRead, keyvaultfake.ActionCertificatesCreate)
	if _, err := c.Sign(ctx, "k", "v", "ES256", make([]byte, 32)); !errors.As(err, &api) || api.Status != http.StatusForbidden {
		t.Errorf("sign: %v", err)
	}
	srv.GrantAll()
	if _, err := c.Sign(ctx, "k", "v", "ES256", make([]byte, 32)); errors.As(err, &api) && api.Status == http.StatusForbidden {
		t.Errorf("sign after GrantAll: %v", err)
	}
}
