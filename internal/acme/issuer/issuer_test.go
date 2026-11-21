package issuer_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/acmefake"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/azurednsfake"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/cloudflarefake"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/dnsstore"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/keyvaultfake"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/azuredns"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/cloudflare"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/issuer"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/keyvault"
)

const (
	sub     = "00000000-0000-0000-0000-000000000000"
	kvToken = "key-vault-test-token"
	rmToken = "resource-manager-test-token"
	cfToken = "cloudflare-test-token"
)

type env struct {
	acme   *acmefake.Server
	kv     *keyvaultfake.Server
	azure  *azurednsfake.Server
	cf     *cloudflarefake.Server
	store  *dnsstore.Store
	client *http.Client
	vault  *keyvault.Client
	reg    issuer.Registration
}

func newEnv(t *testing.T) *env {
	t.Helper()
	certs, err := acctest.NewCerts(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{store: dnsstore.New(), client: certs.HTTPClient()}
	if e.acme, err = acmefake.Start(certs.Server, e.store); err != nil {
		t.Fatal(err)
	}
	if e.kv, err = keyvaultfake.Start(certs.Server, kvToken); err != nil {
		t.Fatal(err)
	}
	e.azure = azurednsfake.Start(certs.Server, rmToken, e.store)
	e.cf = cloudflarefake.Start(certs.Server, e.store)
	t.Cleanup(func() { e.acme.Close(); e.kv.Close(); e.azure.Close(); e.cf.Close() })
	e.azure.AddZone(sub, "dns", "example.net")
	e.cf.AddZone("example.com")
	e.cf.AddToken(cfToken, "example.com")

	if e.vault, err = keyvault.New(e.kv.URL, kvToken, e.client); err != nil {
		t.Fatal(err)
	}
	keyID := e.kv.AddKey("account", "P256", true)
	key, err := acme.ParseKeyID(keyID)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := keyvault.NewSigner(context.Background(), e.vault, key.Name, key.Version)
	if err != nil {
		t.Fatal(err)
	}
	e.reg = issuer.Registration{ServerURL: e.acme.DirectoryURL(), Signer: signer, HTTPClient: e.client, RetryBase: time.Millisecond}
	return e
}

func (e *env) order(t *testing.T, name string, creating bool) issuer.Order {
	t.Helper()
	ids := []string{"example.com", "*.example.com", "*.apps.example.net"}
	blocks := []acme.Block{
		{Kind: acme.KindCloudflare, Zone: "example.com", MatchDomains: []string{"example.com"}},
		{Kind: acme.KindAzureDNS, Zone: "example.net", MatchDomains: []string{"apps.example.net"}},
	}
	routes, err := acme.Route(ids, blocks)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := cloudflare.New(e.cf.APIURL(), cfToken, e.client)
	if err != nil {
		t.Fatal(err)
	}
	az, err := azuredns.New(e.azure.URL, rmToken, e.client)
	if err != nil {
		t.Fatal(err)
	}
	return issuer.Order{
		Registration: e.reg, Vault: e.vault, Certificate: name, CommonName: "example.com", Identifiers: ids, KeyType: "RSA2048",
		Creating: creating, ImportID: acme.CertificateID(e.kv.URL, name), Routes: routes,
		Publishers: map[string]issuer.DNSPublisher{
			blocks[0].String(): cloudflare.NewZonePublisher(cf, "example.com"),
			blocks[1].String(): azuredns.NewZonePublisher(az, sub, "dns", "example.net"),
		},
		Checker: e.store.Checker(), WaitTimeout: 10 * time.Second,
	}
}

func TestAccountLookupRegisterAndUpdate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := issuer.Lookup(ctx, e.reg); !errors.Is(err, issuer.ErrNoAccount) {
		t.Fatalf("lookup before registration: %v", err)
	}
	if len(e.acme.Accounts()) != 0 {
		t.Fatal("a lookup created an account")
	}
	a, err := issuer.Register(ctx, e.reg, "a@example.com")
	if err != nil || a.URL == "" || !slices.Equal(a.Contact, []string{"mailto:a@example.com"}) {
		t.Fatalf("register: %+v %v", a, err)
	}
	// Registering again finds the existing account.
	again, err := issuer.Register(ctx, e.reg, "")
	if err != nil || again.URL != a.URL || len(e.acme.Accounts()) != 1 {
		t.Fatalf("second register: %+v %v (%d accounts)", again, err, len(e.acme.Accounts()))
	}
	found, err := issuer.Lookup(ctx, e.reg)
	if err != nil || found.URL != a.URL {
		t.Fatalf("lookup: %+v %v", found, err)
	}
	updated, err := issuer.UpdateContact(ctx, e.reg, a.URL, "b@example.com")
	if err != nil || !slices.Equal(updated.Contact, []string{"mailto:b@example.com"}) {
		t.Fatalf("update: %+v %v", updated, err)
	}
}

func TestFullOrderThroughBothDNSProviders(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := issuer.Register(ctx, e.reg, ""); err != nil {
		t.Fatal(err)
	}
	res, err := issuer.Issue(ctx, e.order(t, "example-com", true))
	if err != nil {
		t.Fatal(err)
	}
	if res.Bundle.Version == "" || res.Info.CommonName != "example.com" || len(res.Info.SANs) != 2 {
		t.Errorf("result: %+v", res.Info)
	}
	if all := e.store.All(); len(all) != 0 {
		t.Errorf("records left behind: %v", all)
	}
	if got := e.kv.PendingOperations(); len(got) != 0 {
		t.Errorf("pending operations left: %v", got)
	}
	if v := e.kv.Violations(); len(v) != 0 {
		t.Errorf("forbidden requests: %v", v)
	}
	// An order on the same name is an error when creating, and a new version otherwise.
	if _, err := issuer.Issue(ctx, e.order(t, "example-com", true)); err == nil || !strings.Contains(err.Error(), "import it with the ID") {
		t.Errorf("creating over an issued certificate: %v", err)
	}
	if _, err := issuer.Issue(ctx, e.order(t, "example-com", false)); err != nil {
		t.Fatal(err)
	}
	if n := len(e.kv.Versions("example-com")); n != 2 {
		t.Errorf("%d versions, want 2", n)
	}
}

func TestFailuresCleanUp(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		arm  func(e *env)
		want string
	}{
		"validation fails":  {func(e *env) { e.acme.FailValidation("*.apps.example.net") }, "failed"},
		"finalize fails":    {func(e *env) { e.acme.FailFinalize(true) }, "finalize"},
		"wrong key":         {func(e *env) { e.acme.IssueWrongKey(true) }, "key of the signing request"},
		"azure write fails": {func(e *env) { e.azure.FailWrites(true) }, "Azure DNS"},
		"cloudflare fails":  {func(e *env) { e.cf.FailWrites(true) }, "Cloudflare"},
		"never visible":     {func(e *env) { e.store.NeverPropagate("_acme-challenge.example.com") }, "did not become visible"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			if _, err := issuer.Register(ctx, e.reg, ""); err != nil {
				t.Fatal(err)
			}
			c.arm(e)
			_, err := issuer.Issue(ctx, e.order(t, "failing", true))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error containing %q, got %v", c.want, err)
			}
			if all := e.store.All(); len(all) != 0 {
				t.Errorf("records left behind: %v", all)
			}
			if got := e.kv.PendingOperations(); len(got) != 0 {
				t.Errorf("pending operations left: %v", got)
			}
			for _, v := range e.kv.Versions("failing") {
				if v.Issued {
					t.Errorf("a certificate was merged")
				}
			}
		})
	}
}

func TestRemovalFailureStopsBeforeFinalize(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := issuer.Register(ctx, e.reg, ""); err != nil {
		t.Fatal(err)
	}
	e.cf.FailDeletes(true)
	_, err := issuer.Issue(ctx, e.order(t, "stale", true))
	if err == nil || !strings.Contains(err.Error(), "_acme-challenge.example.com") {
		t.Fatalf("want an error naming the leftover records, got %v", err)
	}
	if len(e.kv.PendingOperations()) != 0 {
		t.Errorf("a pending operation is left")
	}
	if got := e.acme.IssuedSerials(); len(got) != 0 {
		t.Errorf("the order was finalized: %v", got)
	}
}

func TestRetriesAreBounded(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.acme.Fail5xx(3)
	if _, err := issuer.Register(ctx, e.reg, ""); err != nil {
		t.Fatalf("three failures are retried: %v", err)
	}
	e.acme.Fail5xx(4)
	start := time.Now()
	if _, err := issuer.Lookup(ctx, e.reg); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("four failures must end in an error, got %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("giving up took %s", d)
	}
	e.acme.ClearFailures()
	e.acme.RejectNextNonce()
	if _, err := issuer.Lookup(ctx, e.reg); err != nil {
		t.Errorf("a bad nonce is retried once: %v", err)
	}
}

func TestRevoke(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := issuer.Register(ctx, e.reg, ""); err != nil {
		t.Fatal(err)
	}
	res, err := issuer.Issue(ctx, e.order(t, "to-revoke", true))
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.Revoke(ctx, e.reg, res.Bundle.Cer); err != nil {
		t.Fatal(err)
	}
	if got := e.acme.Revoked(); !slices.Equal(got, []string{res.Info.Serial}) {
		t.Errorf("revoked %v, want %s", got, res.Info.Serial)
	}
	if err := issuer.Revoke(ctx, e.reg, res.Bundle.Cer); err != nil {
		t.Errorf("revoking twice: %v", err)
	}
	e.acme.RevokeRefused(true)
	if err := issuer.Revoke(ctx, e.reg, res.Bundle.Cer); err == nil {
		t.Error("a refusal was not reported")
	}
}
