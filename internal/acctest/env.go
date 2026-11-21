package acctest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/acmefake"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/azurednsfake"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/cloudflarefake"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/dnsstore"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/fakehttp"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/keyvaultfake"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/tdsproxy"
)

// Env is everything an acceptance run needs: a SQL Server container, certificates, a
// sign-in proxy in front of the container, and the token the proxy accepts.
type Env struct {
	Container *Container
	Certs     *Certs
	Proxy     *tdsproxy.Proxy
	// Token is the access token the proxy accepts. It is random per run, as long as a
	// real token, so that tests can search for it.
	Token string
	// WrongToken is a different token of the same shape that the proxy refuses.
	WrongToken string
	// Server is "localhost:port" of the proxy: what a provider configuration uses.
	Server string

	// The fakes of the ACME area and the DNS they share. They serve HTTPS on localhost
	// with the per-run certificate and accept only their own random token.
	DNS        *dnsstore.Store
	ACME       *acmefake.Server
	KeyVault   *keyvaultfake.Server
	AzureDNS   *azurednsfake.Server
	Cloudflare *cloudflarefake.Server
	// KeyVaultToken, ResourceManagerToken and CloudflareToken are random tokens of the
	// shape of real ones, so that tests can search for them. Each fake rejects the others.
	KeyVaultToken        string
	ResourceManagerToken string
	CloudflareToken      string

	dir string
}

// SetupEnv generates certificates, makes clients trust them by pointing SSL_CERT_FILE
// at the authority (this must happen before anything uses TLS), starts the container
// and the proxy. Callers must call Close.
func SetupEnv(ctx context.Context) (*Env, error) {
	dir, err := os.MkdirTemp("", "conative-acc-")
	if err != nil {
		return nil, err
	}
	e := &Env{dir: dir}
	fail := func(err error) (*Env, error) {
		e.Close()
		return nil, err
	}

	if e.Certs, err = NewCerts(dir); err != nil {
		return fail(err)
	}
	if err := os.Setenv("SSL_CERT_FILE", e.Certs.CAFile); err != nil {
		return fail(err)
	}
	if e.Token, err = randomToken(); err != nil {
		return fail(err)
	}
	if e.WrongToken, err = randomToken(); err != nil {
		return fail(err)
	}
	for _, t := range []*string{&e.KeyVaultToken, &e.ResourceManagerToken, &e.CloudflareToken} {
		if *t, err = randomToken(); err != nil {
			return fail(err)
		}
	}
	e.DNS = dnsstore.New()
	if e.ACME, err = acmefake.Start(e.Certs.Server, e.DNS); err != nil {
		return fail(err)
	}
	if e.KeyVault, err = keyvaultfake.Start(e.Certs.Server, e.KeyVaultToken); err != nil {
		return fail(err)
	}
	e.AzureDNS = azurednsfake.Start(e.Certs.Server, e.ResourceManagerToken, e.DNS)
	e.Cloudflare = cloudflarefake.Start(e.Certs.Server, e.DNS)
	if e.Container, err = StartContainer(ctx); err != nil {
		return fail(err)
	}
	if e.Proxy, err = e.NewProxy(); err != nil {
		return fail(err)
	}
	e.Server = ServerName(e.Proxy)
	return e, nil
}

// NewProxy starts another sign-in proxy in front of the same container, for tests that
// need to stop one without affecting the others.
func (e *Env) NewProxy() (*tdsproxy.Proxy, error) { return e.NewProxyAt("127.0.0.1:0") }

// NewProxyAt starts a sign-in proxy listening on a given address, for example to bring
// a proxy back on the address of one that was closed.
func (e *Env) NewProxyAt(listenAddr string) (*tdsproxy.Proxy, error) {
	return tdsproxy.Start(tdsproxy.Config{
		ListenAddr:   listenAddr,
		Certificate:  e.Certs.Server,
		Token:        e.Token,
		UpstreamAddr: e.Container.Addr,
		UpstreamUser: "sa",
		UpstreamPass: e.Container.Password,
	})
}

// ServerName returns the provider-facing server name of a proxy, "localhost:port".
func ServerName(p *tdsproxy.Proxy) string {
	_, port, _ := splitAddr(p.Addr())
	return fmt.Sprintf("localhost:%d", port)
}

// Mark is a position in the request journals of the four fakes.
type Mark struct{ acme, keyVault, azureDNS, cloudflare int }

// ACMEPosition is the position in the certificate authority's journal.
func (m Mark) ACMEPosition() int { return m.acme }

// AzureDNSPosition is the position in the Azure DNS journal.
func (m Mark) AzureDNSPosition() int { return m.azureDNS }

// CloudflarePosition is the position in the Cloudflare journal.
func (m Mark) CloudflarePosition() int { return m.cloudflare }

// Mark returns the current position of every journal.
func (e *Env) Mark() Mark {
	return Mark{e.ACME.Journal.Mark(), e.KeyVault.Journal.Mark(), e.AzureDNS.Journal.Mark(), e.Cloudflare.Journal.Mark()}
}

// WritesSince lists, across the four fakes, the requests since the mark that changed
// something. Reads (including Key Vault sign operations and ACME account lookups) are
// not listed.
func (e *Env) WritesSince(m Mark) []string {
	var out []string
	add := func(prefix string, entries []fakehttp.Entry) {
		for _, w := range entries {
			out = append(out, prefix+" "+w.String())
		}
	}
	add("acme", e.ACME.Journal.WritesSince(m.acme))
	add("keyvault", e.KeyVault.Journal.WritesSince(m.keyVault))
	add("azuredns", e.AzureDNS.Journal.WritesSince(m.azureDNS))
	add("cloudflare", e.Cloudflare.Journal.WritesSince(m.cloudflare))
	return out
}

// RequestsSince lists every request, read or write, that any fake served since the mark.
func (e *Env) RequestsSince(m Mark) []string {
	var out []string
	add := func(prefix string, entries []fakehttp.Entry) {
		for _, w := range entries {
			out = append(out, prefix+" "+w.String())
		}
	}
	add("acme", e.ACME.Journal.Since(m.acme))
	add("keyvault", e.KeyVault.Journal.Since(m.keyVault))
	add("azuredns", e.AzureDNS.Journal.Since(m.azureDNS))
	add("cloudflare", e.Cloudflare.Journal.Since(m.cloudflare))
	return out
}

// Close stops the fakes and the proxy, removes the container and deletes the temporary
// files.
func (e *Env) Close() {
	if e.ACME != nil {
		e.ACME.Close()
	}
	if e.KeyVault != nil {
		e.KeyVault.Close()
	}
	if e.AzureDNS != nil {
		e.AzureDNS.Close()
	}
	if e.Cloudflare != nil {
		e.Cloudflare.Close()
	}
	if e.Proxy != nil {
		_ = e.Proxy.Close()
	}
	if e.Container != nil {
		e.Container.Remove()
	}
	if e.dir != "" {
		_ = os.RemoveAll(e.dir)
	}
}

func randomToken() (string, error) {
	b := make([]byte, 1700)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// About 2.2 KB of base64, in the shape of a signed JWT: long enough that the login
	// message spans more than one 4096-byte packet.
	s := base64.RawURLEncoding.EncodeToString(b)
	return "eyJ" + s[:1000] + "." + s[1000:1700] + "." + s[1700:], nil
}
