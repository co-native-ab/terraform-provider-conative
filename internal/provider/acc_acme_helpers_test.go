package provider

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/config"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/keyvaultfake"
)

const (
	testSubscription = "00000000-0000-0000-0000-000000000000"
	testResourceGrp  = "dns"
)

// newTestProviderFactories builds a provider whose fixed endpoints and propagation check
// point at the fakes. Only test files can do this: the fields are unexported.
func newTestProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"conative": func() (tfprotov6.ProviderServer, error) {
			p := &conativeProvider{version: "test", acmeEnv: acmeEnv{
				resourceManagerURL: acc.AzureDNS.URL,
				cloudflareURL:      acc.Cloudflare.APIURL(),
				propagation:        acc.DNS.Checker(),
				retryBase:          5 * time.Millisecond,
				waitTimeout:        30 * time.Second,
				httpClient:         acc.HTTPClient(),
			}}
			return providerserver.NewProtocol6WithError(p)()
		},
	}
}

// acmeProviderConfig is the provider block of the ACME acceptance configurations. The
// tokens come from ephemeral, sensitive variables, as they would in practice.
func acmeProviderConfig() string {
	return `
variable "kv_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "arm_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "cf_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

provider "conative" {
  acme = {
    key_vault_access_token        = var.kv_token
    resource_manager_access_token = var.arm_token
  }
}
`
}

func acmeVariables() config.Variables {
	return config.Variables{
		"kv_token":  config.StringVariable(acc.KeyVaultToken),
		"arm_token": config.StringVariable(acc.ResourceManagerToken),
		"cf_token":  config.StringVariable(acc.CloudflareToken),
	}
}

var acmeCounter atomic.Int64

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano()%1_000_000, acmeCounter.Add(1))
}

// setupDNS registers the zones the configurations use and lets the Cloudflare token use
// its zone.
func setupDNS(t *testing.T) {
	t.Helper()
	acc.AzureDNS.AddZone(testSubscription, testResourceGrp, "example.net")
	acc.Cloudflare.AddZone("example.com")
	acc.Cloudflare.AddToken(acc.CloudflareToken, "example.com")
	acc.Cloudflare.AddReadOnlyToken(acc.CloudflareReadOnlyToken, "example.com")
	acc.KeyVault.SetReader(false)
	acc.ACME.ClearFailures()
	acc.ACME.SetValidity(90 * 24 * time.Hour)
	acc.KeyVault.SetFailure(0)
	acc.AzureDNS.FailWrites(false)
	acc.Cloudflare.FailWrites(false)
	reset := func() {
		acc.ACME.ClearFailures()
		acc.KeyVault.SetFailure(0)
		acc.KeyVault.SetReader(false)
		acc.AzureDNS.FailWrites(false)
		acc.AzureDNS.FailDeletes(false)
		acc.Cloudflare.FailWrites(false)
		acc.Cloudflare.FailDeletes(false)
		acc.AzureDNS.Reset()
		acc.Cloudflare.Reset()
		acc.DNS.Reset()
	}
	reset()
	t.Cleanup(reset)
}

// acmeFixture is a Key Vault account key and the names a test uses.
type acmeFixture struct {
	KeyName string
	KeyID   string
	Cert    string
}

func newACMEFixture(t *testing.T, keyKind string) acmeFixture {
	t.Helper()
	setupDNS(t)
	name := uniqueName("acct")
	return acmeFixture{KeyName: name, KeyID: acc.KeyVault.AddKey(name, keyKind, true), Cert: uniqueName("cert")}
}

// registrationHCL declares the registration every certificate test uses.
func (f acmeFixture) registrationHCL(extra string) string {
	return fmt.Sprintf(`
resource "conative_acme_registration" "r" {
  server_url     = %q
  account_key_id = %q
  %s
}
`, acc.ACME.DirectoryURL(), f.KeyID, extra)
}

const mixedBlocks = `
  cloudflare {
    zone          = "example.com"
    match_domains = ["example.com"]
    api_token     = var.cf_token
  }

  azure_dns {
    subscription_id = "00000000-0000-0000-0000-000000000000"
    resource_group  = "dns"
    zone_name       = "example.net"
    match_domains   = ["apps.example.net"]
  }
`

// certOptions describes a conative_acme_certificate for the tests.
type certOptions struct {
	CN        string
	SANs      []string
	KeyType   string
	MinDays   int
	Revoke    string // "true" or "false"
	VaultURL  string
	Blocks    string
	Resource  string // address name, default "c"
	Registrat string // registration_id expression, default the fixture's registration
}

func (f acmeFixture) certHCL(s certOptions) string {
	if s.CN == "" {
		s.CN = "example.com"
	}
	if s.SANs == nil {
		s.SANs = []string{"*.example.com", "*.apps.example.net"}
	}
	if s.KeyType == "" {
		s.KeyType = "RSA2048"
	}
	if s.Revoke == "" {
		s.Revoke = "true"
	}
	if s.VaultURL == "" {
		s.VaultURL = acc.KeyVault.URL
	}
	if s.Blocks == "" {
		s.Blocks = mixedBlocks
	}
	if s.Resource == "" {
		s.Resource = "c"
	}
	if s.Registrat == "" {
		s.Registrat = "conative_acme_registration.r.id"
	}
	revoke := "revoke_on_destroy         = " + s.Revoke
	if s.Revoke == "omit" {
		revoke = ""
	}
	var sans []string
	for _, n := range s.SANs {
		sans = append(sans, fmt.Sprintf("%q", n))
	}
	days := ""
	if s.MinDays != 0 {
		days = fmt.Sprintf("min_days_remaining = %d", s.MinDays)
	}
	return fmt.Sprintf(`
resource "conative_acme_certificate" %q {
  registration_id           = %s
  key_vault_url             = %q
  certificate_name          = %q
  common_name               = %q
  subject_alternative_names = [%s]
  key_type                  = %q
  %s
  %s
  %s
}
`, s.Resource, s.Registrat, s.VaultURL, f.Cert, s.CN, strings.Join(sans, ", "), s.KeyType, revoke, days, s.Blocks)
}

// config is the whole configuration of a certificate test step.
func (f acmeFixture) config(s certOptions) string {
	return acmeProviderConfig() + f.registrationHCL(`email = "certificates@example.com"`) + f.certHCL(s)
}

// noWritesSince returns a check that fails when any fake saw a write since the mark.
func noWritesSince(mark *acctest.Mark) func(*terraform.State) error {
	return func(*terraform.State) error {
		if w := acc.WritesSince(*mark); len(w) > 0 {
			return fmt.Errorf("unexpected writes: %v", w)
		}
		if v := acc.KeyVault.Violations(); len(v) > 0 {
			return fmt.Errorf("the provider made requests it must never make: %v", v)
		}
		return nil
	}
}

// vaultVersions returns the number of issued versions of a certificate in the fake vault.
func vaultVersions(name string) int {
	n := 0
	for _, v := range acc.KeyVault.Versions(name) {
		if v.Issued {
			n++
		}
	}
	return n
}

// importOptions describe a certificate that was issued and put into the vault elsewhere.
func importOptions(issuer string, exportable bool) keyvaultfake.ImportOptions {
	return keyvaultfake.ImportOptions{
		Issuer: issuer, Exportable: exportable, Key: "RSA2048", CommonName: "example.com",
		DNSNames: []string{"EXAMPLE.com", "*.example.com", "example.com"}, Validity: 90 * 24 * time.Hour,
		LifetimeActions: []string{"EmailContacts"},
	}
}

// ecBits returns the size in bits of an EC certificate's curve.
func ecBits(c *x509.Certificate) int {
	if k, ok := c.PublicKey.(*ecdsa.PublicKey); ok {
		return k.Curve.Params().BitSize
	}
	return 0
}

func ipList(addrs ...string) []net.IP {
	var out []net.IP
	for _, a := range addrs {
		out = append(out, net.ParseIP(a))
	}
	return out
}

func (f acmeFixture) registrationOnlyConfig() string {
	return acmeProviderConfig() + f.registrationHCL("")
}
