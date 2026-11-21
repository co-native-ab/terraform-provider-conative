package provider

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
)

const certAddr = "conative_acme_certificate.c"

func certAttrs(s *terraform.State) (map[string]string, error) {
	rs, ok := s.RootModule().Resources[certAddr]
	if !ok {
		return nil, fmt.Errorf("%s is not in the state", certAddr)
	}
	return rs.Primary.Attributes, nil
}

// leafOf returns the latest issued certificate of a Key Vault certificate name.
func leafOf(name string) (*x509.Certificate, error) {
	der := acc.KeyVault.LeafDER(name, "")
	if der == nil {
		return nil, fmt.Errorf("the vault has no issued certificate %q", name)
	}
	return x509.ParseCertificate(der)
}

func markNow(m *acctest.Mark) func() { return func() { *m = acc.Mark() } }

// requireNoWrites fails the test when a fake saw a write since the mark.
func requireNoWrites(t *testing.T, m *acctest.Mark) func() {
	return func() {
		t.Helper()
		if w := acc.WritesSince(*m); len(w) > 0 {
			t.Errorf("planning wrote: %v", w)
		}
		if v := acc.KeyVault.Violations(); len(v) > 0 {
			t.Errorf("forbidden Key Vault requests: %v", v)
		}
	}
}

func dnsClean() resource.TestCheckFunc {
	return func(*terraform.State) error {
		if all := acc.DNS.All(); len(all) != 0 {
			return fmt.Errorf("challenge records are left behind: %v", all)
		}
		return nil
	}
}

func sortedStrings(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

func TestAccACMECertificate_mixedProvidersWildcardAndApex(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	cfg := f.config(certOptions{})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				ConfigVariables: acmeVariables(),
				Config:          cfg,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						leaf, err := leafOf(f.Cert)
						if err != nil {
							return err
						}
						want := []string{"*.apps.example.net", "*.example.com", "example.com"}
						if got := sortedStrings(leaf.DNSNames); !slices.Equal(got, want) {
							return fmt.Errorf("leaf names %v, want %v", got, want)
						}
						if k, ok := leaf.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != 2048 {
							return fmt.Errorf("the leaf key is not RSA 2048: %T", leaf.PublicKey)
						}
						if p := acc.KeyVault.Policy(f.Cert); !p.Exportable || p.Issuer != "Unknown" || p.KTY != "RSA" || p.KeySize != 2048 {
							return fmt.Errorf("unexpected policy %+v", p)
						}
						a, err := certAttrs(s)
						if err != nil {
							return err
						}
						if a["id"] != acc.KeyVault.URL+"/certificates/"+f.Cert || a["secret_id"] != acc.KeyVault.URL+"/secrets/"+f.Cert {
							return fmt.Errorf("ids: %s, %s", a["id"], a["secret_id"])
						}
						if a["version"] == "" || a["version"] != a["issued_version"] {
							return fmt.Errorf("version %q, issued_version %q", a["version"], a["issued_version"])
						}
						if !strings.HasPrefix(a["certificate_pem"], "-----BEGIN CERTIFICATE-----") || a["thumbprint"] == "" {
							return fmt.Errorf("pem or thumbprint missing")
						}
						if a["not_after"] != leaf.NotAfter.UTC().Format(time.RFC3339) {
							return fmt.Errorf("not_after %q, leaf %s", a["not_after"], leaf.NotAfter)
						}
						return nil
					},
					dnsClean(),
					func(*terraform.State) error {
						if v := acc.KeyVault.Violations(); len(v) > 0 {
							return fmt.Errorf("forbidden Key Vault requests: %v", v)
						}
						if p := acc.KeyVault.PendingOperations(); slices.Contains(p, f.Cert) {
							return fmt.Errorf("a pending operation is left")
						}
						return nil
					},
					resource.TestCheckNoResourceAttr(certAddr, "cloudflare.0.api_token"),
					resource.TestCheckResourceAttr(certAddr, "min_days_remaining", "30"),
				),
			},
			// The plan after apply is empty (checked by the framework); say it explicitly.
			{ConfigVariables: acmeVariables(), Config: cfg, PlanOnly: true},
		},
	})
}

func TestAccACMECertificate_keyTypes(t *testing.T) {
	accPreCheck(t)
	for _, kt := range []string{"RSA2048", "RSA3072", "RSA4096", "P256", "P384", "P521"} {
		t.Run(kt, func(t *testing.T) {
			f := newACMEFixture(t, "P256")
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: newTestProviderFactories(),
				Steps: []resource.TestStep{{
					ConfigVariables: acmeVariables(),
					Config:          f.config(certOptions{KeyType: kt, SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(certAddr, "key_type", kt),
						func(*terraform.State) error {
							leaf, err := leafOf(f.Cert)
							if err != nil {
								return err
							}
							if got := keyTypeOfCert(leaf); got != kt {
								return fmt.Errorf("the vault's key is %s, want %s", got, kt)
							}
							return nil
						},
					),
				}},
			})
		})
	}
}

func keyTypeOfCert(c *x509.Certificate) string {
	if k, ok := c.PublicKey.(*rsa.PublicKey); ok {
		return fmt.Sprintf("RSA%d", k.N.BitLen())
	}
	return map[int]string{256: "P256", 384: "P384", 521: "P521"}[ecBits(c)]
}

const cloudflareOnly = `
  cloudflare {
    zone          = "example.com"
    match_domains = ["example.com"]
    api_token     = var.cf_token
  }
`

func TestAccACMECertificate_routingErrors(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	cases := map[string]struct {
		tweaks certOptions
		want   string
	}{
		"uncovered name": {certOptions{SANs: []string{"*.example.org"}}, `not\s+covered\s+by\s+any\s+match_domains`},
		"same entry in both kinds": {certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly + `
  azure_dns {
    subscription_id = "00000000-0000-0000-0000-000000000000"
    resource_group  = "dns"
    zone_name       = "example.com"
    match_domains   = ["example.com"]
  }`}, `appears\s+in\s+(azure_dns\[0\]\s+and\s+cloudflare\[0\]|cloudflare\[0\]\s+and\s+azure_dns\[0\])`},
		"entry outside its zone": {certOptions{SANs: []string{"*.example.com"}, Blocks: `
  cloudflare {
    zone          = "example.com"
    match_domains = ["example.net"]
    api_token     = var.cf_token
  }`}, `not\s+equal\s+to\s+or\s+inside\s+the\s+zone`},
		"no dns block":    {certOptions{SANs: []string{"*.example.com"}, Blocks: " "}, `at\s+least\s+one\s+azure_dns\s+or\s+cloudflare\s+block`},
		"upper case name": {certOptions{CN: "Example.com", SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}, `must\s+be\s+lower\s+case`},
		"common name repeated": {certOptions{SANs: []string{"example.com"}, Blocks: cloudflareOnly},
			`do\s+not\s+repeat\s+it`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var mark acctest.Mark
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: newTestProviderFactories(),
				Steps: []resource.TestStep{{
					PreConfig:       markNow(&mark),
					ConfigVariables: acmeVariables(),
					Config:          f.config(c.tweaks),
					PlanOnly:        true,
					ExpectError:     regexp.MustCompile(`(?s)` + c.want),
				}},
			})
			if r := acc.RequestsSince(mark); len(r) > 0 {
				t.Errorf("a configuration error must not cause any request: %v", r)
			}
		})
	}
}

func TestAccACMECertificate_nestedSuffixRouting(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	acc.AzureDNS.AddZone(testSubscription, testResourceGrp, "apps.example.com")
	var mark acctest.Mark
	blocks := cloudflareOnly + `
  azure_dns {
    subscription_id = "00000000-0000-0000-0000-000000000000"
    resource_group  = "dns"
    zone_name       = "apps.example.com"
    match_domains   = ["apps.example.com"]
  }
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{{
			PreConfig:       markNow(&mark),
			ConfigVariables: acmeVariables(),
			Config:          f.config(certOptions{CN: "www.example.com", SANs: []string{"x.apps.example.com"}, Blocks: blocks}),
			Check: func(*terraform.State) error {
				var azure, cf []string
				for _, e := range acc.AzureDNS.Journal.WritesSince(mark.AzureDNSPosition()) {
					azure = append(azure, e.String())
				}
				for _, e := range acc.Cloudflare.Journal.WritesSince(mark.CloudflarePosition()) {
					cf = append(cf, e.String())
				}
				if !slices.ContainsFunc(azure, func(s string) bool {
					return strings.HasPrefix(s, "PUT ") && strings.Contains(s, "/dnsZones/apps.example.com/TXT/_acme-challenge.x")
				}) {
					return fmt.Errorf("x.apps.example.com was not published through Azure DNS: %v", azure)
				}
				if len(azure) != 2 {
					return fmt.Errorf("Azure DNS should see exactly one publish and one removal: %v", azure)
				}
				if len(cf) != 2 {
					return fmt.Errorf("Cloudflare should see exactly one create and one delete (www.example.com): %v", cf)
				}
				return nil
			},
		}},
	})
}

func TestAccACMECertificate_existingCertificateRequiresImport(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	var mark acctest.Mark
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{{
			PreConfig: func() {
				importLeaf(t, f.Cert, "OtherCA", false)
				mark = acc.Mark()
			},
			ConfigVariables: acmeVariables(),
			Config:          f.config(certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}),
			PlanOnly:        true,
			ExpectError: regexp.MustCompile(`(?s)import\s+it\s+with\s+the\s+ID\s+` +
				regexp.QuoteMeta(acc.KeyVault.URL+"/certificates/"+f.Cert)),
		}},
	})
	requireNoWrites(t, &mark)()
}

func TestAccACMECertificate_preflightZoneChecks(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	var mark acctest.Mark
	unknownAzure := `
  azure_dns {
    subscription_id = "00000000-0000-0000-0000-000000000000"
    resource_group  = "dns"
    zone_name       = "missing.example.net"
    match_domains   = ["missing.example.net"]
  }
`
	foreignCloudflare := `
  cloudflare {
    zone          = "example.org"
    match_domains = ["example.org"]
    api_token     = var.cf_token
  }
`
	noRM := strings.Replace(acmeProviderConfig(), "resource_manager_access_token = var.arm_token", "", 1)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				PreConfig:       markNow(&mark),
				ConfigVariables: acmeVariables(),
				Config:          f.config(certOptions{CN: "x.missing.example.net", SANs: []string{}, Blocks: unknownAzure}),
				PlanOnly:        true,
				ExpectError:     regexp.MustCompile(`(?s)ResourceNotFound`),
			},
			{
				PreConfig:       requireNoWrites(t, &mark),
				ConfigVariables: acmeVariables(),
				Config:          f.config(certOptions{CN: "example.org", SANs: []string{}, Blocks: foreignCloudflare}),
				PlanOnly:        true,
				ExpectError:     regexp.MustCompile(`(?s)not\s+found\s+or\s+cannot\s+be\s+read`),
			},
			{
				ConfigVariables: acmeVariables(),
				Config:          noRM + f.registrationHCL("") + f.certHCL(certOptions{}),
				PlanOnly:        true,
				ExpectError:     regexp.MustCompile(`(?s)resource_manager_access_token`),
			},
		},
	})
	requireNoWrites(t, &mark)()
}

func TestAccACMECertificate_existingTXTKept(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	var cfRecord string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{{
			PreConfig: func() {
				acc.AzureDNS.Seed(testSubscription, testResourceGrp, "example.net", "_acme-challenge.apps", "foreign-azure-value")
				cfRecord = acc.Cloudflare.Seed("example.com", "_acme-challenge.example.com", "foreign-cloudflare-value")
			},
			ConfigVariables: acmeVariables(),
			Config:          f.config(certOptions{}),
			Check: func(*terraform.State) error {
				if got := acc.AzureDNS.Values(testSubscription, testResourceGrp, "example.net", "_acme-challenge.apps"); !slices.Equal(got, []string{"foreign-azure-value"}) {
					return fmt.Errorf("Azure DNS values %v", got)
				}
				if got := acc.DNS.Values("_acme-challenge.example.com"); !slices.Equal(got, []string{"foreign-cloudflare-value"}) {
					return fmt.Errorf("Cloudflare values %v (record %s)", got, cfRecord)
				}
				if n := acc.Cloudflare.RecordCount("example.com"); n != 1 {
					return fmt.Errorf("%d Cloudflare records, want only the foreign one", n)
				}
				return nil
			},
		}},
	})
}

// importLeaf puts an existing certificate into the vault from outside the provider.
func importLeaf(t *testing.T, name, issuer string, exportable bool) string {
	t.Helper()
	v, err := acc.KeyVault.ImportCertificate(name, importOptions(issuer, exportable))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// ---- renewal, changes and plans ------------------------------------------------------

func TestAccACMECertificate_renewalWindow(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	var id string
	var mark acctest.Mark
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly, MinDays: 5}
	renew := tweaks
	renew.MinDays = 15

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				PreConfig:       func() { acc.ACME.SetValidity(10 * 24 * time.Hour) },
				ConfigVariables: acmeVariables(),
				Config:          f.config(tweaks),
				Check: func(s *terraform.State) error {
					a, err := certAttrs(s)
					id = a["id"]
					return err
				},
			},
			{
				PreConfig:       markNow(&mark),
				ConfigVariables: acmeVariables(),
				Config:          f.config(tweaks),
				PlanOnly:        true,
			},
			{
				PreConfig: func() {
					requireNoWrites(t, &mark)()
					acc.ACME.SetValidity(90 * 24 * time.Hour)
				},
				ConfigVariables: acmeVariables(),
				Config:          f.config(renew),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(certAddr, plancheck.ResourceActionUpdate),
					plancheck.ExpectUnknownValue(certAddr, tfjsonpath.New("version")),
					plancheck.ExpectUnknownValue(certAddr, tfjsonpath.New("not_after")),
				}},
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						a, err := certAttrs(s)
						if err != nil {
							return err
						}
						if a["id"] != id {
							return fmt.Errorf("the ID changed: %s -> %s", id, a["id"])
						}
						if n := vaultVersions(f.Cert); n != 2 {
							return fmt.Errorf("%d issued versions, want 2 (the old one stays)", n)
						}
						if a["version"] != a["issued_version"] {
							return fmt.Errorf("version %s, issued %s", a["version"], a["issued_version"])
						}
						return nil
					},
					dnsClean(),
				),
			},
		},
	})
}

func TestAccACMECertificate_externalVersion(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	var external string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: f.config(tweaks)},
			{
				PreConfig: func() {
					v, err := acc.KeyVault.AddExternalVersion(f.Cert)
					if err != nil {
						t.Fatal(err)
					}
					external = v
				},
				ConfigVariables: acmeVariables(),
				Config:          f.config(tweaks),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(certAddr, plancheck.ResourceActionUpdate),
				}},
				Check: func(s *terraform.State) error {
					a, err := certAttrs(s)
					if err != nil {
						return err
					}
					if n := vaultVersions(f.Cert); n != 3 {
						return fmt.Errorf("%d issued versions, want 3", n)
					}
					if a["version"] == external || a["version"] != a["issued_version"] {
						return fmt.Errorf("version %s, issued %s, external %s", a["version"], a["issued_version"], external)
					}
					return nil
				},
			},
		},
	})
}

func TestAccACMECertificate_namesChange(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	base := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	more := base
	more.SANs = []string{"*.example.com", "www.example.com"}
	ec := more
	ec.KeyType = "P256"
	update := resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
		plancheck.ExpectResourceAction(certAddr, plancheck.ResourceActionUpdate),
	}}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: f.config(base)},
			{
				ConfigVariables: acmeVariables(), Config: f.config(more), ConfigPlanChecks: update,
				Check: func(*terraform.State) error {
					leaf, err := leafOf(f.Cert)
					if err != nil {
						return err
					}
					if !slices.Contains(leaf.DNSNames, "www.example.com") || vaultVersions(f.Cert) != 2 {
						return fmt.Errorf("names %v, versions %d", leaf.DNSNames, vaultVersions(f.Cert))
					}
					return nil
				},
			},
			{
				ConfigVariables: acmeVariables(), Config: f.config(ec), ConfigPlanChecks: update,
				Check: func(*terraform.State) error {
					leaf, err := leafOf(f.Cert)
					if err != nil {
						return err
					}
					if keyTypeOfCert(leaf) != "P256" || vaultVersions(f.Cert) != 3 {
						return fmt.Errorf("key %s, versions %d", keyTypeOfCert(leaf), vaultVersions(f.Cert))
					}
					if p := acc.KeyVault.Policy(f.Cert); p.KTY != "EC" || p.Curve != "P-256" {
						return fmt.Errorf("policy %+v", p)
					}
					return nil
				},
			},
		},
	})
}

func TestAccACMECertificate_stateOnlyChange(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	second := acc.KeyVault.AddKey(uniqueName("acct2"), "P256", true)
	secondReg := fmt.Sprintf(`
resource "conative_acme_registration" "r2" {
  server_url     = %q
  account_key_id = %q
}
`, acc.ACME.DirectoryURL(), second)
	base := certOptions{SANs: []string{"*.example.com", "*.apps.example.net"}}
	swapped := base
	swapped.Registrat = "conative_acme_registration.r2.id"
	swapped.Revoke = "false"
	swapped.MinDays = 20
	swapped.Blocks = `
  azure_dns {
    subscription_id = "00000000-0000-0000-0000-000000000000"
    resource_group  = "dns"
    zone_name       = "example.net"
    match_domains   = ["apps.example.net"]
  }

  cloudflare {
    zone          = "example.com"
    match_domains = ["example.com"]
    api_token     = var.cf_token
  }
`
	var mark acctest.Mark
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				ConfigVariables: acmeVariables(), Config: f.config(base) + secondReg,
			},
			{
				PreConfig:       markNow(&mark),
				ConfigVariables: acmeVariables(),
				Config:          f.config(swapped) + secondReg,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(certAddr, plancheck.ResourceActionUpdate),
					plancheck.ExpectKnownValue(certAddr, tfjsonpath.New("version"), knownvalue.NotNull()),
					plancheck.ExpectKnownValue(certAddr, tfjsonpath.New("issued_version"), knownvalue.NotNull()),
				}},
				Check: resource.ComposeTestCheckFunc(noWritesSince(&mark), resource.TestCheckResourceAttr(certAddr, "revoke_on_destroy", "false")),
			},
		},
	})
}

func TestAccACMECertificate_planWritesNothing(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	base := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly, MinDays: 5}
	due := base
	due.MinDays = 15
	var mark acctest.Mark
	assertAndMark := func() {
		requireNoWrites(t, &mark)()
		mark = acc.Mark()
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ // (a) a new certificate and registration
				PreConfig: markNow(&mark), ConfigVariables: acmeVariables(), Config: f.config(base),
				PlanOnly: true, ExpectNonEmptyPlan: true,
			},
			{
				PreConfig: func() { assertAndMark(); acc.ACME.SetValidity(10 * 24 * time.Hour) }, ConfigVariables: acmeVariables(), Config: f.config(base),
			},
			{ // (b) a due renewal
				PreConfig: markNow(&mark), ConfigVariables: acmeVariables(), Config: f.config(due),
				PlanOnly: true, ExpectNonEmptyPlan: true,
			},
			{ // (c) an external version
				PreConfig: func() {
					assertAndMark()
					if _, err := acc.KeyVault.AddExternalVersion(f.Cert); err != nil {
						t.Fatal(err)
					}
					mark = acc.Mark()
				},
				ConfigVariables: acmeVariables(), Config: f.config(base), PlanOnly: true, ExpectNonEmptyPlan: true,
			},
			{ // (d) a refresh-only plan
				PreConfig: assertAndMark, ConfigVariables: acmeVariables(),
				RefreshState: true, ExpectNonEmptyPlan: true,
			},
			{ // the refresh-only plan wrote nothing; now apply the pending renewal
				PreConfig: assertAndMark, ConfigVariables: acmeVariables(), Config: f.config(base),
			},
		},
	})
}

func TestAccACMECertificate_lifetimeWarning(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	logFile := acctest.EnableTraceLogs(t, t.TempDir())
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly, MinDays: 20}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{{
			PreConfig:          func() { acc.ACME.SetValidity(10 * 24 * time.Hour) },
			ConfigVariables:    acmeVariables(),
			Config:             f.config(tweaks),
			ExpectNonEmptyPlan: true,
		}},
	})
	acctest.AssertLogContains(t, logFile, "min_days_remaining (20 days)")
}
