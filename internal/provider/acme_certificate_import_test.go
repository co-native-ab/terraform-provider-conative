package provider

import (
	"crypto/sha1" //nolint:gosec // the thumbprint is a SHA-1 by definition
	"crypto/x509"
	"encoding/hex"
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
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/keyvaultfake"
)

// importID is the versionless certificate ID of a name in the fake vault.
func importID(name string) string { return acc.KeyVault.URL + "/certificates/" + name }

func registrationOnly(f acmeFixture) string {
	return acmeProviderConfig() + f.registrationHCL(`email = "certificates@example.com"`)
}

var ignoreUnreadable = []string{"registration_id", "revoke_on_destroy", "azure_dns", "cloudflare"}

func TestAccACMECertificate_import(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	slash := tweaks
	slash.VaultURL = acc.KeyVault.URL + "/"
	var mark acctest.Mark
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: f.config(tweaks)},
			{
				ConfigVariables:         acmeVariables(),
				Config:                  f.config(tweaks),
				ResourceName:            certAddr,
				ImportState:             true,
				ImportStateId:           importID(f.Cert),
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: ignoreUnreadable,
			},
			{
				// Another spelling of the same vault URL is no change at all.
				PreConfig:       markNow(&mark),
				ConfigVariables: acmeVariables(),
				Config:          f.config(slash),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectEmptyPlan(),
				}},
				Check: noWritesSince(&mark),
			},
		},
	})
}

// existingStep puts an existing certificate into the vault before the step runs.
func existingCert(t *testing.T, f acmeFixture, o keyvaultfake.ImportOptions, version *string) func() {
	return func() {
		v, err := acc.KeyVault.ImportCertificate(f.Cert, o)
		if err != nil {
			t.Fatal(err)
		}
		*version = v
	}
}

func existingOptions() keyvaultfake.ImportOptions {
	o := importOptions("OtherCA", false)
	return o
}

func TestAccACMECertificate_importExisting(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	var imported, id, secretID string
	var mark acctest.Mark
	matching := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly, VaultURL: acc.KeyVault.URL + "/"}
	due := matching
	due.MinDays = 100
	onlyKnown := func(attr string) plancheck.PlanCheck {
		return plancheck.ExpectKnownValue(certAddr, tfjsonpath.New(attr), knownvalue.NotNull())
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: registrationOnly(f)},
			{
				PreConfig: func() {
					existingCert(t, f, existingOptions(), &imported)()
					mark = acc.Mark()
				},
				ConfigVariables:    acmeVariables(),
				Config:             f.config(matching),
				ResourceName:       certAddr,
				ImportState:        true,
				ImportStatePersist: true,
				ImportStateId:      importID(f.Cert),
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					var a map[string]string
					for _, st := range states {
						if st.Attributes["certificate_name"] == f.Cert {
							a = st.Attributes
						}
					}
					if a == nil {
						return fmt.Errorf("the certificate is not among the %d imported states", len(states))
					}
					der := acc.KeyVault.LeafDER(f.Cert, "")
					sum := sha1.Sum(der) //nolint:gosec // see the import
					leaf, _ := x509.ParseCertificate(der)
					want := map[string]string{
						"version": imported, "issued_version": imported, "common_name": "example.com", "key_type": "RSA2048",
						"min_days_remaining": "30", "subject_alternative_names.#": "1",
						"thumbprint": strings.ToUpper(hex.EncodeToString(sum[:])), "not_after": leaf.NotAfter.UTC().Format(time.RFC3339),
						"id": importID(f.Cert), "secret_id": acc.KeyVault.URL + "/secrets/" + f.Cert,
					}
					for k, v := range want {
						if a[k] != v {
							return fmt.Errorf("%s = %q, want %q", k, a[k], v)
						}
					}
					if !strings.HasPrefix(a["certificate_pem"], "-----BEGIN CERTIFICATE-----") {
						return fmt.Errorf("certificate_pem is not set")
					}
					if _, ok := a["registration_id"]; ok {
						return fmt.Errorf("registration_id must stay null after import")
					}
					if v, ok := a["revoke_on_destroy"]; ok {
						return fmt.Errorf("revoke_on_destroy must stay null after import, got %q", v)
					}
					if w := acc.WritesSince(mark); len(w) > 0 {
						return fmt.Errorf("import wrote: %v", w)
					}
					if v := acc.KeyVault.Violations(); len(v) > 0 {
						return fmt.Errorf("forbidden requests: %v", v)
					}
					return nil
				},
			},
			{
				// The one in-place update that only records what Key Vault cannot report.
				PreConfig:       markNow(&mark),
				ConfigVariables: acmeVariables(),
				Config:          f.config(matching),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(certAddr, plancheck.ResourceActionUpdate),
					attributeUnchanged{certAddr, "key_vault_url"},
					onlyKnown("version"), onlyKnown("issued_version"), onlyKnown("certificate_pem"),
					onlyKnown("not_after"), onlyKnown("thumbprint"),
				}},
				Check: resource.ComposeTestCheckFunc(
					noWritesSince(&mark),
					func(s *terraform.State) error {
						a, err := certAttrs(s)
						if err != nil {
							return err
						}
						id, secretID = a["id"], a["secret_id"]
						if a["version"] != imported || a["issued_version"] != imported {
							return fmt.Errorf("the imported version changed: %s / %s, want %s", a["version"], a["issued_version"], imported)
						}
						return nil
					},
				),
			},
			{ConfigVariables: acmeVariables(), Config: f.config(matching), PlanOnly: true},
			{
				// A renewal: a new version of the same certificate under this resource's policy.
				PreConfig:       func() { acc.ACME.SetValidity(365 * 24 * time.Hour) },
				ConfigVariables: acmeVariables(),
				Config:          f.config(due),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(certAddr, plancheck.ResourceActionUpdate),
					plancheck.ExpectUnknownValue(certAddr, tfjsonpath.New("version")),
				}},
				Check: func(s *terraform.State) error {
					a, err := certAttrs(s)
					if err != nil {
						return err
					}
					if a["id"] != id || a["secret_id"] != secretID {
						return fmt.Errorf("the IDs changed")
					}
					if n := vaultVersions(f.Cert); n != 2 {
						return fmt.Errorf("%d issued versions, want the imported one and a new one", n)
					}
					if a["version"] == imported || a["version"] != a["issued_version"] {
						return fmt.Errorf("version %s, issued %s, imported %s", a["version"], a["issued_version"], imported)
					}
					der := acc.KeyVault.LeafDER(f.Cert, "")
					sum := sha1.Sum(der) //nolint:gosec // see the import
					if strings.ToUpper(hex.EncodeToString(sum[:])) != a["thumbprint"] {
						return fmt.Errorf("the versionless certificate is not the new version")
					}
					leaf, _ := x509.ParseCertificate(der)
					if leaf.Issuer.CommonName != "Test ACME Intermediate" {
						return fmt.Errorf("the new certificate was issued by %q", leaf.Issuer.CommonName)
					}
					p := acc.KeyVault.Policy(f.Cert)
					if p.Issuer != "Unknown" || !p.Exportable || p.KTY != "RSA" || p.KeySize != 2048 || len(p.LifetimeActions) != 0 {
						return fmt.Errorf("the policy was not replaced: %+v", p)
					}
					return nil
				},
			},
			{ConfigVariables: acmeVariables(), Config: f.config(due), PlanOnly: true},
		},
	})
}

func TestAccACMECertificate_importRefused(t *testing.T) {
	accPreCheck(t)
	base := func() keyvaultfake.ImportOptions {
		return keyvaultfake.ImportOptions{
			Issuer: "OtherCA", Key: "RSA2048", CommonName: "example.com", DNSNames: []string{"example.com"},
		}
	}
	type refusal struct {
		prepare func(name string)
		want    string
	}
	with := func(edit func(*keyvaultfake.ImportOptions)) func(string) {
		return func(name string) {
			o := base()
			edit(&o)
			if _, err := acc.KeyVault.ImportCertificate(name, o); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := map[string]refusal{
		"no names at all": {with(func(o *keyvaultfake.ImportOptions) { o.CommonName, o.DNSNames = "", nil }),
			`neither\s+a\s+subject\s+common\s+name\s+nor\s+a\s+DNS\s+name`},
		"common name not among names": {with(func(o *keyvaultfake.ImportOptions) { o.DNSNames = []string{"www.example.com"} }),
			`not\s+among\s+the\s+certificate's\s+DNS\s+names`},
		"ip address": {with(func(o *keyvaultfake.ImportOptions) { o.IPAddresses = ipList("192.0.2.1") }), `not\s+a\s+DNS\s+name`},
		"rsa 1024":   {with(func(o *keyvaultfake.ImportOptions) { o.Key = "RSA1024" }), `RSA\s+1024`},
		"ec p224":    {with(func(o *keyvaultfake.ImportOptions) { o.Key = "P224" }), `EC\s+P-224`},
		"only a pending operation": {func(name string) { acc.KeyVault.AddPendingOperation(name, "OtherCA") },
			`no\s+issued\s+version`},
		"does not exist": {func(string) {}, `was\s+not\s+found`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newACMEFixture(t, "P256")
			var mark acctest.Mark
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: newTestProviderFactories(),
				Steps: []resource.TestStep{
					{ConfigVariables: acmeVariables(), Config: registrationOnly(f)},
					{
						PreConfig:          func() { c.prepare(f.Cert); mark = acc.Mark() },
						ConfigVariables:    acmeVariables(),
						Config:             f.config(certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}),
						ResourceName:       certAddr,
						ImportState:        true,
						ImportStatePersist: true,
						ImportStateId:      importID(f.Cert),
						ExpectError:        regexp.MustCompile(`(?s)Cannot\s+import.*` + c.want),
					},
					{
						PreConfig: func() {
							if w := acc.WritesSince(mark); len(w) > 0 {
								t.Errorf("a refused import wrote: %v", w)
							}
							if v := acc.KeyVault.Violations(); len(v) > 0 {
								t.Errorf("forbidden requests: %v", v)
							}
						},
						ConfigVariables: acmeVariables(),
						Config:          registrationOnly(f),
					},
				},
			})
		})
	}
}

func TestAccACMECertificate_importThenOrder(t *testing.T) {
	accPreCheck(t)
	importStep := func(t *testing.T, f acmeFixture, tweaks certOptions, o keyvaultfake.ImportOptions, version *string) resource.TestStep {
		return resource.TestStep{
			PreConfig:          existingCert(t, f, o, version),
			ConfigVariables:    acmeVariables(),
			Config:             f.config(tweaks),
			ResourceName:       certAddr,
			ImportState:        true,
			ImportStatePersist: true,
			ImportStateId:      importID(f.Cert),
		}
	}
	orders := resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
		plancheck.ExpectResourceAction(certAddr, plancheck.ResourceActionUpdate),
		plancheck.ExpectUnknownValue(certAddr, tfjsonpath.New("version")),
	}}
	opts := func() keyvaultfake.ImportOptions {
		return keyvaultfake.ImportOptions{
			Issuer: "OtherCA", Key: "RSA2048", CommonName: "example.com", DNSNames: []string{"example.com", "*.example.com"},
			Validity: 90 * 24 * time.Hour,
		}
	}

	t.Run("another key type orders", func(t *testing.T) {
		f := newACMEFixture(t, "P256")
		var v string
		tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly, KeyType: "RSA4096"}
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{
				{ConfigVariables: acmeVariables(), Config: registrationOnly(f)},
				importStep(t, f, tweaks, opts(), &v),
				{
					ConfigVariables: acmeVariables(), Config: f.config(tweaks), ConfigPlanChecks: orders,
					Check: func(*terraform.State) error {
						if p := acc.KeyVault.Policy(f.Cert); p.KeySize != 4096 || vaultVersions(f.Cert) != 2 {
							return fmt.Errorf("policy %+v, versions %d", p, vaultVersions(f.Cert))
						}
						leaf, err := leafOf(f.Cert)
						if err != nil {
							return err
						}
						if got := keyTypeOfCert(leaf); got != "RSA4096" {
							return fmt.Errorf("the new certificate's key is %s", got)
						}
						return nil
					},
				},
			},
		})
	})

	t.Run("a certificate close to expiry orders", func(t *testing.T) {
		f := newACMEFixture(t, "P256")
		var v string
		o := opts()
		o.Validity = 10 * 24 * time.Hour
		tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{
				{ConfigVariables: acmeVariables(), Config: registrationOnly(f)},
				importStep(t, f, tweaks, o, &v),
				{
					ConfigVariables: acmeVariables(), Config: f.config(tweaks), ConfigPlanChecks: orders,
					Check: func(*terraform.State) error {
						if vaultVersions(f.Cert) != 2 {
							return fmt.Errorf("%d issued versions, want 2", vaultVersions(f.Cert))
						}
						return nil
					},
				},
			},
		})
	})

	t.Run("a pending operation of another issuer fails the order", func(t *testing.T) {
		f := newACMEFixture(t, "P256")
		var v string
		tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly, KeyType: "P256"}
		var mark acctest.Mark
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{
				{ConfigVariables: acmeVariables(), Config: registrationOnly(f)},
				importStep(t, f, tweaks, opts(), &v),
				{
					PreConfig:       func() { acc.KeyVault.AddPendingOperation(f.Cert, "OtherCA"); mark = acc.Mark() },
					ConfigVariables: acmeVariables(), Config: f.config(tweaks),
					ExpectError: regexp.MustCompile(`OtherCA`),
				},
				{
					PreConfig: func() {
						if w := acc.WritesSince(mark); len(w) > 0 {
							t.Errorf("the failed order wrote: %v", w)
						}
					},
					ConfigVariables: acmeVariables(), Config: registrationOnly(f),
				},
			},
		})
	})
}

func TestAccACMECertificate_destroyAfterImport(t *testing.T) {
	accPreCheck(t)
	logFile := acctest.EnableTraceLogs(t, t.TempDir())
	var imported string
	t.Run("an imported certificate is not revoked", func(t *testing.T) {
		f := newACMEFixture(t, "P256")
		before := slices.Clone(acc.ACME.Revoked())
		matching := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			CheckDestroy: func(*terraform.State) error {
				if !slices.Equal(acc.ACME.Revoked(), before) {
					return fmt.Errorf("a certificate was revoked: %v", acc.ACME.Revoked())
				}
				if !acc.KeyVault.Deleted(f.Cert) {
					return fmt.Errorf("the certificate was not deleted")
				}
				return nil
			},
			Steps: []resource.TestStep{
				{ConfigVariables: acmeVariables(), Config: registrationOnly(f)},
				{
					PreConfig:       existingCert(t, f, existingOptions(), &imported),
					ConfigVariables: acmeVariables(), Config: f.config(matching),
					ResourceName: certAddr, ImportState: true, ImportStatePersist: true, ImportStateId: importID(f.Cert),
				},
				{ConfigVariables: acmeVariables(), Config: f.config(matching)},
			},
		})
	})
	acctest.AssertLogContains(t, logFile, "Version "+imported+" of the certificate was issued elsewhere")

	t.Run("a renewed certificate is revoked", func(t *testing.T) {
		f := newACMEFixture(t, "P256")
		var serial string
		var v string
		renew := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly, MinDays: 100}
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			CheckDestroy: func(*terraform.State) error {
				if !slices.Contains(acc.ACME.Revoked(), serial) {
					return fmt.Errorf("the renewed certificate (serial %s) was not revoked", serial)
				}
				return nil
			},
			Steps: []resource.TestStep{
				{ConfigVariables: acmeVariables(), Config: registrationOnly(f)},
				{
					PreConfig:       existingCert(t, f, existingOptions(), &v),
					ConfigVariables: acmeVariables(), Config: f.config(renew),
					ResourceName: certAddr, ImportState: true, ImportStatePersist: true, ImportStateId: importID(f.Cert),
				},
				{
					PreConfig:       func() { acc.ACME.SetValidity(365 * 24 * time.Hour) },
					ConfigVariables: acmeVariables(), Config: f.config(renew),
					Check: func(s *terraform.State) (err error) { serial, err = serialOf(s); return err },
				},
			},
		})
	})
}

// After an import, either spelling of the vault URL leaves key_vault_url unchanged.
func TestAccACMECertificate_importVaultURLSpellings(t *testing.T) {
	accPreCheck(t)
	for name, spell := range map[string]func(string) string{
		"without a slash": func(u string) string { return u },
		"with a slash":    func(u string) string { return u + "/" },
		"host in capitals": func(u string) string {
			return strings.Replace(u, "fake.vault.azure.net", "FAKE.Vault.AZURE.net", 1) + "/"
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newACMEFixture(t, "P256")
			var imported string
			tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly, VaultURL: spell(acc.KeyVault.URL)}
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: newTestProviderFactories(),
				Steps: []resource.TestStep{
					{ConfigVariables: acmeVariables(), Config: registrationOnly(f)},
					{
						PreConfig:       existingCert(t, f, existingOptions(), &imported),
						ConfigVariables: acmeVariables(), Config: f.config(tweaks),
						ResourceName: certAddr, ImportState: true, ImportStatePersist: true, ImportStateId: importID(f.Cert),
					},
					{
						ConfigVariables: acmeVariables(), Config: f.config(tweaks),
						ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
							attributeUnchanged{certAddr, "key_vault_url"},
						}},
					},
					{ConfigVariables: acmeVariables(), Config: f.config(tweaks), PlanOnly: true},
				},
			})
		})
	}
}

// A certificate without a subject common name can be imported: common_name is null after
// the import, and a configuration whose common name and alternative names make up the
// certificate's DNS names is a state-only update.
func TestAccACMECertificate_importWithoutCommonName(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	matching := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	other := certOptions{SANs: []string{"*.example.com", "www.example.com"}, Blocks: cloudflareOnly}
	forget := acmeProviderConfig() + f.registrationHCL(`email = "certificates@example.com"`) + `
removed {
  from = conative_acme_certificate.c
  lifecycle {
    destroy = false
  }
}
`
	var mark acctest.Mark
	var version string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				PreConfig:       func() { acc.ACME.OmitCommonName(true) },
				ConfigVariables: acmeVariables(), Config: f.config(matching),
				Check: func(s *terraform.State) error {
					a, err := certAttrs(s)
					version = a["version"]
					return err
				},
			},
			{ConfigVariables: acmeVariables(), Config: forget}, // state rm
			{
				PreConfig:       markNow(&mark),
				ConfigVariables: acmeVariables(), Config: f.config(matching),
				ResourceName: certAddr, ImportState: true, ImportStatePersist: true, ImportStateId: importID(f.Cert),
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					for _, st := range states {
						if st.Attributes["certificate_name"] != f.Cert {
							continue
						}
						if v, ok := st.Attributes["common_name"]; ok {
							return fmt.Errorf("common_name must be null after the import, got %q", v)
						}
						if st.Attributes["subject_alternative_names.#"] != "2" {
							return fmt.Errorf("the alternative names are %q, want both DNS names", st.Attributes["subject_alternative_names.#"])
						}
						if st.Attributes["version"] != version {
							return fmt.Errorf("the imported version is %s, want %s", st.Attributes["version"], version)
						}
						return nil
					}
					return fmt.Errorf("the certificate is not among the imported states")
				},
			},
			{
				// The names match as one set: a state-only update that writes nothing.
				PreConfig:       markNow(&mark),
				ConfigVariables: acmeVariables(), Config: f.config(matching),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(certAddr, plancheck.ResourceActionUpdate),
					plancheck.ExpectKnownValue(certAddr, tfjsonpath.New("version"), knownvalue.NotNull()),
				}},
				Check: resource.ComposeTestCheckFunc(
					noWritesSince(&mark),
					func(s *terraform.State) error {
						a, err := certAttrs(s)
						if err == nil && a["version"] != version {
							err = fmt.Errorf("version %s, want the imported %s", a["version"], version)
						}
						return err
					},
					resource.TestCheckResourceAttr(certAddr, "common_name", "example.com"),
					resource.TestCheckResourceAttr(certAddr, "subject_alternative_names.#", "1"),
				),
			},
			{ConfigVariables: acmeVariables(), Config: f.config(matching), PlanOnly: true},
			{
				// Other names are a change that orders a new version.
				ConfigVariables: acmeVariables(), Config: f.config(other),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectUnknownValue(certAddr, tfjsonpath.New("version")),
				}},
			},
		},
	})
}
