package provider

import (
	"crypto/sha1" //nolint:gosec // the thumbprint is a SHA-1 by definition
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// A configuration that creates a registration and, in the same run, imports or changes a
// certificate that references it cannot tell at plan time whether the certificate has to
// be ordered: registration_id is not known. The plan shows an in-place update with the
// attributes of the new version unknown, and apply decides.

// importBlock imports the certificate of the fixture from the fake vault.
func importBlock(f acmeFixture) string {
	return fmt.Sprintf(`
import {
  to = conative_acme_certificate.c
  id = %q
}
`, importID(f.Cert))
}

// unknownAtPlan are the checks of a plan that leaves the decision to apply.
func unknownAtPlan() resource.ConfigPlanChecks {
	checks := []plancheck.PlanCheck{plancheck.ExpectResourceAction(certAddr, plancheck.ResourceActionUpdate)}
	for _, a := range orderedComputed {
		checks = append(checks, plancheck.ExpectUnknownValue(certAddr, tfjsonpath.New(a)))
	}
	return resource.ConfigPlanChecks{PreApply: checks}
}

// orderRequestsSince lists the Key Vault requests since the mark that write anything or
// touch a pending operation: everything an order does that a plan or a state-only update
// does not. Signing is left out, because creating the registration of the same run signs
// too.
func orderRequestsSince(mark int) []string {
	var out []string
	for _, e := range acc.KeyVault.Journal.Since(mark) {
		if e.IsWrite || strings.Contains(e.Path, "/pending") {
			out = append(out, e.String())
		}
	}
	return out
}

// newOrdersSince counts the orders the certificate authority received since the mark.
func newOrdersSince(mark int) int {
	n := 0
	for _, e := range acc.ACME.Journal.Since(mark) {
		if strings.HasSuffix(e.Path, "/new-order") {
			n++
		}
	}
	return n
}

func thumbprintOf(name string) string {
	sum := sha1.Sum(acc.KeyVault.LeafDER(name, "")) //nolint:gosec // see the import
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func TestAccACMECertificate_importWithRegistrationInSameRun(t *testing.T) {
	accPreCheck(t)
	matching := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}

	t.Run("a certificate that is not due is only recorded", func(t *testing.T) {
		f := newACMEFixture(t, "P256")
		var imported string
		var kvMark, acmeMark, records, serials int
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{
				{
					PreConfig: func() {
						existingCert(t, f, existingOptions(), &imported)()
						kvMark = acc.KeyVault.Journal.Mark()
						acmeMark = acc.ACME.Journal.Mark()
						records = acc.Cloudflare.RecordCount("example.com")
						serials = len(acc.ACME.IssuedSerials())
					},
					ConfigVariables:  acmeVariables(),
					Config:           f.config(matching) + importBlock(f),
					ConfigPlanChecks: unknownAtPlan(),
					Check: resource.ComposeTestCheckFunc(
						func(*terraform.State) error {
							if r := orderRequestsSince(kvMark); len(r) != 0 {
								return fmt.Errorf("Key Vault saw requests of an order: %v", r)
							}
							if n := len(acc.ACME.IssuedSerials()); n != serials {
								return fmt.Errorf("the certificate authority issued %d certificates, want %d", n, serials)
							}
							if n := newOrdersSince(acmeMark); n != 0 {
								return fmt.Errorf("the certificate authority received %d orders, want none", n)
							}
							if n := acc.Cloudflare.RecordCount("example.com"); n != records {
								return fmt.Errorf("the zone holds %d records, want %d", n, records)
							}
							if n := vaultVersions(f.Cert); n != 1 {
								return fmt.Errorf("%d issued versions, want the imported one", n)
							}
							return nil
						},
						resource.TestCheckResourceAttrSet(certAddr, "registration_id"),
						resource.TestCheckResourceAttrPtr(certAddr, "version", &imported),
						resource.TestCheckResourceAttrPtr(certAddr, "issued_version", &imported),
						func(s *terraform.State) error {
							return resource.TestCheckResourceAttr(certAddr, "thumbprint", thumbprintOf(f.Cert))(s)
						},
					),
				},
				{
					ConfigVariables: acmeVariables(), Config: f.config(matching) + importBlock(f),
					ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
				},
			},
		})
	})

	t.Run("a certificate that is due is ordered", func(t *testing.T) {
		f := newACMEFixture(t, "P256")
		var imported string
		due := matching
		due.MinDays = 100
		var serials int
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{
				{
					PreConfig: func() {
						existingCert(t, f, existingOptions(), &imported)()
						acc.ACME.SetValidity(365 * 24 * time.Hour)
						serials = len(acc.ACME.IssuedSerials())
					},
					ConfigVariables:  acmeVariables(),
					Config:           f.config(due) + importBlock(f),
					ConfigPlanChecks: unknownAtPlan(),
					Check: func(s *terraform.State) error {
						a, err := certAttrs(s)
						if err != nil {
							return err
						}
						if n := len(acc.ACME.IssuedSerials()); n != serials+1 {
							return fmt.Errorf("the certificate authority issued %d certificates, want %d", n, serials+1)
						}
						if n := vaultVersions(f.Cert); n != 2 {
							return fmt.Errorf("%d issued versions, want the imported one and a new one", n)
						}
						if a["version"] == imported || a["version"] != a["issued_version"] || a["registration_id"] == "" {
							return fmt.Errorf("version %s, issued %s, imported %s, registration %q", a["version"], a["issued_version"], imported, a["registration_id"])
						}
						return nil
					},
				},
				{
					ConfigVariables: acmeVariables(), Config: f.config(due) + importBlock(f),
					ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
				},
			},
		})
	})
}

// registrationAt declares a registration at another directory URL of the same fake
// authority (a different server_url) or, when alternate is false, at the URL of the main
// registration with another account key. Either is created in the step that uses it, so
// the certificate's registration_id is not known at plan.
func registrationAt(f acmeFixture, name, keyID string, alternate bool) string {
	url := acc.ACME.DirectoryURL()
	if alternate {
		url = acc.ACME.AlternateDirectoryURL()
	}
	return fmt.Sprintf(`
resource "conative_acme_registration" %q {
  server_url     = %q
  account_key_id = %q
}
`, name, url, keyID)
}

func TestAccACMECertificate_registrationChangeDecidedAtApply(t *testing.T) {
	accPreCheck(t)
	opts := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}

	t.Run("another authority orders", func(t *testing.T) {
		f := newACMEFixture(t, "P256")
		next := opts
		next.Registrat = "conative_acme_registration.new.id"
		var firstSerials int
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{
				{ConfigVariables: acmeVariables(), Config: f.config(opts)},
				{
					PreConfig:        func() { firstSerials = len(acc.ACME.IssuedSerials()) },
					ConfigVariables:  acmeVariables(),
					Config:           f.config(next) + registrationAt(f, "new", f.KeyID, true),
					ConfigPlanChecks: unknownAtPlan(),
					Check: func(*terraform.State) error {
						if n := vaultVersions(f.Cert); n != 2 {
							return fmt.Errorf("%d issued versions, want 2", n)
						}
						if n := len(acc.ACME.IssuedSerials()); n != firstSerials+1 {
							return fmt.Errorf("the certificate authority issued %d certificates, want %d", n, firstSerials+1)
						}
						return nil
					},
				},
				{
					ConfigVariables: acmeVariables(), Config: f.config(next) + registrationAt(f, "new", f.KeyID, true),
					ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
				},
			},
		})
	})

	t.Run("another account at the same authority orders nothing", func(t *testing.T) {
		f := newACMEFixture(t, "P256")
		otherKey := acc.KeyVault.AddKey(uniqueName("acct"), "P256", true)
		next := opts
		next.Registrat = "conative_acme_registration.new.id"
		var kvMark, acmeMark, serials int
		var before map[string]string
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{
				{
					ConfigVariables: acmeVariables(), Config: f.config(opts),
					Check: func(s *terraform.State) (err error) { before, err = certAttrs(s); return err },
				},
				{
					PreConfig: func() {
						kvMark = acc.KeyVault.Journal.Mark()
						acmeMark = acc.ACME.Journal.Mark()
						serials = len(acc.ACME.IssuedSerials())
					},
					ConfigVariables:  acmeVariables(),
					Config:           f.config(next) + registrationAt(f, "new", otherKey, false),
					ConfigPlanChecks: unknownAtPlan(),
					Check: func(s *terraform.State) error {
						if r := orderRequestsSince(kvMark); len(r) != 0 {
							return fmt.Errorf("Key Vault saw requests of an order: %v", r)
						}
						if n := len(acc.ACME.IssuedSerials()); n != serials {
							return fmt.Errorf("the certificate authority issued %d certificates, want %d", n, serials)
						}
						if n := newOrdersSince(acmeMark); n != 0 {
							return fmt.Errorf("the certificate authority received %d orders, want none", n)
						}
						a, err := certAttrs(s)
						if err != nil {
							return err
						}
						for _, k := range []string{"version", "issued_version", "thumbprint", "not_after", "certificate_pem"} {
							if a[k] != before[k] {
								return fmt.Errorf("%s changed from %q to %q", k, before[k], a[k])
							}
						}
						if a["registration_id"] == before["registration_id"] {
							return fmt.Errorf("registration_id was not recorded")
						}
						return nil
					},
				},
				{
					ConfigVariables: acmeVariables(), Config: f.config(next) + registrationAt(f, "new", otherKey, false),
					ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
				},
			},
		})
	})
}
