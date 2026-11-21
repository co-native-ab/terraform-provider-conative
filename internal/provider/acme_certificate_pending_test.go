package provider

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
)

// Key Vault keeps the pending-operation record after an operation completes. Only an
// operation in progress blocks an order.
func TestAccACMECertificate_completedOperationDoesNotBlock(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	update := resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
		plancheck.ExpectResourceAction(certAddr, plancheck.ResourceActionUpdate),
	}}
	var mark acctest.Mark
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				ConfigVariables: acmeVariables(), Config: f.config(tweaks),
				Check: func(*terraform.State) error {
					// The record of the provider's own merge is kept, as Key Vault does.
					if issuer, status, ok := acc.KeyVault.PendingRecord(f.Cert); !ok || issuer != "Unknown" || status != "completed" {
						return fmt.Errorf("pending record: %q %q %v", issuer, status, ok)
					}
					return nil
				},
			},
			{
				// A version made outside Terraform with the Self issuer: the plan sees the drift
				// and plans an in-place renewal instead of failing.
				PreConfig: func() {
					if _, err := acc.KeyVault.AddSelfIssuedVersion(f.Cert); err != nil {
						t.Fatal(err)
					}
					if issuer, status, ok := acc.KeyVault.PendingRecord(f.Cert); !ok || issuer != "Self" || status != "completed" {
						t.Fatalf("pending record: %q %q %v", issuer, status, ok)
					}
					mark = acc.Mark()
				},
				ConfigVariables: acmeVariables(), Config: f.config(tweaks), PlanOnly: true, ExpectNonEmptyPlan: true,
			},
			{
				PreConfig:       func() { requireNoWrites(t, &mark)() },
				ConfigVariables: acmeVariables(), Config: f.config(tweaks), ConfigPlanChecks: update,
				Check: func(*terraform.State) error {
					if n := vaultVersions(f.Cert); n != 3 {
						return fmt.Errorf("%d issued versions, want 3", n)
					}
					if p := acc.KeyVault.Policy(f.Cert); p.Issuer != "Unknown" {
						return fmt.Errorf("the policy issuer is %q", p.Issuer)
					}
					return nil
				},
			},
			{ConfigVariables: acmeVariables(), Config: f.config(tweaks), PlanOnly: true},
		},
	})
}

func TestAccACMECertificate_importSelfIssuedThenRenew(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	var imported string
	opts := existingOptions()
	opts.Issuer = "Self"
	matching := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	due := matching
	due.MinDays = 100
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: registrationOnly(f)},
			{
				PreConfig: func() {
					existingCert(t, f, opts, &imported)()
					if issuer, status, ok := acc.KeyVault.PendingRecord(f.Cert); !ok || issuer != "Self" || status != "completed" {
						t.Fatalf("pending record: %q %q %v", issuer, status, ok)
					}
				},
				ConfigVariables: acmeVariables(), Config: f.config(matching),
				ResourceName: certAddr, ImportState: true, ImportStatePersist: true, ImportStateId: importID(f.Cert),
			},
			{ConfigVariables: acmeVariables(), Config: f.config(matching)},
			{ConfigVariables: acmeVariables(), Config: f.config(matching), PlanOnly: true},
			{
				// The record of the Self operation does not stop a renewal.
				PreConfig:       func() { acc.ACME.SetValidity(365 * 24 * time.Hour) },
				ConfigVariables: acmeVariables(), Config: f.config(due),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(certAddr, plancheck.ResourceActionUpdate),
				}},
				Check: func(*terraform.State) error {
					if n := vaultVersions(f.Cert); n != 2 {
						return fmt.Errorf("%d issued versions, want 2", n)
					}
					return nil
				},
			},
			{ConfigVariables: acmeVariables(), Config: f.config(due), PlanOnly: true},
		},
	})
}

// An authority that never reports contacts (Let's Encrypt) must keep a refresh and a
// refresh-only plan empty, after a create and after an import followed by an apply.
func TestAccACMERegistration_refreshWithoutContacts(t *testing.T) {
	accPreCheck(t)
	setupDNS(t)
	keyID := acc.KeyVault.AddKey(uniqueName("acct"), "P256", true)
	server := acc.ACME.DirectoryURL()
	cfg := registrationConfig(server, keyID, `email = "a@example.com"`)
	const addr = "conative_acme_registration.r"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				PreConfig:       func() { acc.ACME.OmitContact(true) },
				ConfigVariables: acmeVariables(), Config: cfg,
				Check: resource.TestCheckResourceAttr(addr, "email", "a@example.com"),
			},
			{
				// A refresh-only plan after the create.
				ConfigVariables: acmeVariables(), RefreshState: true,
				Check: resource.TestCheckResourceAttr(addr, "email", "a@example.com"),
			},
			{
				// Dropping the resource only forgets it: the account stays at the authority.
				ConfigVariables: acmeVariables(), Config: acmeProviderConfig(),
			},
			{
				// Import, then the first apply records the address, then refresh again.
				ConfigVariables: acmeVariables(), Config: cfg, ResourceName: addr,
				ImportState: true, ImportStatePersist: true, ImportStateId: server + "|" + keyID,
			},
			{
				ConfigVariables: acmeVariables(), Config: cfg,
				Check: resource.TestCheckResourceAttr(addr, "email", "a@example.com"),
			},
			{
				ConfigVariables: acmeVariables(), RefreshState: true,
				Check: resource.TestCheckResourceAttr(addr, "email", "a@example.com"),
			},
			{ConfigVariables: acmeVariables(), Config: cfg, PlanOnly: true},
		},
	})
}
