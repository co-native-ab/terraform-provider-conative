package provider

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/config"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
)

// noCloudflareToken is the Cloudflare block of a configuration that does not pass a token,
// as a plan without write rights does.
const noCloudflareToken = `
  cloudflare {
    zone          = "example.com"
    match_domains = ["example.com"]
  }

  azure_dns {
    subscription_id = "00000000-0000-0000-0000-000000000000"
    resource_group  = "dns"
    zone_name       = "example.net"
    match_domains   = ["apps.example.net"]
  }
`

// providerWithoutARM is the provider block without a Resource Manager token.
func providerWithoutARM() string {
	return strings.Replace(acmeProviderConfig(), "resource_manager_access_token = var.arm_token", "", 1)
}

func withCloudflareToken(token string) config.Variables {
	v := acmeVariables()
	v["cf_token"] = config.StringVariable(token)
	return v
}

// requireReadOnlyTraffic fails when, since the mark, anything was written, a key signed,
// a secret was requested, or a certificate authority, DNS service or Cloudflare was
// contacted at all.
func requireReadOnlyTraffic(t *testing.T, m *acctest.Mark) func() {
	return func() {
		t.Helper()
		if w := acc.WritesSince(*m); len(w) > 0 {
			t.Errorf("writes: %v", w)
		}
		for _, r := range acc.RequestsSince(*m) {
			if strings.Contains(r, "/sign") || strings.Contains(r, "/secrets") || strings.HasPrefix(r, "acme ") ||
				strings.HasPrefix(r, "azuredns ") || strings.HasPrefix(r, "cloudflare ") {
				t.Errorf("a read-only run made the request %s", r)
			}
		}
		if v := acc.KeyVault.Violations(); len(v) > 0 {
			t.Errorf("forbidden Key Vault requests: %v", v)
		}
	}
}

// Refreshing and planning need only read rights in Key Vault and no DNS tokens when nothing
// is ordered.
func TestAccACMECertificate_readOnlyPlanAndRefresh(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	full := f.config(certOptions{})
	var mark acctest.Mark
	readerCfg := providerWithoutARM() + f.registrationHCL(`email = "certificates@example.com"`) + f.certHCL(certOptions{Blocks: noCloudflareToken})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: full},
			{
				PreConfig: func() {
					acc.KeyVault.SetReader(true)
					mark = acc.Mark()
				},
				ConfigVariables: acmeVariables(), Config: readerCfg,
				PlanOnly: true,
			},
			{
				PreConfig: func() {
					requireReadOnlyTraffic(t, &mark)()
					acc.KeyVault.SetReader(false)
				},
				ConfigVariables: acmeVariables(), Config: full,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
			},
		},
	})
}

func TestAccACMERegistration_readOnlyPlanAndRefresh(t *testing.T) {
	accPreCheck(t)
	setupDNS(t)
	keyID := acc.KeyVault.AddKey(uniqueName("acct"), "P256", true)
	cfg := registrationConfig(acc.ACME.DirectoryURL(), keyID, `email = "a@example.com"`)
	reader := strings.Replace(cfg, "resource_manager_access_token = var.arm_token", "", 1)
	var mark acctest.Mark
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: cfg},
			{
				PreConfig:       func() { acc.KeyVault.SetReader(true); mark = acc.Mark() },
				ConfigVariables: acmeVariables(), Config: reader, PlanOnly: true,
			},
			{
				// A key that Key Vault confirms is gone removes the registration from the state.
				PreConfig: func() {
					requireReadOnlyTraffic(t, &mark)()
					acc.KeyVault.SetReader(false)
				},
				ConfigVariables: acmeVariables(), Config: cfg, PlanOnly: true,
			},
		},
	})
}

// A plan in which an order is due needs the DNS tokens of the blocks that serve the names:
// without one the plan fails and names the attribute.
func TestAccACMECertificate_orderDueNeedsTokens(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	full := f.config(certOptions{})
	var mark acctest.Mark
	t.Run("cloudflare", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{
				{ConfigVariables: acmeVariables(), Config: full},
				{
					PreConfig:       func() { acc.ACME.SetValidity(365 * 24 * time.Hour); mark = acc.Mark() },
					ConfigVariables: acmeVariables(),
					Config:          providerWithoutARM() + f.registrationHCL(`email = "certificates@example.com"`) + f.certHCL(certOptions{MinDays: 100, Blocks: noCloudflareToken}),
					PlanOnly:        true,
					ExpectError:     regexp.MustCompile(`(?s)api_token.*cloudflare\[0\]|cloudflare\[0\].*api_token`),
				},
				{
					PreConfig:       requireNoWrites(t, &mark),
					ConfigVariables: acmeVariables(), Config: full, PlanOnly: true,
				},
			},
		})
	})
	t.Run("azure", func(t *testing.T) {
		g := newACMEFixture(t, "P256")
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{
				{
					ConfigVariables: acmeVariables(),
					Config:          providerWithoutARM() + g.registrationHCL("") + g.certHCL(certOptions{}),
					PlanOnly:        true,
					ExpectError:     regexp.MustCompile(`(?s)resource_manager_access_token.*azure_dns\[0\]|azure_dns\[0\].*resource_manager_access_token`),
				},
			},
		})
	})
}

// With a token that can only read Cloudflare, a plan passes even when an order is due; an
// apply fails cleanly at the first write, and the old certificate stays.
func TestAccACMECertificate_readOnlyCloudflareToken(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	full := f.config(certOptions{})
	renew := f.config(certOptions{MinDays: 100})
	readOnly := withCloudflareToken(acc.CloudflareReadOnlyToken)
	var mark acctest.Mark
	failed := regexp.MustCompile(`(?s)cloudflare\[0\].*example\.com`)

	cleanState := func() {
		if all := acc.DNS.All(); len(all) != 0 {
			t.Errorf("challenge records are left behind: %v", all)
		}
		if slices.Contains(acc.KeyVault.PendingOperations(), f.Cert) {
			t.Error("a pending operation is left")
		}
		if n := vaultVersions(f.Cert); n != 1 {
			t.Errorf("%d issued versions, want 1", n)
		}
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: full},
			{
				PreConfig:       func() { acc.ACME.SetValidity(365 * 24 * time.Hour); mark = acc.Mark() },
				ConfigVariables: readOnly, Config: renew,
				PlanOnly: true, ExpectNonEmptyPlan: true,
			},
			{
				PreConfig: func() {
					requireNoWrites(t, &mark)()
					// Make the order validate again, as it does once authorizations have expired.
					acc.ACME.ExpireAuthorizations()
				},
				ConfigVariables: readOnly, Config: renew,
				ExpectError: failed,
			},
			{
				PreConfig:       cleanState,
				ConfigVariables: acmeVariables(), Config: renew,
				Check: func(*terraform.State) error {
					if n := vaultVersions(f.Cert); n != 2 {
						return fmt.Errorf("%d issued versions after the renewal, want 2", n)
					}
					return nil
				},
			},
		},
	})
}

func TestAccACMECertificate_createWithReadOnlyCloudflareToken(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				ConfigVariables: withCloudflareToken(acc.CloudflareReadOnlyToken), Config: f.config(certOptions{}),
				ExpectError: regexp.MustCompile(`(?s)cloudflare\[0\].*example\.com`),
			},
			{
				PreConfig: func() {
					if all := acc.DNS.All(); len(all) != 0 {
						t.Errorf("challenge records are left behind: %v", all)
					}
					if acc.KeyVault.Exists(f.Cert) && (len(acc.KeyVault.PendingOperations()) != 0 || vaultVersions(f.Cert) != 0) {
						t.Error("the failed create left something in Key Vault")
					}
				},
				ConfigVariables: acmeVariables(), Config: f.config(certOptions{}),
			},
		},
	})
}

// An authority that reports no contacts (Let's Encrypt) must not make the provider send
// the address again.
func TestAccACMERegistration_authorityWithoutContacts(t *testing.T) {
	accPreCheck(t)
	setupDNS(t)
	keyID := acc.KeyVault.AddKey(uniqueName("acct"), "P256", true)
	server := acc.ACME.DirectoryURL()
	cfg := registrationConfig(server, keyID, `email = "a@example.com"`)
	var mark acctest.Mark
	acctPosts := func() {
		for _, r := range acc.RequestsSince(mark) {
			if strings.HasPrefix(r, "acme POST /acme/acct/") {
				t.Errorf("an account update was sent: %s", r)
			}
		}
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				PreConfig:       func() { acc.ACME.OmitContact(true); mark = acc.Mark() },
				ConfigVariables: acmeVariables(), Config: cfg,
				Check: resource.TestCheckResourceAttr("conative_acme_registration.r", "email", "a@example.com"),
			},
			{
				PreConfig:       func() { acctPosts(); mark = acc.Mark() },
				ConfigVariables: acmeVariables(), Config: cfg,
			},
			{
				// A second resource finds the account; with no contacts reported nothing is sent.
				PreConfig:       func() { acctPosts(); mark = acc.Mark() },
				ConfigVariables: acmeVariables(), Config: cfg + strings.Replace(secondRegistration(server, keyID), `account_key_id`, `email = "b@example.com"
  account_key_id`, 1),
			},
			{
				PreConfig:       acctPosts,
				ConfigVariables: acmeVariables(), Config: cfg,
			},
		},
	})
}

// A certificate authority may drop the common name from the certificate.
func TestAccACMECertificate_commonNameDroppedByAuthority(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	opts := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	var mark acctest.Mark
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				PreConfig:       func() { acc.ACME.OmitCommonName(true) },
				ConfigVariables: acmeVariables(), Config: f.config(opts),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(certAddr, "common_name", "example.com"),
					resource.TestCheckResourceAttr(certAddr, "subject_alternative_names.#", "1"),
					func(*terraform.State) error {
						leaf, err := leafOf(f.Cert)
						if err != nil {
							return err
						}
						if leaf.Subject.CommonName != "" {
							return fmt.Errorf("the certificate has the common name %q; the fake should have dropped it", leaf.Subject.CommonName)
						}
						return nil
					},
				),
			},
			{
				PreConfig:       markNow(&mark),
				ConfigVariables: acmeVariables(), Config: f.config(opts), PlanOnly: true,
			},
			{
				PreConfig:       func() { requireNoWrites(t, &mark)() },
				ConfigVariables: acmeVariables(), Config: f.config(opts),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
				Check: func(*terraform.State) error {
					if n := vaultVersions(f.Cert); n != 1 {
						return fmt.Errorf("%d versions, want 1", n)
					}
					return nil
				},
			},
		},
	})
}

func TestAccACMECertificate_commonNameTooLong(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{{
			ConfigVariables: acmeVariables(),
			Config:          f.config(certOptions{CN: strings.Repeat("a", 60) + ".example.com", SANs: []string{}, Blocks: cloudflareOnly}),
			PlanOnly:        true,
			ExpectError:     regexp.MustCompile(`(?s)at\s+most\s+64`),
		}},
	})
}

// Moving the registration to another certificate authority URL orders a new certificate;
// another account at the same URL, or the first value after an import, only updates the state.
func TestAccACMECertificate_authorityChangeOrders(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	otherKey := acc.KeyVault.AddKey(uniqueName("acct"), "P256", true)
	extra := fmt.Sprintf(`
resource "conative_acme_registration" "alt" {
  server_url     = %q
  account_key_id = %q
}

resource "conative_acme_registration" "alt_other_key" {
  server_url     = %q
  account_key_id = %q
}
`, acc.ACME.AlternateDirectoryURL(), f.KeyID, acc.ACME.AlternateDirectoryURL(), otherKey)
	opts := func(reg string) string {
		return acmeProviderConfig() + f.registrationHCL("") + extra + f.certHCL(certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly, Registrat: reg})
	}
	action := func(a plancheck.ResourceActionType) resource.ConfigPlanChecks {
		return resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(certAddr, a)}}
	}
	versions := func(want int) resource.TestCheckFunc {
		return func(*terraform.State) error {
			if n := vaultVersions(f.Cert); n != want {
				return fmt.Errorf("%d issued versions, want %d", n, want)
			}
			return nil
		}
	}
	var kvMark int
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: opts("conative_acme_registration.r.id"), Check: versions(1)},
			{
				ConfigVariables: acmeVariables(), Config: opts("conative_acme_registration.alt.id"),
				ConfigPlanChecks: action(plancheck.ResourceActionUpdate), Check: versions(2),
			},
			{
				PreConfig:       func() { kvMark = acc.KeyVault.Journal.Mark() },
				ConfigVariables: acmeVariables(), Config: opts("conative_acme_registration.alt_other_key.id"),
				ConfigPlanChecks: action(plancheck.ResourceActionUpdate),
				Check: resource.ComposeTestCheckFunc(versions(2), func(*terraform.State) error {
					if w := acc.KeyVault.Journal.WritesSince(kvMark); len(w) != 0 {
						return fmt.Errorf("a change of account at the same authority wrote to Key Vault: %v", w)
					}
					return nil
				}),
			},
		},
	})
}

// A failed renewal leaves the state as it was; a leftover pending version does not confuse
// refresh or the next order. A renewal soon after an issue reuses the authorizations that are
// still valid, and publishes records only for the names that need them.
func TestAccACMECertificate_failedRenewalAndAuthorizationReuse(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	opts := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	base := f.config(opts)
	renew := func(days int) string { o := opts; o.MinDays = days; return f.config(o) }
	var mark acctest.Mark
	cfWrites := func() int {
		return len(acc.Cloudflare.Journal.WritesSince(mark.CloudflarePosition()))
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: base},
			{
				PreConfig:       func() { acc.ACME.SetValidity(365 * 24 * time.Hour); acc.ACME.FailFinalize(true) },
				ConfigVariables: acmeVariables(), Config: renew(100),
				ExpectError: regexp.MustCompile(`(?s)cannot\s+finalize`),
			},
			{
				// A pending version is the latest one in Key Vault; refresh and plan read through it.
				PreConfig: func() {
					acc.ACME.ClearFailures()
					acc.ACME.SetValidity(365 * 24 * time.Hour)
					if n := vaultVersions(f.Cert); n != 1 {
						t.Errorf("%d issued versions after the failed renewal, want 1", n)
					}
					acc.KeyVault.AddPendingOperation(f.Cert, "Unknown")
				},
				ConfigVariables: acmeVariables(), Config: base, PlanOnly: true,
			},
			{
				// The authorizations are not known to the authority any more (they were created
				// by the failed order): this renewal validates every name and cleans up.
				ConfigVariables: acmeVariables(), Config: renew(100),
				Check: func(*terraform.State) error {
					if n := vaultVersions(f.Cert); n != 2 {
						return fmt.Errorf("%d issued versions, want 2", n)
					}
					return nil
				},
			},
			{
				// The authorizations of that order are still valid: no challenge record at all.
				PreConfig:       func() { acc.ACME.SetValidity(2000 * 24 * time.Hour); mark = acc.Mark() },
				ConfigVariables: acmeVariables(), Config: renew(400),
				Check: func(*terraform.State) error {
					if n := vaultVersions(f.Cert); n != 3 {
						return fmt.Errorf("%d issued versions, want 3", n)
					}
					if n := cfWrites(); n != 0 {
						return fmt.Errorf("%d Cloudflare writes although every authorization was valid", n)
					}
					if all := acc.DNS.All(); len(all) != 0 {
						return fmt.Errorf("records left: %v", all)
					}
					return nil
				},
			},
			{
				// One name needs validating again: only its value is published, and removed.
				PreConfig: func() {
					acc.ACME.SetValidity(4000 * 24 * time.Hour)
					acc.ACME.ForgetAuthorization("*.example.com")
					mark = acc.Mark()
				},
				ConfigVariables: acmeVariables(), Config: renew(3000),
				Check: func(*terraform.State) error {
					if n := vaultVersions(f.Cert); n != 4 {
						return fmt.Errorf("%d issued versions, want 4", n)
					}
					if n := cfWrites(); n != 2 {
						return fmt.Errorf("%d Cloudflare writes, want one create and one delete", n)
					}
					if all := acc.DNS.All(); len(all) != 0 {
						return fmt.Errorf("records left: %v", all)
					}
					return nil
				},
			},
		},
	})
}
