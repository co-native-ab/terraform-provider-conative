package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
)

func registrationConfig(server, keyID, extra string) string {
	return acmeProviderConfig() + fmt.Sprintf(`
resource "conative_acme_registration" "r" {
  server_url     = %q
  account_key_id = %q
  %s
}
`, server, keyID, extra)
}

func accountCount() int { return len(acc.ACME.Accounts()) }

func TestAccACMERegistration_createReuseUpdateImport(t *testing.T) {
	accPreCheck(t)
	for _, kind := range []string{"RSA2048", "P256"} {
		t.Run(kind, func(t *testing.T) {
			setupDNS(t)
			keyName := uniqueName("acct")
			keyID := acc.KeyVault.AddKey(keyName, kind, true)
			server := acc.ACME.DirectoryURL()
			var before int
			var mark acctest.Mark

			// A key that already has an account at the authority.
			preKeyID := acc.KeyVault.AddKey(uniqueName("acct"), kind, true)

			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: newTestProviderFactories(),
				Steps: []resource.TestStep{
					{
						PreConfig:       func() { before = accountCount() },
						ConfigVariables: acmeVariables(),
						Config:          registrationConfig(server, keyID, `email = "a@example.com"`),
						Check: resource.ComposeTestCheckFunc(
							func(*terraform.State) error {
								if got := accountCount(); got != before+1 {
									return fmt.Errorf("accounts: got %d, want %d", got, before+1)
								}
								return nil
							},
							resource.TestCheckResourceAttr("conative_acme_registration.r", "id", server+"|"+keyID),
							resource.TestMatchResourceAttr("conative_acme_registration.r", "account_url", regexp.MustCompile(`/acme/acct/`)),
							resource.TestCheckResourceAttr("conative_acme_registration.r", "email", "a@example.com"),
						),
					},
					{
						// The contact is updated in place at the authority.
						ConfigVariables: acmeVariables(),
						Config:          registrationConfig(server, keyID, `email = "b@example.com"`),
						ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("conative_acme_registration.r", plancheck.ResourceActionUpdate),
						}},
						Check: func(*terraform.State) error {
							for _, a := range acc.ACME.Accounts() {
								if len(a.Contact) == 1 && a.Contact[0] == "mailto:b@example.com" {
									return nil
								}
							}
							return fmt.Errorf("no account has the contact b@example.com: %v", acc.ACME.Accounts())
						},
					},
					{
						// Removing the email only stops managing it: no request at all.
						PreConfig:       func() { mark = acc.Mark() },
						ConfigVariables: acmeVariables(),
						Config:          registrationConfig(server, keyID, ``),
						Check: resource.ComposeTestCheckFunc(
							noWritesSince(&mark),
							func(*terraform.State) error {
								if n := len(acc.ACME.Journal.WritesSince(mark.ACMEPosition())); n != 0 {
									return fmt.Errorf("%d writes at the authority", n)
								}
								return nil
							},
						),
					},
					{
						ConfigVariables:   acmeVariables(),
						Config:            registrationConfig(server, keyID, ``),
						ResourceName:      "conative_acme_registration.r",
						ImportState:       true,
						ImportStateVerify: true,
					},
					{
						// A second resource on a key that already has an account reuses it.
						PreConfig: func() {
							// Register the key outside the provider by applying a first resource below.
							before = accountCount()
						},
						ConfigVariables: acmeVariables(),
						Config:          registrationConfig(server, keyID, ``) + secondRegistration(server, preKeyID),
						Check: func(*terraform.State) error {
							if got := accountCount(); got != before+1 {
								return fmt.Errorf("accounts: got %d, want %d (one for the new key)", got, before+1)
							}
							return nil
						},
					},
					{
						ConfigVariables: acmeVariables(),
						Config:          registrationConfig(server, keyID, ``),
						Check: func(*terraform.State) error {
							// Destroying a registration leaves the account at the authority.
							if got := accountCount(); got < before+1 {
								return fmt.Errorf("an account was removed: %d", got)
							}
							return nil
						},
					},
				},
			})
		})
	}
}

func secondRegistration(server, keyID string) string {
	return fmt.Sprintf(`
resource "conative_acme_registration" "second" {
  server_url     = %q
  account_key_id = %q
}
`, server, keyID)
}

func TestAccACMERegistration_reusesExistingAccount(t *testing.T) {
	accPreCheck(t)
	setupDNS(t)
	keyID := acc.KeyVault.AddKey(uniqueName("acct"), "P256", true)
	server := acc.ACME.DirectoryURL()
	var before int

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				ConfigVariables: acmeVariables(),
				Config:          registrationConfig(server, keyID, ``),
			},
			{
				// Same key, second resource: the existing account is found, none is created.
				PreConfig:       func() { before = accountCount() },
				ConfigVariables: acmeVariables(),
				Config:          registrationConfig(server, keyID, ``) + secondRegistration(server, keyID),
				Check: resource.ComposeTestCheckFunc(
					func(*terraform.State) error {
						if got := accountCount(); got != before {
							return fmt.Errorf("accounts: got %d, want %d", got, before)
						}
						return nil
					},
					resource.TestCheckResourceAttrPair("conative_acme_registration.r", "account_url", "conative_acme_registration.second", "account_url"),
				),
			},
		},
	})
}

func TestAccACMERegistration_versionlessKeyRejected(t *testing.T) {
	accPreCheck(t)
	setupDNS(t)
	keyID := acc.KeyVault.AddKey(uniqueName("acct"), "P256", true)
	versionless := keyID[:strings.LastIndex(keyID, "/")]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{{
			ConfigVariables: acmeVariables(),
			Config:          registrationConfig(acc.ACME.DirectoryURL(), versionless, ``),
			PlanOnly:        true,
			ExpectError:     regexp.MustCompile(`(?s)no version.*azurerm_key_vault_key`),
		}},
	})
}

func TestAccACMERegistration_unsupportedKeyRejected(t *testing.T) {
	accPreCheck(t)
	setupDNS(t)
	for _, kind := range []string{"RSA1024", "P256K"} {
		keyID := acc.KeyVault.AddKey(uniqueName("acct"), kind, true)
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{{
				ConfigVariables: acmeVariables(),
				Config:          registrationConfig(acc.ACME.DirectoryURL(), keyID, ``),
				ExpectError:     regexp.MustCompile(`(?s)not\s+accepted`),
			}},
		})
	}
}

func TestAccACMERegistration_readFailureKeepsState(t *testing.T) {
	accPreCheck(t)
	setupDNS(t)
	keyID := acc.KeyVault.AddKey(uniqueName("acct"), "P256", true)
	cfg := registrationConfig(acc.ACME.DirectoryURL(), keyID, ``)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: cfg},
			{
				PreConfig:       func() { acc.KeyVault.SetFailure(503) },
				ConfigVariables: acmeVariables(),
				Config:          cfg,
				PlanOnly:        true,
				ExpectError:     regexp.MustCompile(`(?s)Key\s+Vault\s+answered\s+503`),
			},
			{
				PreConfig:       func() { acc.KeyVault.SetFailure(0) },
				ConfigVariables: acmeVariables(),
				Config:          cfg,
				PlanOnly:        true,
			},
		},
	})
}
