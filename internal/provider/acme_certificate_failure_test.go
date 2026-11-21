package provider

import (
	"fmt"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// assertCleanup fails the test when an order left a record or a pending operation behind.
func assertCleanup(t *testing.T, cert string) func() {
	return func() {
		t.Helper()
		if all := acc.DNS.All(); len(all) != 0 {
			t.Errorf("challenge records are left behind: %v", all)
		}
		if slices.Contains(acc.KeyVault.PendingOperations(), cert) {
			t.Errorf("a pending operation is left on %s", cert)
		}
	}
}

func TestAccACMECertificate_failedValidationCleansUpAndRetries(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	tweaks := certOptions{}
	renew := certOptions{MinDays: 100}
	cleanup := assertCleanup(t, f.Cert)
	failed := regexp.MustCompile(`(?s)validation\s+of\s+\*\.apps\.example\.net\s+failed`)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				PreConfig:       func() { acc.ACME.FailValidation("*.apps.example.net") },
				ConfigVariables: acmeVariables(), Config: f.config(tweaks), ExpectError: failed,
			},
			{
				PreConfig: func() {
					cleanup()
					if acc.KeyVault.Exists(f.Cert) && vaultVersions(f.Cert) != 0 {
						t.Errorf("a failed create left an issued version")
					}
					acc.ACME.ClearFailures()
				},
				ConfigVariables: acmeVariables(), Config: f.config(tweaks),
				Check: dnsClean(),
			},
			{
				// A renewal that fails leaves the current version and the state as they were.
				PreConfig: func() {
					acc.ACME.SetValidity(365 * 24 * time.Hour)
					acc.ACME.ExpireAuthorizations()
					acc.ACME.FailValidation("*.apps.example.net")
				},
				ConfigVariables: acmeVariables(), Config: f.config(renew), ExpectError: failed,
			},
			{
				PreConfig: func() {
					cleanup()
					if n := vaultVersions(f.Cert); n != 1 {
						t.Errorf("%d issued versions after a failed renewal, want 1", n)
					}
					acc.ACME.ClearFailures()
					acc.ACME.SetValidity(365 * 24 * time.Hour)
				},
				ConfigVariables: acmeVariables(), Config: f.config(renew),
				Check: func(*terraform.State) error {
					if n := vaultVersions(f.Cert); n != 2 {
						return fmt.Errorf("%d issued versions after the retry, want 2", n)
					}
					return nil
				},
			},
		},
	})
}

func TestAccACMECertificate_pendingOperationLeftBehind(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	renew := tweaks
	renew.MinDays = 100
	other := regexp.MustCompile(`OtherCA`)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				// Create: a leftover operation of issuer Unknown is deleted.
				PreConfig:       func() { acc.KeyVault.AddPendingOperation(f.Cert, "Unknown") },
				ConfigVariables: acmeVariables(), Config: f.config(tweaks),
				Check: func(*terraform.State) error {
					if slices.Contains(acc.KeyVault.PendingOperations(), f.Cert) {
						return fmt.Errorf("the leftover pending operation was not deleted")
					}
					return nil
				},
			},
			{
				// Update: the same after issuance.
				PreConfig: func() {
					acc.ACME.SetValidity(365 * 24 * time.Hour)
					acc.KeyVault.AddPendingOperation(f.Cert, "Unknown")
				},
				ConfigVariables: acmeVariables(), Config: f.config(renew),
				Check: func(*terraform.State) error {
					if slices.Contains(acc.KeyVault.PendingOperations(), f.Cert) || vaultVersions(f.Cert) != 2 {
						return fmt.Errorf("pending %v, issued versions %d", acc.KeyVault.PendingOperations(), vaultVersions(f.Cert))
					}
					return nil
				},
			},
			{
				// Another issuer's operation is never touched; the order fails naming it.
				PreConfig: func() {
					acc.KeyVault.AddPendingOperation(f.Cert, "OtherCA")
				},
				ConfigVariables: acmeVariables(), Config: f.config(certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly, MinDays: 400}),
				ExpectError: other,
			},
		},
	})
}

func TestAccACMECertificate_pendingOperationOfAnotherIssuerOnCreate(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{{
			PreConfig:       func() { acc.KeyVault.AddPendingOperation(f.Cert, "OtherCA") },
			ConfigVariables: acmeVariables(),
			Config:          f.config(certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}),
			ExpectError:     regexp.MustCompile(`OtherCA`),
		}},
	})
	if !slices.Contains(acc.KeyVault.PendingOperations(), f.Cert) {
		t.Errorf("the operation of another issuer was removed")
	}
}

func TestAccACMECertificate_wrongKeyChainRefused(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	cleanup := assertCleanup(t, f.Cert)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{{
			PreConfig:       func() { acc.ACME.IssueWrongKey(true) },
			ConfigVariables: acmeVariables(),
			Config:          f.config(certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}),
			ExpectError:     regexp.MustCompile(`(?s)not\s+the\s+key\s+of\s+the\s+signing\s+request`),
		}},
	})
	cleanup()
	if n := vaultVersions(f.Cert); n != 0 {
		t.Errorf("%d issued versions, want none", n)
	}
}

func TestAccACMECertificate_dnsWriteFails(t *testing.T) {
	accPreCheck(t)
	cases := map[string]struct {
		arm     func()
		want    string
		cleaned bool
	}{
		"azure writes fail":      {func() { acc.AzureDNS.FailWrites(true) }, `Azure\s+DNS\s+answered\s+500`, true},
		"cloudflare writes fail": {func() { acc.Cloudflare.FailWrites(true) }, `Cloudflare\s+answered\s+500`, true},
		"never propagates": {func() { acc.DNS.NeverPropagate("_acme-challenge.example.com") },
			`challenge\s+record\s+_acme-challenge\.example\.com\s+did\s+not\s+become\s+visible`, true},
		"removal fails": {func() { acc.Cloudflare.FailDeletes(true) },
			`(?s)cannot\s+remove\s+the\s+challenge\s+records\s+\(_acme-challenge\.example\.com\)`, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newACMEFixture(t, "P256")
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: newTestProviderFactories(),
				Steps: []resource.TestStep{{
					PreConfig:       c.arm,
					ConfigVariables: acmeVariables(),
					Config:          f.config(certOptions{}),
					ExpectError:     regexp.MustCompile(`(?s)` + c.want),
				}},
			})
			if slices.Contains(acc.KeyVault.PendingOperations(), f.Cert) {
				t.Errorf("a pending operation is left")
			}
			if vaultVersions(f.Cert) != 0 {
				t.Errorf("a certificate was merged")
			}
			if c.cleaned {
				if all := acc.DNS.All(); len(all) != 0 {
					t.Errorf("records are left behind: %v", all)
				}
			} else if left := acc.DNS.Values("_acme-challenge.example.com"); len(left) == 0 {
				t.Errorf("the test expected the Cloudflare records to remain")
			}
		})
	}
}

func TestAccACMECertificate_refreshFailureKeepsState(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	wrongToken := acmeVariables()
	wrongToken["kv_token"] = acmeVariables()["arm_token"] // the Resource Manager token is not accepted by Key Vault
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: f.config(tweaks)},
			{
				PreConfig:       func() { acc.KeyVault.SetFailure(503) },
				ConfigVariables: acmeVariables(), Config: f.config(tweaks), PlanOnly: true,
				ExpectError: regexp.MustCompile(`Key\s+Vault\s+answered\s+503`),
			},
			{
				PreConfig:       func() { acc.KeyVault.SetFailure(0) },
				ConfigVariables: wrongToken, Config: f.config(tweaks), PlanOnly: true,
				ExpectError: regexp.MustCompile(`Key\s+Vault\s+answered\s+401`),
			},
			{ConfigVariables: acmeVariables(), Config: f.config(tweaks), PlanOnly: true},
		},
	})
}

func TestAccACMECertificate_boundedRetries(t *testing.T) {
	accPreCheck(t)
	t.Run("a few failures are retried", func(t *testing.T) {
		f := newACMEFixture(t, "P256")
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{{
				PreConfig:       func() { acc.ACME.Fail5xx(2) },
				ConfigVariables: acmeVariables(),
				Config:          f.config(certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}),
			}},
		})
	})
	t.Run("many failures stop quickly", func(t *testing.T) {
		f := newACMEFixture(t, "P256")
		start := time.Now()
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{{
				PreConfig:       func() { acc.ACME.Fail5xx(10) },
				ConfigVariables: acmeVariables(),
				Config:          f.config(certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}),
				ExpectError:     regexp.MustCompile(`(?s)cannot\s+look\s+up\s+the\s+account.*503`),
			}},
		})
		if d := time.Since(start); d > 30*time.Second {
			t.Errorf("giving up took %s", d)
		}
	})
}

func TestAccACMECertificate_propagationSettings(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	with := func(settings string) string {
		return acmeProviderConfigWith(settings) + f.registrationHCL("") + f.certHCL(tweaks)
	}
	never := func() { acc.DNS.NeverPropagate("_acme-challenge.example.com") }
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				// On by default: a record that never becomes visible fails the order.
				PreConfig:       never,
				ConfigVariables: acmeVariables(), Config: with(""),
				ExpectError: regexp.MustCompile(`(?s)did\s+not\s+become\s+visible`),
			},
			{
				PreConfig: func() {
					if s, ok := lastPropagation(); !ok || !s.check || s.timeout != 2*time.Minute {
						t.Errorf("default settings: %+v", s)
					}
				},
				ConfigVariables: acmeVariables(), Config: with(`dns_propagation_timeout = "90s"`),
				ExpectError: regexp.MustCompile(`(?s)did\s+not\s+become\s+visible`),
			},
			{
				PreConfig: func() {
					if s, ok := lastPropagation(); !ok || !s.check || s.timeout != 90*time.Second {
						t.Errorf("timeout setting: %+v", s)
					}
				},
				// Off: the provider does not wait for visibility and the authority validates.
				ConfigVariables: acmeVariables(), Config: with(`dns_propagation_check = false`),
				Check: func(*terraform.State) error {
					if s, ok := lastPropagation(); !ok || s.check {
						return fmt.Errorf("the check was not turned off: %+v", s)
					}
					return nil
				},
			},
		},
	})
}

func TestAccACMEProvider_propagationTimeoutOutOfRange(t *testing.T) {
	accPreCheck(t)
	for _, bad := range []string{"5s", "31m", "soon"} {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{{
				ConfigVariables: acmeVariables(),
				Config:          acmeProviderConfigWith(`dns_propagation_timeout = "`+bad+`"`) + `data "conative_azuresql_database_users" "x" {}`,
				PlanOnly:        true,
				ExpectError:     regexp.MustCompile(`(?s)Invalid\s+value.*must\s+be\s+(between\s+10s\s+and\s+30m|a\s+duration)`),
			}},
		})
	}
}

// A first order that fails leaves the Key Vault certificate without an issued version. It
// is kept on purpose: the error says so and a retry of the same configuration reuses it.
func TestAccACMECertificate_failedFirstCreateKeepsCertificate(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	cleanup := assertCleanup(t, f.Cert)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				PreConfig:       func() { acc.ACME.FailFinalize(true) },
				ConfigVariables: acmeVariables(), Config: f.config(tweaks),
				ExpectError: regexp.MustCompile(`(?s)Key\s+Vault\s+now\s+holds\s+a\s+certificate\s+named\s+"` + f.Cert +
					`"\s+that\s+has\s+no\s+issued\s+version.*next\s+apply.*reuses\s+it.*delete.*purge`),
			},
			{
				PreConfig: func() {
					cleanup()
					if !acc.KeyVault.Exists(f.Cert) || vaultVersions(f.Cert) != 0 {
						t.Errorf("the certificate should exist without an issued version (exists %t, issued versions %d)",
							acc.KeyVault.Exists(f.Cert), vaultVersions(f.Cert))
					}
					acc.ACME.ClearFailures()
				},
				ConfigVariables: acmeVariables(), Config: f.config(tweaks),
				Check: resource.ComposeTestCheckFunc(
					func(*terraform.State) error {
						if n := vaultVersions(f.Cert); n != 1 {
							return fmt.Errorf("%d issued versions after the retry, want 1", n)
						}
						return nil
					},
					dnsClean(),
				),
			},
		},
	})
}

// When the authority no longer knows the account, the error names the way out.
func TestAccACMECertificate_accountGone(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly, Revoke: "false"}
	renew := tweaks
	renew.MinDays = 100
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: f.config(tweaks)},
			{
				PreConfig:       func() { acc.ACME.SetValidity(365 * 24 * time.Hour); acc.ACME.ForgetAccounts() },
				ConfigVariables: acmeVariables(), Config: f.config(renew),
				ExpectError: regexp.MustCompile(`(?s)no\s+account\s+for\s+the\s+registration.*terraform\s+apply\s+-replace=`),
			},
			{
				// A renewal that fails before it touches Key Vault leaves it as it was.
				PreConfig: func() {
					if n := vaultVersions(f.Cert); n != 1 {
						t.Errorf("%d issued versions, want 1", n)
					}
					acc.ACME.SetValidity(90 * 24 * time.Hour)
				},
				ConfigVariables: acmeVariables(), Config: f.config(tweaks), PlanOnly: true,
			},
		},
	})
}
