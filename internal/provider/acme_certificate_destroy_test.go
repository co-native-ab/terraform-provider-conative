package provider

import (
	"crypto/x509"
	"fmt"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// serialOf returns the serial number of the certificate in the state.
func serialOf(s *terraform.State) (string, error) {
	a, err := certAttrs(s)
	if err != nil {
		return "", err
	}
	der := acc.KeyVault.LeafDER(a["certificate_name"], a["version"])
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	return leaf.SerialNumber.String(), nil
}

func TestAccACMECertificate_revokeOnDestroy(t *testing.T) {
	accPreCheck(t)
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}

	run := func(t *testing.T, name string, revoke string, arm func(f acmeFixture, serial *string) resource.TestCheckFunc, expectRevoked bool, nonEmpty bool) {
		t.Run(name, func(t *testing.T) {
			f := newACMEFixture(t, "P256")
			var serial string
			s := tweaks
			s.Revoke = revoke
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: newTestProviderFactories(),
				CheckDestroy: func(*terraform.State) error {
					if got := slices.Contains(acc.ACME.Revoked(), serial); got != expectRevoked {
						return fmt.Errorf("serial %s revoked: %t, want %t", serial, got, expectRevoked)
					}
					if !acc.KeyVault.Deleted(f.Cert) {
						return fmt.Errorf("the certificate was not deleted")
					}
					return nil
				},
				Steps: []resource.TestStep{{
					PreConfig:       func() {},
					ConfigVariables: acmeVariables(),
					Config:          f.config(s),
					Check: resource.ComposeTestCheckFunc(
						func(st *terraform.State) (err error) { serial, err = serialOf(st); return err },
						arm(f, &serial),
					),
					ExpectNonEmptyPlan: nonEmpty,
				}},
			})
		})
	}
	none := func(acmeFixture, *string) resource.TestCheckFunc { return func(*terraform.State) error { return nil } }
	run(t, "revoked", "true", none, true, false)
	run(t, "not revoked when revoke_on_destroy is false", "false", none, false, false)
	run(t, "already revoked", "true", func(_ acmeFixture, serial *string) resource.TestCheckFunc {
		return func(*terraform.State) error { acc.ACME.MarkRevoked(*serial); return nil }
	}, true, false)

	t.Run("expired certificate is not revoked", func(t *testing.T) {
		f := newACMEFixture(t, "P256")
		before := len(acc.ACME.Revoked())
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			CheckDestroy: func(*terraform.State) error {
				if n := len(acc.ACME.Revoked()); n != before {
					return fmt.Errorf("a certificate that had expired was revoked")
				}
				if !acc.KeyVault.Deleted(f.Cert) {
					return fmt.Errorf("the certificate was not deleted")
				}
				return nil
			},
			Steps: []resource.TestStep{{
				PreConfig:          func() { acc.ACME.SetValidity(-24 * time.Hour) },
				ConfigVariables:    acmeVariables(),
				Config:             f.config(tweaks),
				ExpectNonEmptyPlan: true,
			}},
		})
	})

	t.Run("refused revocation keeps the certificate", func(t *testing.T) {
		f := newACMEFixture(t, "P256")
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{
				{ConfigVariables: acmeVariables(), Config: f.config(tweaks)},
				{
					PreConfig:       func() { acc.ACME.RevokeRefused(true) },
					ConfigVariables: acmeVariables(),
					Config:          f.config(tweaks),
					Destroy:         true,
					ExpectError:     regexp.MustCompile(`(?s)revocation\s+is\s+refused`),
				},
				{
					PreConfig: func() {
						if !acc.KeyVault.Exists(f.Cert) {
							t.Errorf("the certificate was deleted although revocation failed")
						}
						acc.ACME.RevokeRefused(false)
					},
					ConfigVariables: acmeVariables(),
					Config:          f.config(tweaks),
					PlanOnly:        true,
				},
			},
		})
	})
}

func TestAccACMECertificate_revokeOnDestroyRequired(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{{
			ConfigVariables: acmeVariables(),
			Config:          f.config(certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly, Revoke: "omit"}),
			PlanOnly:        true,
			ExpectError:     regexp.MustCompile(`(?s)revoke_on_destroy.*is\s+required`),
		}},
	})
}

func TestAccACMECertificate_deletedOutsideTerraform(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: f.config(tweaks)},
			{
				// Refresh drops the resource; creating it again meets Key Vault's soft-deleted name.
				PreConfig:       func() { acc.KeyVault.SoftDelete(f.Cert) },
				ConfigVariables: acmeVariables(),
				Config:          f.config(tweaks),
				ExpectError:     regexp.MustCompile(`(?s)deleted\s+but\s+recoverable`),
			},
			{
				PreConfig:       func() { acc.KeyVault.Purge(f.Cert) },
				ConfigVariables: acmeVariables(),
				Config:          f.config(tweaks),
			},
		},
	})
}
