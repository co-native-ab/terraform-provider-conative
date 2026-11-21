package provider

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/keyvaultfake"
)

// documentedOrderActions are exactly the Key Vault data actions that the guide lists for
// "Order or renew a certificate". The acceptance tests below run an order with no other
// right, and TestGuideListsTheDocumentedActions checks the guide against this list, so the
// documentation and the behaviour cannot drift apart.
var documentedOrderActions = []string{
	keyvaultfake.ActionCertificatesRead,
	keyvaultfake.ActionCertificatesCreate,
	keyvaultfake.ActionKeysRead,
	keyvaultfake.ActionKeysSign,
}

// documentedRevokeDestroyActions are exactly the Key Vault data actions that the guide
// lists for "Destroy with `revoke_on_destroy = true`".
var documentedRevokeDestroyActions = []string{
	keyvaultfake.ActionCertificatesRead,
	keyvaultfake.ActionCertificatesDelete,
	keyvaultfake.ActionKeysRead,
	keyvaultfake.ActionKeysSign,
}

const keyVaultActionPrefix = "Microsoft.KeyVault/vaults/"

// shortAction drops the common prefix, the form the guide uses.
func shortAction(a string) string { return strings.TrimPrefix(a, keyVaultActionPrefix) }

func without(actions []string, drop string) []string {
	return slices.DeleteFunc(slices.Clone(actions), func(a string) bool { return a == drop })
}

var guideActionRE = regexp.MustCompile("`((?:Microsoft\\.KeyVault/vaults/)?(?:certificates|keys|secrets)/[A-Za-z/]+)`")

// guideRowActions returns the Key Vault data actions named in the "Key Vault data
// actions" column of the permissions-table row that starts with operation.
func guideRowActions(t *testing.T, guide, operation string) []string {
	t.Helper()
	for _, line := range strings.Split(guide, "\n") {
		cells := strings.Split(line, "|")
		// A table row splits into an empty cell, the operation, the data actions, the other
		// services and an empty cell.
		if len(cells) < 5 || strings.TrimSpace(cells[1]) != operation {
			continue
		}
		var out []string
		for _, m := range guideActionRE.FindAllStringSubmatch(cells[2], -1) {
			out = append(out, shortAction(m[1]))
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	t.Fatalf("the guide has no permissions row %q", operation)
	return nil
}

func TestGuideListsTheDocumentedActions(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../docs/guides/acme-certificates-in-key-vault.md")
	if err != nil {
		t.Fatal(err)
	}
	for operation, actions := range map[string][]string{
		"Order or renew a certificate":            documentedOrderActions,
		"Destroy with `revoke_on_destroy = true`": documentedRevokeDestroyActions,
	} {
		got := guideRowActions(t, string(raw), operation)
		var want []string
		for _, a := range actions {
			want = append(want, shortAction(a))
		}
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("the guide lists %v for %q, the acceptance tests grant %v", got, operation, want)
		}
	}
}

// The documented rights are enough for an order that has to clear a pending operation:
// a finished record that Key Vault keeps, and an operation in progress that a failed run
// left behind. As in Key Vault, the fake authorises every request to the pending operation,
// deleting it included, as certificates/create/action alone.
func TestAccACMECertificate_orderWithDocumentedRights(t *testing.T) {
	accPreCheck(t)
	t.Cleanup(acc.KeyVault.GrantAll)
	f := newACMEFixture(t, "P256")
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	finished := tweaks
	finished.MinDays = 100
	leftover := finished
	// A new name orders again, and leaves a plan that is empty afterwards.
	leftover.SANs = []string{"*.example.com", "www.example.com"}

	var kvMark, forbidden int
	restrict := func(kind string) func() {
		return func() {
			acc.ACME.SetValidity(365 * 24 * time.Hour)
			acc.KeyVault.SetDataActions(documentedOrderActions...)
			kvMark = acc.KeyVault.Journal.Mark()
			forbidden = acc.KeyVault.ForbiddenMark()
			if kind == "leftover" {
				acc.KeyVault.AddPendingOperation(f.Cert, "Unknown")
			}
		}
	}
	cleared := func(want int) resource.TestCheckFunc {
		return func(*terraform.State) error {
			if got := acc.KeyVault.ForbiddenSince(forbidden); len(got) != 0 {
				return fmt.Errorf("Key Vault refused requests with the documented rights: %v", got)
			}
			deleted := false
			for _, e := range acc.KeyVault.Journal.Since(kvMark) {
				if e.Method == "DELETE" && strings.HasSuffix(e.Path, "/certificates/"+f.Cert+"/pending") {
					deleted = true
				}
			}
			if !deleted {
				return fmt.Errorf("the pending operation was not deleted")
			}
			if n := vaultVersions(f.Cert); n != want {
				return fmt.Errorf("%d issued versions, want %d", n, want)
			}
			return nil
		}
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: f.config(tweaks)},
			{
				// A finished record: Key Vault keeps the record of the first order.
				PreConfig: func() {
					if _, status, ok := acc.KeyVault.PendingRecord(f.Cert); !ok || status != "completed" {
						t.Fatalf("pending record: %q %v", status, ok)
					}
					restrict("finished")()
				},
				ConfigVariables: acmeVariables(), Config: f.config(finished),
				Check: cleared(2),
			},
			{
				// An operation in progress, left behind by a failed run, is cancelled.
				PreConfig:       restrict("leftover"),
				ConfigVariables: acmeVariables(), Config: f.config(leftover),
				Check: resource.ComposeTestCheckFunc(cleared(3), func(*terraform.State) error {
					if slices.Contains(acc.KeyVault.PendingOperations(), f.Cert) {
						return fmt.Errorf("the leftover pending operation was not deleted")
					}
					return nil
				}),
			},
			{
				// Every right again, so that the test can destroy what it made.
				PreConfig:       acc.KeyVault.GrantAll,
				ConfigVariables: acmeVariables(), Config: f.config(leftover), PlanOnly: true,
			},
		},
	})
}

// Without one of the documented rights the order fails with the 403 that names it: the
// documented set has no right to spare.
func TestAccACMECertificate_orderNeedsEveryDocumentedRight(t *testing.T) {
	accPreCheck(t)
	for _, missing := range documentedOrderActions {
		t.Run("without "+shortAction(missing), func(t *testing.T) {
			t.Cleanup(acc.KeyVault.GrantAll)
			f := newACMEFixture(t, "P256")
			tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
			renew := tweaks
			renew.MinDays = 100
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: newTestProviderFactories(),
				Steps: []resource.TestStep{
					{ConfigVariables: acmeVariables(), Config: f.config(tweaks)},
					{
						PreConfig: func() {
							acc.ACME.SetValidity(365 * 24 * time.Hour)
							acc.KeyVault.SetDataActions(without(documentedOrderActions, missing)...)
						},
						ConfigVariables: acmeVariables(), Config: f.config(renew),
						ExpectError: regexp.MustCompile(`(?s)` + strings.ReplaceAll(regexp.QuoteMeta(shortAction(missing)), "/", `\s*/\s*`)),
					},
					{PreConfig: acc.KeyVault.GrantAll, ConfigVariables: acmeVariables(), Config: f.config(tweaks), PlanOnly: true},
				},
			})
		})
	}
}

// certificates/update/action and certificates/delete are not needed for an order, not even
// to clear a finished record or cancel a leftover operation: Key Vault authorises the
// pending-operation endpoint as certificates/create/action alone. An order with neither
// of them, on top of the documented set, succeeds and deletes the pending operation.
func TestAccACMECertificate_orderNeedsNoUpdateOrDeleteRight(t *testing.T) {
	accPreCheck(t)
	t.Cleanup(acc.KeyVault.GrantAll)
	for _, granted := range documentedOrderActions {
		if granted == keyvaultfake.ActionCertificatesUpdate || granted == keyvaultfake.ActionCertificatesDelete {
			t.Fatalf("the documented order set lists %s", shortAction(granted))
		}
	}
	f := newACMEFixture(t, "P256")
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly}
	renew := tweaks
	renew.MinDays = 100
	var kvMark, forbidden int
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: f.config(tweaks)},
			{
				PreConfig: func() {
					acc.ACME.SetValidity(365 * 24 * time.Hour)
					acc.KeyVault.SetDataActions(documentedOrderActions...)
					acc.KeyVault.AddPendingOperation(f.Cert, "Unknown")
					kvMark = acc.KeyVault.Journal.Mark()
					forbidden = acc.KeyVault.ForbiddenMark()
				},
				ConfigVariables: acmeVariables(), Config: f.config(renew),
				Check: func(*terraform.State) error {
					if got := acc.KeyVault.ForbiddenSince(forbidden); len(got) != 0 {
						return fmt.Errorf("Key Vault refused requests without update/action and delete: %v", got)
					}
					for _, e := range acc.KeyVault.Journal.Since(kvMark) {
						if e.Method == "DELETE" && strings.HasSuffix(e.Path, "/certificates/"+f.Cert+"/pending") {
							return nil
						}
					}
					return fmt.Errorf("the pending operation was not deleted")
				},
			},
			{PreConfig: acc.KeyVault.GrantAll, ConfigVariables: acmeVariables(), Config: f.config(renew), PlanOnly: true},
		},
	})
}

// Destroy with revoke_on_destroy = true works with exactly the documented rights, and
// fails without keys/read: the account key is read to sign the revocation (and, in this
// configuration, already by the refresh of the registration that precedes the destroy).
func TestAccACMECertificate_revokeDestroyWithDocumentedRights(t *testing.T) {
	accPreCheck(t)
	tweaks := certOptions{SANs: []string{"*.example.com"}, Blocks: cloudflareOnly, Revoke: "true"}

	t.Run("documented rights", func(t *testing.T) {
		t.Cleanup(acc.KeyVault.GrantAll)
		// The rights are narrowed after the apply, so that the final destroy runs with
		// exactly the documented set.
		f := newACMEFixture(t, "P256")
		var serial string
		var forbidden int
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			CheckDestroy: func(*terraform.State) error {
				acc.KeyVault.GrantAll()
				if got := acc.KeyVault.ForbiddenSince(forbidden); len(got) != 0 {
					return fmt.Errorf("Key Vault refused requests with the documented rights: %v", got)
				}
				if !slices.Contains(acc.ACME.Revoked(), serial) {
					return fmt.Errorf("serial %s was not revoked", serial)
				}
				if !acc.KeyVault.Deleted(f.Cert) {
					return fmt.Errorf("the certificate was not deleted")
				}
				return nil
			},
			Steps: []resource.TestStep{{
				ConfigVariables: acmeVariables(), Config: f.config(tweaks),
				Check: func(st *terraform.State) (err error) {
					if serial, err = serialOf(st); err != nil {
						return err
					}
					acc.KeyVault.SetDataActions(documentedRevokeDestroyActions...)
					forbidden = acc.KeyVault.ForbiddenMark()
					return nil
				},
			}},
		})
	})

	t.Run("without keys/read", func(t *testing.T) {
		t.Cleanup(acc.KeyVault.GrantAll)
		f := newACMEFixture(t, "P256")
		var serial string
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: newTestProviderFactories(),
			Steps: []resource.TestStep{
				{
					ConfigVariables: acmeVariables(), Config: f.config(tweaks),
					Check: func(st *terraform.State) (err error) { serial, err = serialOf(st); return err },
				},
				{
					PreConfig: func() {
						acc.KeyVault.SetDataActions(without(documentedRevokeDestroyActions, keyvaultfake.ActionKeysRead)...)
					},
					ConfigVariables: acmeVariables(), Config: f.config(tweaks),
					Destroy:     true,
					ExpectError: regexp.MustCompile(`(?s)keys\s*/\s*read`),
				},
				{
					PreConfig: func() {
						acc.KeyVault.GrantAll()
						if slices.Contains(acc.ACME.Revoked(), serial) {
							t.Errorf("serial %s was revoked although destroy failed", serial)
						}
						if !acc.KeyVault.Exists(f.Cert) {
							t.Errorf("the certificate was deleted although destroy failed")
						}
					},
					ConfigVariables: acmeVariables(), Config: f.config(tweaks), PlanOnly: true,
				},
			},
		})
	})
}
