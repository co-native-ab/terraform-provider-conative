package provider

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const azureApex = `
  azure_dns {
    subscription_id = "00000000-0000-0000-0000-000000000000"
    resource_group  = "dns"
    zone_name       = "example.net"
    match_domains   = ["example.net"]
  }
`

// parallelPair declares two certificates of one registration whose names share a
// challenge record name (example and *.example): Terraform orders them at the same time.
func parallelPair(f acmeFixture, base, wildcard string, blocks string) (string, acmeFixture) {
	g := f
	g.Cert = uniqueName("cert")
	cfg := acmeProviderConfig() + f.registrationHCL("") +
		f.certHCL(certOptions{Resource: "c", CN: base, SANs: []string{}, Blocks: blocks, KeyType: "P256"}) +
		g.certHCL(certOptions{Resource: "d", CN: wildcard, SANs: []string{}, Blocks: blocks, KeyType: "P256"})
	return cfg, g
}

func bothIssued(f, g acmeFixture) resource.TestCheckFunc {
	return func(*terraform.State) error {
		for _, name := range []string{f.Cert, g.Cert} {
			if n := vaultVersions(name); n != 1 {
				return fmt.Errorf("%s has %d issued versions, want 1", name, n)
			}
			if p := acc.KeyVault.PendingOperations(); len(p) != 0 {
				return fmt.Errorf("pending operations are left: %v", p)
			}
		}
		if all := acc.DNS.All(); len(all) != 0 {
			return fmt.Errorf("challenge records are left behind: %v", all)
		}
		return nil
	}
}

// Two certificates for example.net and *.example.net write one Azure DNS record set at
// the same time; both orders succeed and the record set is empty afterwards.
func TestAccACMECertificate_parallelOrdersShareAzureRecordSet(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	cfg, g := parallelPair(f, "example.net", "*.example.net", azureApex)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				// Latency makes the two orders overlap between reading and writing the set.
				PreConfig:       func() { acc.AzureDNS.SetLatency(15 * time.Millisecond) },
				ConfigVariables: acmeVariables(), Config: cfg,
				Check: bothIssued(f, g),
			},
			{ConfigVariables: acmeVariables(), Config: cfg, PlanOnly: true},
		},
	})
}

// Two certificates for example.com and *.example.com publish challenge records for one
// name in Cloudflare. When the authority hands both orders the same pending authorization
// the second publishes an identical record, which Cloudflare refuses: it is used as it is
// and left to the order that created it.
func TestAccACMECertificate_parallelOrdersShareCloudflareName(t *testing.T) {
	accPreCheck(t)
	for name, pending := range map[string]bool{"separate authorizations": false, "shared pending authorization": true} {
		t.Run(name, func(t *testing.T) {
			f := newACMEFixture(t, "P256")
			cfg, g := parallelPair(f, "example.com", "*.example.com", cloudflareOnly)
			if pending {
				// The same name in both certificates, so the orders share one authorization.
				cfg, g = parallelPair(f, "example.com", "example.com", cloudflareOnly)
			}
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: newTestProviderFactories(),
				Steps: []resource.TestStep{
					{
						PreConfig: func() {
							acc.Cloudflare.RefuseIdenticalRecords(true)
							acc.ACME.ReusePendingAuthorizations(pending)
						},
						ConfigVariables: acmeVariables(), Config: cfg,
						Check: bothIssued(f, g),
					},
					{ConfigVariables: acmeVariables(), Config: cfg, PlanOnly: true},
				},
			})
		})
	}
}
