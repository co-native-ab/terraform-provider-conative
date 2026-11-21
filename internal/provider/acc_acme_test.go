package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
)

// acmeSecrets are the tokens of the run; every file and log is searched for them.
func acmeSecrets() []string {
	return []string{acc.KeyVaultToken, acc.ResourceManagerToken, acc.CloudflareToken, acc.CloudflareReadOnlyToken}
}

// planNeverHoldsACMESecrets fails if the saved plan, as `terraform show -json` renders it,
// holds a token or a private key.
type planNeverHoldsACMESecrets struct {
	t      *testing.T
	checks *int
}

func (c planNeverHoldsACMESecrets) CheckPlan(_ context.Context, req plancheck.CheckPlanRequest, _ *plancheck.CheckPlanResponse) {
	data, err := json.Marshal(req.Plan)
	if err != nil {
		c.t.Errorf("cannot render the plan: %v", err)
		return
	}
	*c.checks++
	for _, s := range acmeSecrets() {
		if acctest.ContainsSecret(data, s) {
			c.t.Error("the saved plan contains a token")
		}
	}
	if acctest.ContainsPrivateKey(data, acc.KeyVault.PrivateKeysDER()) {
		c.t.Error("the saved plan contains a private key")
	}
}

func workdirHasNoACMESecrets(t *testing.T, dir string, files *int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		data, err := json.Marshal(s)
		if err != nil {
			return err
		}
		for _, secret := range acmeSecrets() {
			if acctest.ContainsSecret(data, secret) {
				return fmt.Errorf("the state reported by Terraform contains a token")
			}
			*files += acctest.AssertNoSecretInFiles(t, dir, secret, "terraform.tfstate*", "tfplan*")
		}
		if acctest.ContainsPrivateKey(data, acc.KeyVault.PrivateKeysDER()) {
			return fmt.Errorf("the state reported by Terraform contains a private key")
		}
		acctest.AssertNoPrivateKeyInFiles(t, dir, acc.KeyVault.PrivateKeysDER(), "terraform.tfstate*", "tfplan*")
		return nil
	}
}

// Tokens come from ephemeral variables and the Cloudflare token is write-only; private
// keys never leave Key Vault. None of them may be in a state file, a saved plan, or a
// state or plan as Terraform renders them, through issuance, renewal and a refresh.
func TestAccProvider_acmeSecretsNotInStateOrPlan(t *testing.T) {
	accPreCheck(t)
	dir := t.TempDir()
	t.Setenv("TF_ACC_TEMP_DIR", dir)
	f := newACMEFixture(t, "P256")
	var files, plans int
	cfg := f.config(certOptions{})
	renew := f.config(certOptions{MinDays: 100})
	planChecks := resource.ConfigPlanChecks{
		PreApply:             []plancheck.PlanCheck{planNeverHoldsACMESecrets{t, &plans}},
		PostApplyPostRefresh: []plancheck.PlanCheck{planNeverHoldsACMESecrets{t, &plans}},
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: acmeVariables(), Config: cfg, ConfigPlanChecks: planChecks, Check: workdirHasNoACMESecrets(t, dir, &files)},
			{
				PreConfig:       func() { acc.ACME.SetValidity(365 * 24 * time.Hour) },
				ConfigVariables: acmeVariables(), Config: renew, ConfigPlanChecks: planChecks, Check: workdirHasNoACMESecrets(t, dir, &files),
			},
			{ConfigVariables: acmeVariables(), Config: renew, ConfigPlanChecks: planChecks, Check: workdirHasNoACMESecrets(t, dir, &files)},
		},
	})
	if files == 0 || plans == 0 {
		t.Errorf("the check was vacuous: %d files, %d plans searched", files, plans)
	}
}

// At the most verbose logging level none of the tokens and none of the private keys may
// appear in the logs of Terraform, the plugin SDK or the provider, for registration,
// issuance, renewal, destroy and a run with a token Key Vault refuses.
func TestAccProvider_acmeSecretsNotInLogs(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	logPath := acctest.EnableTraceLogs(t, t.TempDir())
	cfg := f.config(certOptions{})
	renew := f.config(certOptions{MinDays: 100})
	refused := acmeVariables()
	refused["kv_token"] = acmeVariables()["arm_token"]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{ConfigVariables: refused, Config: cfg, ExpectError: regexp.MustCompile(`(?s)Key\s+Vault\s+answered\s+401`)},
			{ConfigVariables: acmeVariables(), Config: cfg},
			{
				PreConfig:       func() { acc.ACME.SetValidity(365 * 24 * time.Hour) },
				ConfigVariables: acmeVariables(), Config: renew,
			},
			{ConfigVariables: acmeVariables(), Config: renew, PlanOnly: true},
		},
	})

	for _, s := range acmeSecrets() {
		acctest.AssertSecretAbsent(t, logPath, s)
	}
	acctest.AssertPrivateKeysAbsent(t, logPath, acc.KeyVault.PrivateKeysDER())

	// The check is not vacuous: the log holds the provider's own trace output.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"key vault request", "reading acme certificate", "a new certificate will be ordered"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("the log has no %q line, so provider logging was not captured", want)
		}
	}
	t.Logf("searched %d bytes of trace logs", len(data))
}

func TestAccProvider_acmeSettingsRequiredOnlyOnUse(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	noSettings := `provider "conative" {}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				// Nothing uses the ACME area: no settings are needed.
				Config: noSettings + `
output "unrelated" {
  value = "ok"
}
`,
				Check: resource.TestCheckOutput("unrelated", "ok"),
			},
			{
				Config:      noSettings + f.registrationHCL(""),
				ExpectError: regexp.MustCompile(`(?s)acme\s+settings\s+\(key_vault_access_token\)\s+are\s+required`),
			},
		},
	})
}

// Each token is sent only to the service it is for: swapping them makes the services
// refuse them, and the error names the service.
func TestAccProvider_acmeTokensReachOnlyTheirService(t *testing.T) {
	accPreCheck(t)
	f := newACMEFixture(t, "P256")
	swapped := acmeVariables()
	swapped["kv_token"], swapped["arm_token"] = acmeVariables()["arm_token"], acmeVariables()["kv_token"]
	armOnly := acmeVariables()
	armOnly["arm_token"] = acmeVariables()["kv_token"]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: newTestProviderFactories(),
		Steps: []resource.TestStep{
			{
				ConfigVariables: swapped, Config: f.registrationOnlyConfig(),
				ExpectError: regexp.MustCompile(`(?s)Key\s+Vault\s+answered\s+401`),
			},
			{
				ConfigVariables: acmeVariables(), Config: f.config(certOptions{}),
				PlanOnly: true, ExpectNonEmptyPlan: true,
			},
			{
				// The Resource Manager token is refused by Azure DNS, which names itself.
				ConfigVariables: armOnly, Config: f.config(certOptions{}),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Azure\s+DNS\s+answered\s+401`),
			},
		},
	})
}
