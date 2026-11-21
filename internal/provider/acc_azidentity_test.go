package provider

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// The recommended way to supply the access token is an ephemeral resource of the
// co-native-ab/azidentity provider. These tests run that provider, downloaded from the
// Terraform Registry, next to this one, so that an ephemeral value it produces flows into
// the provider configuration exactly as it does for users.
//
// Its credential resources need Microsoft Entra ID, which the acceptance environment does
// not have. Its azidentity_environment_variable resource produces the same kind of value,
// an ephemeral and sensitive string, from an environment variable the test sets to the
// token the sign-in proxy accepts.

// azidentityTokenEnv is the environment variable the azidentity provider reads the
// token from. Terraform passes the test's environment on to the providers it starts.
const azidentityTokenEnv = "CONATIVE_ACC_AZIDENTITY_TOKEN"

var azidentityProvider = map[string]resource.ExternalProvider{
	"azidentity": {
		Source:            "co-native-ab/azidentity",
		VersionConstraint: "~> 0.1",
	},
}

func azidentityConfig(server, rest string) string {
	return fmt.Sprintf(`
provider "azidentity" {}

ephemeral "azidentity_environment_variable" "token" {
  key = %q
}

provider "conative" {
  azuresql = {
    server       = %q
    access_token = ephemeral.azidentity_environment_variable.token.value
  }
}
`, azidentityTokenEnv, server) + rest
}

func TestAccProvider_tokenFromAzidentity(t *testing.T) {
	accPreCheck(t)
	dir := t.TempDir()
	t.Setenv("TF_ACC_TEMP_DIR", dir)
	t.Setenv(azidentityTokenEnv, acc.Token)
	db := newDatabase(t)
	if err := acc.Container(t).CreateUserWithoutLogin(db, "reader"); err != nil {
		t.Fatal(err)
	}
	var files int

	cfg := azidentityConfig(acc.Server(t), fmt.Sprintf(`
resource "conative_azuresql_database_role_member" "m" {
  database = %[1]q
  role     = "db_datareader"
  member   = "reader"
}

data "conative_azuresql_database_user" "reader" {
  database = %[1]q
  name     = conative_azuresql_database_role_member.m.member
}
`, db))
	const user = "data.conative_azuresql_database_user.reader"

	resource.Test(t, resource.TestCase{
		ExternalProviders:        azidentityProvider,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					memberCheck(t, db, "db_datareader", "reader", true),
					resource.TestCheckResourceAttr(user, "id", db+"/reader"),
					resource.TestCheckResourceAttr(user, "principal_type", "SQL_USER"),
					workdirHasNoToken(t, dir, &files),
				),
			},
			{
				// Every run obtains the token again; nothing changes.
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
	if ok, err := isMember(t, db, "db_datareader", "reader"); err != nil || ok {
		t.Errorf("after destroy: member = %t, err = %v; want the membership removed", ok, err)
	}
	if files == 0 {
		t.Error("no state file was searched, so the check proved nothing")
	}
}

// A rejected token from azidentity fails with the sign-in error at once and is not retried.
func TestAccProvider_wrongTokenFromAzidentityFailsFast(t *testing.T) {
	accPreCheck(t)
	t.Setenv(azidentityTokenEnv, acc.WrongToken)
	db := newDatabase(t)

	start := time.Now()
	resource.Test(t, resource.TestCase{
		ExternalProviders:        azidentityProvider,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: azidentityConfig(acc.Server(t), fmt.Sprintf(`
data "conative_azuresql_database_users" "all" {
  database = %q
}
`, db)),
			ExpectError: regexp.MustCompile(`(?s)Login\s+failed`),
		}},
	})
	// The limit allows for downloading the azidentity provider. A retried sign-in would
	// keep trying for the default retry timeout of two minutes.
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("the wrong token took %s to fail, which means it was retried", elapsed)
	}
}
