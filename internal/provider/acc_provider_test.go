package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccProvider_connects(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "smoke"); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config: providerConfig() + `
data "conative_azuresql_database_users" "all" {
  database = "` + db + `"
}
`,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("data.conative_azuresql_database_users.all", "users.#", "1"),
				resource.TestCheckResourceAttr("data.conative_azuresql_database_users.all", "users.0.name", "smoke"),
				resource.TestCheckResourceAttr("data.conative_azuresql_database_users.all", "users.0.principal_type", "SQL_USER"),
			),
		}},
	})
}
