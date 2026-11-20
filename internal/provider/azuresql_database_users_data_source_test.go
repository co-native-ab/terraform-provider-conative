package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func usersDataSourceConfig(db, filters string) string {
	return providerConfig() + fmt.Sprintf(`
data "conative_azuresql_database_users" "all" {
  database = %q
  %s
}
`, db, filters)
}

const usersAddr = "data.conative_azuresql_database_users.all"

func TestAccDatabaseUsersDataSource_listsOrderedWithoutBuiltIns(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	for _, n := range []string{"zeta", "alpha", "mid"} {
		if err := acc.Container.CreateUserWithoutLogin(db, n); err != nil {
			t.Fatal(err)
		}
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          usersDataSourceConfig(db, ""),
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr(usersAddr, "id", db),
				resource.TestCheckResourceAttr(usersAddr, "users.#", "3"),
				resource.TestCheckResourceAttr(usersAddr, "users.0.name", "alpha"),
				resource.TestCheckResourceAttr(usersAddr, "users.1.name", "mid"),
				resource.TestCheckResourceAttr(usersAddr, "users.2.name", "zeta"),
				resource.TestCheckResourceAttr(usersAddr, "users.0.principal_type", "SQL_USER"),
				resource.TestMatchResourceAttr(usersAddr, "users.0.sid", regexp.MustCompile(`^0x[0-9A-F]+$`)),
				resource.TestCheckNoResourceAttr(usersAddr, "users.0.entra_id"),
			),
		}},
	})
}

func TestAccDatabaseUsersDataSource_nameFilterIsExact(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	for _, n := range []string{"app", "app2", "APP-other"} {
		if err := acc.Container.CreateUserWithoutLogin(db, n); err != nil {
			t.Fatal(err)
		}
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				ConfigVariables: tokenVariables(),
				Config:          usersDataSourceConfig(db, `name = "app2"`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(usersAddr, "users.#", "1"),
					resource.TestCheckResourceAttr(usersAddr, "users.0.name", "app2"),
				),
			},
			{
				ConfigVariables: tokenVariables(),
				Config:          usersDataSourceConfig(db, `name = "ap"`),
				Check:           resource.TestCheckResourceAttr(usersAddr, "users.#", "0"),
			},
		},
	})
}

func TestAccDatabaseUsersDataSource_principalTypeFilter(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "sqluser"); err != nil {
		t.Fatal(err)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// An empty result is not an error.
				ConfigVariables: tokenVariables(),
				Config:          usersDataSourceConfig(db, `principal_type = "EXTERNAL_USER"`),
				Check:           resource.TestCheckResourceAttr(usersAddr, "users.#", "0"),
			},
			{
				ConfigVariables: tokenVariables(),
				Config:          usersDataSourceConfig(db, `principal_type = "SQL_USER"`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(usersAddr, "users.#", "1"),
					resource.TestCheckResourceAttr(usersAddr, "users.0.name", "sqluser"),
				),
			},
		},
	})
}

func TestAccDatabaseUsersDataSource_rejectsUnknownPrincipalType(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          usersDataSourceConfig(db, `principal_type = "external_user"`),
			PlanOnly:        true,
			ExpectError:     regexp.MustCompile(`not\s+a\s+database\s+user\s+type`),
		}},
	})
}

func TestAccDatabaseUsersDataSource_emptyDatabase(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          usersDataSourceConfig(db, ""),
			Check:           resource.TestCheckResourceAttr(usersAddr, "users.#", "0"),
		}},
	})
}

func TestAccDatabaseUsersDataSource_namesAreNotInterpolated(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "safe"); err != nil {
		t.Fatal(err)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          usersDataSourceConfig(db, `name = "x' OR '1'='1"`),
			Check:           resource.TestCheckResourceAttr(usersAddr, "users.#", "0"),
		}},
	})
}
