package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func userDataSourceConfig(t testing.TB, db, name string) string {
	return providerConfig(t) + fmt.Sprintf(`
data "conative_azuresql_database_user" "u" {
  database = %q
  name     = %q
}
`, db, name)
}

func TestAccDatabaseUserDataSource_reads(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container(t).CreateUserWithoutLogin(db, "lookup"); err != nil {
		t.Fatal(err)
	}
	sid, err := acc.Container(t).QueryStringAsSA(db, "SELECT '0x' + CONVERT(varchar(100), sid, 2) FROM sys.database_principals WHERE name = 'lookup'")
	if err != nil {
		t.Fatal(err)
	}

	const addr = "data.conative_azuresql_database_user.u"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          userDataSourceConfig(t, db, "lookup"),
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr(addr, "id", db+"/lookup"),
				resource.TestCheckResourceAttr(addr, "sid", sid),
				resource.TestCheckResourceAttr(addr, "principal_type", "SQL_USER"),
				resource.TestCheckNoResourceAttr(addr, "entra_id"),
			),
		}},
	})
}

func TestAccDatabaseUserDataSource_notFoundFails(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          userDataSourceConfig(t, db, "nobody"),
			ExpectError:     regexp.MustCompile(`(?s)not\s+found\s+in\s+database`),
		}},
	})
}

// The built-in principals are never returned, even when asked for by name.
func TestAccDatabaseUserDataSource_builtInPrincipalsAreNotUsers(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	for _, name := range []string{"dbo", "guest", "sys", "INFORMATION_SCHEMA"} {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{{
				ConfigVariables: tokenVariables(),
				Config:          userDataSourceConfig(t, db, name),
				ExpectError:     regexp.MustCompile(`(?s)not\s+found`),
			}},
		})
	}
}

func TestAccDatabaseUserDataSource_hostileName(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	name := "x'; DROP TABLE y; --]"
	if err := acc.Container(t).CreateUserWithoutLogin(db, name); err != nil {
		t.Fatal(err)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          userDataSourceConfig(t, db, name),
			Check:           resource.TestCheckResourceAttr("data.conative_azuresql_database_user.u", "name", name),
		}},
	})
}
