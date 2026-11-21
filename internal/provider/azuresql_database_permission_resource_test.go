package provider

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql"
)

const permAddr = "conative_azuresql_database_permission.p"

func permConfig(db, principal, state, permission, schema string) string {
	schemaLine := ""
	if schema != "" {
		schemaLine = fmt.Sprintf("schema     = %q", schema)
	}
	return providerConfig() + fmt.Sprintf(`
resource "conative_azuresql_database_permission" "p" {
  database   = %q
  principal  = %q
  state      = %q
  permission = %q
  %s
}
`, db, principal, state, permission, schemaLine)
}

// reportedState reads the state code the engine holds for a permission, "" for none.
func reportedState(db string, p azuresql.Permission) (string, error) {
	query, args := azuresql.PermissionQuery(p)
	s, err := acc.Container.QueryStringAsSA(db, query, args...)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return s, err
}

func permissionCheck(db string, p azuresql.Permission, want string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		got, err := reportedState(db, p)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("permission %s of %q in %q: engine reports %q, want %q", p.Permission, p.Principal, db, got, want)
		}
		return nil
	}
}

// permissionRows lists "CLASS:PERMISSION:STATE" for everything a principal holds, so a
// test can prove that nothing besides the declared permission changed.
func permissionRows(db, principal string) (string, error) {
	conn, err := acc.Container.SA(db)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	rows, err := conn.Query(`SELECT class, permission_name, state FROM sys.database_permissions
		WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID(@p1) ORDER BY class, major_id, permission_name`, principal)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var class int
		var name, state string
		if err := rows.Scan(&class, &name, &state); err != nil {
			return "", err
		}
		out = append(out, fmt.Sprintf("%d:%s:%s", class, name, state))
	}
	return strings.Join(out, ","), rows.Err()
}

func TestAccDatabasePermission_databaseLevel(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "reader"); err != nil {
		t.Fatal(err)
	}
	p := azuresql.Permission{Principal: "reader", Permission: "VIEW DEFINITION"}
	before, err := permissionRows(db, "reader")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			if err := permissionCheck(db, p, "")(s); err != nil {
				return err
			}
			after, err := permissionRows(db, "reader")
			if err != nil {
				return err
			}
			if after != before {
				return fmt.Errorf("destroy changed other permissions: %q -> %q", before, after)
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				ConfigVariables: tokenVariables(),
				Config:          permConfig(db, "reader", "GRANT", "VIEW DEFINITION", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(permAddr, "id", db+"/reader/GRANT/VIEW DEFINITION"),
					resource.TestCheckResourceAttr(permAddr, "state", "GRANT"),
					resource.TestCheckNoResourceAttr(permAddr, "schema"),
					permissionCheck(db, p, "G"),
					func(*terraform.State) error {
						now, err := permissionRows(db, "reader")
						if err != nil {
							return err
						}
						if now != before+",0:VIEW DEFINITION:G" {
							return fmt.Errorf("permissions after apply = %q (before: %q)", now, before)
						}
						return nil
					},
				),
			},
			{
				ConfigVariables:   tokenVariables(),
				Config:            permConfig(db, "reader", "GRANT", "VIEW DEFINITION", ""),
				ResourceName:      permAddr,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccDatabasePermission_schemaLevelDeny(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "analyst"); err != nil {
		t.Fatal(err)
	}
	if err := acc.Container.ExecAsSA(db, "CREATE SCHEMA [sales];", "CREATE SCHEMA [hr];"); err != nil {
		t.Fatal(err)
	}
	sales := azuresql.Permission{Principal: "analyst", Permission: "SELECT", Schema: "sales"}
	hr := azuresql.Permission{Principal: "analyst", Permission: "SELECT", Schema: "hr"}
	database := azuresql.Permission{Principal: "analyst", Permission: "SELECT"}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             permissionCheck(db, sales, ""),
		Steps: []resource.TestStep{
			{
				ConfigVariables: tokenVariables(),
				Config:          permConfig(db, "analyst", "DENY", "SELECT", "sales"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(permAddr, "id", db+"/analyst/DENY/SELECT/sales"),
					resource.TestCheckResourceAttr(permAddr, "schema", "sales"),
					permissionCheck(db, sales, "D"),
					permissionCheck(db, hr, ""),
					permissionCheck(db, database, ""),
				),
			},
			{
				ConfigVariables:   tokenVariables(),
				Config:            permConfig(db, "analyst", "DENY", "SELECT", "sales"),
				ResourceName:      permAddr,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccDatabasePermission_rejectsInvalidPermissions(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	tests := map[string]struct {
		cfg   string
		match string
	}{
		"database permission on a schema": {permConfig(db, "u", "GRANT", "CREATE TABLE", "sales"), `not a permission that can be granted on a schema`},
		"lower case":                      {permConfig(db, "u", "GRANT", "view definition", ""), `upper case`},
		"unknown":                         {permConfig(db, "u", "GRANT", "FLY", ""), `not a permission that can be granted on a database`},
		"injection attempt":               {permConfig(db, "u", "GRANT", "SELECT TO [x]; DROP TABLE y; --", ""), `not a permission`},
		"bad state":                       {permConfig(db, "u", "REVOKE", "SELECT", ""), `not\s+a\s+valid\s+state`},
		"lower case state":                {permConfig(db, "u", "grant", "SELECT", ""), `not\s+a\s+valid\s+state`},
		"empty principal":                 {permConfig(db, "", "GRANT", "SELECT", ""), `must be 1 to 128 characters`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					ConfigVariables: tokenVariables(),
					Config:          tt.cfg,
					PlanOnly:        true,
					ExpectError:     regexp.MustCompile(tt.match),
				}},
			})
		})
	}
}

func TestAccDatabasePermission_driftRevokedOutsideTerraform(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "drifter"); err != nil {
		t.Fatal(err)
	}
	p := azuresql.Permission{Principal: "drifter", Permission: "VIEW DEFINITION"}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             permissionCheck(db, p, ""),
		Steps: []resource.TestStep{
			{
				ConfigVariables: tokenVariables(),
				Config:          permConfig(db, "drifter", "GRANT", "VIEW DEFINITION", ""),
				Check:           permissionCheck(db, p, "G"),
			},
			{
				PreConfig: func() {
					if err := acc.Container.ExecAsSA(db, "REVOKE VIEW DEFINITION FROM [drifter];"); err != nil {
						t.Fatal(err)
					}
				},
				ConfigVariables: tokenVariables(),
				Config:          permConfig(db, "drifter", "GRANT", "VIEW DEFINITION", ""),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(permAddr, plancheck.ResourceActionCreate),
				}},
				Check: permissionCheck(db, p, "G"),
			},
		},
	})
}

func TestAccDatabasePermission_driftChangedToDeny(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "flipper"); err != nil {
		t.Fatal(err)
	}
	p := azuresql.Permission{Principal: "flipper", Permission: "VIEW DEFINITION"}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             permissionCheck(db, p, ""),
		Steps: []resource.TestStep{
			{
				ConfigVariables: tokenVariables(),
				Config:          permConfig(db, "flipper", "GRANT", "VIEW DEFINITION", ""),
				Check:           permissionCheck(db, p, "G"),
			},
			{
				PreConfig: func() {
					if err := acc.Container.ExecAsSA(db, "DENY VIEW DEFINITION TO [flipper];"); err != nil {
						t.Fatal(err)
					}
				},
				ConfigVariables: tokenVariables(),
				Config:          permConfig(db, "flipper", "GRANT", "VIEW DEFINITION", ""),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(permAddr, plancheck.ResourceActionDestroyBeforeCreate),
				}},
				Check: permissionCheck(db, p, "G"),
			},
		},
	})
}

// A permission granted with grant option outside Terraform is reported as such, shows
// as a difference, and is never revoked with CASCADE: the replacement fails until
// the grant option is removed by whoever set it.
func TestAccDatabasePermission_driftGrantOption(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "grantor"); err != nil {
		t.Fatal(err)
	}
	p := azuresql.Permission{Principal: "grantor", Permission: "VIEW DEFINITION"}
	cfg := permConfig(db, "grantor", "GRANT", "VIEW DEFINITION", "")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             permissionCheck(db, p, ""),
		Steps: []resource.TestStep{
			{ConfigVariables: tokenVariables(), Config: cfg, Check: permissionCheck(db, p, "G")},
			{
				PreConfig: func() {
					if err := acc.Container.ExecAsSA(db, "GRANT VIEW DEFINITION TO [grantor] WITH GRANT OPTION;"); err != nil {
						t.Fatal(err)
					}
				},
				ConfigVariables:    tokenVariables(),
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check:              resource.TestCheckResourceAttr(permAddr, "state", "GRANT_WITH_GRANT_OPTION"),
			},
			{
				ConfigVariables: tokenVariables(),
				Config:          cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(permAddr, plancheck.ResourceActionDestroyBeforeCreate),
				}},
				ExpectError: regexp.MustCompile(`Cannot revoke`),
			},
			{
				// Whoever set the grant option removes it; the final cleanup then works.
				PreConfig: func() {
					if got, err := reportedState(db, p); err != nil || got != "W" {
						t.Errorf("the grant option was changed by the failed replacement: %q (%v)", got, err)
					}
					if err := acc.Container.ExecAsSA(db, "REVOKE VIEW DEFINITION FROM [grantor] CASCADE;"); err != nil {
						t.Errorf("cannot remove the grant option: %v", err)
					}
				},
				ConfigVariables:    tokenVariables(),
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccDatabasePermission_existingPermissionSuggestsImport(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "holder"); err != nil {
		t.Fatal(err)
	}
	if err := acc.Container.ExecAsSA(db, "DENY SELECT TO [holder];"); err != nil {
		t.Fatal(err)
	}

	// Granting over an existing DENY would silently replace a declaration the provider does not own.
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          permConfig(db, "holder", "GRANT", "SELECT", ""),
			ExpectError:     regexp.MustCompile(`(?s)already\s+holds\s+permission.*import\s+it\s+with\s+terraform\s+import`),
		}},
	})
	if err := permissionCheck(db, azuresql.Permission{Principal: "holder", Permission: "SELECT"}, "D")(nil); err != nil {
		t.Errorf("the existing DENY was changed: %v", err)
	}
}

// Every new database user holds CONNECT already, so declaring it means importing it.
func TestAccDatabasePermission_implicitConnectNeedsImport(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "fresh"); err != nil {
		t.Fatal(err)
	}
	p := azuresql.Permission{Principal: "fresh", Permission: "CONNECT"}
	cfg := permConfig(db, "fresh", "GRANT", "CONNECT", "")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				ConfigVariables: tokenVariables(),
				Config:          cfg,
				ExpectError:     regexp.MustCompile(`(?s)already\s+holds.*import\s+it`),
			},
			{
				ConfigVariables:    tokenVariables(),
				Config:             cfg,
				ResourceName:       permAddr,
				ImportState:        true,
				ImportStateId:      azuresql.PermissionID(db, "fresh", "GRANT", "CONNECT", ""),
				ImportStatePersist: true,
			},
			{ConfigVariables: tokenVariables(), Config: cfg, PlanOnly: true},
		},
		CheckDestroy: permissionCheck(db, p, ""),
	})
}

func TestAccDatabasePermission_importBothForms(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "importer"); err != nil {
		t.Fatal(err)
	}
	if err := acc.Container.ExecAsSA(db, "CREATE SCHEMA [sales];", "GRANT VIEW DEFINITION TO [importer];", "DENY SELECT ON SCHEMA::[sales] TO [importer];"); err != nil {
		t.Fatal(err)
	}
	dbLevel := azuresql.Permission{Principal: "importer", Permission: "VIEW DEFINITION"}
	schemaLevel := azuresql.Permission{Principal: "importer", Permission: "SELECT", Schema: "sales"}

	t.Run("database level", func(t *testing.T) {
		cfg := permConfig(db, "importer", "GRANT", "VIEW DEFINITION", "")
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			CheckDestroy:             permissionCheck(db, dbLevel, ""),
			Steps: []resource.TestStep{
				{
					ConfigVariables: tokenVariables(), Config: cfg, ResourceName: permAddr, ImportState: true,
					ImportStateId: db + "/importer/GRANT/VIEW DEFINITION", ImportStatePersist: true,
				},
				{ConfigVariables: tokenVariables(), Config: cfg, PlanOnly: true},
			},
		})
	})
	t.Run("schema level", func(t *testing.T) {
		cfg := permConfig(db, "importer", "DENY", "SELECT", "sales")
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			CheckDestroy:             permissionCheck(db, schemaLevel, ""),
			Steps: []resource.TestStep{
				{
					ConfigVariables: tokenVariables(), Config: cfg, ResourceName: permAddr, ImportState: true,
					ImportStateId: db + "/importer/DENY/SELECT/sales", ImportStatePersist: true,
				},
				{ConfigVariables: tokenVariables(), Config: cfg, PlanOnly: true},
			},
		})
	})
}

func TestAccDatabasePermission_importRejectsBadIDs(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	cfg := permConfig(db, "u", "GRANT", "SELECT", "")
	for name, id := range map[string]string{
		"too few parts":              db + "/u/GRANT",
		"too many parts":             db + "/u/GRANT/SELECT/s/x",
		"revoke is not a state":      db + "/u/REVOKE/SELECT",
		"unknown permission":         db + "/u/GRANT/FLY",
		"database permission on one": db + "/u/GRANT/CREATE TABLE/sales",
	} {
		t.Run(name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					ConfigVariables: tokenVariables(),
					Config:          cfg,
					ResourceName:    permAddr,
					ImportState:     true,
					ImportStateId:   id,
					ExpectError:     regexp.MustCompile(`Invalid import ID`),
				}},
			})
		})
	}
}

func TestAccDatabasePermission_hostileNames(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	hostile := "we]ird'; DROP USER victim; --"
	if err := acc.Container.CreateUserWithoutLogin(db, "victim"); err != nil {
		t.Fatal(err)
	}
	if err := acc.Container.CreateUserWithoutLogin(db, hostile); err != nil {
		t.Fatal(err)
	}
	schemaName := "s]chema'; --"
	if err := acc.Container.ExecAsSA(db, "CREATE SCHEMA [s]]chema'; --];"); err != nil {
		t.Fatal(err)
	}
	p := azuresql.Permission{Principal: hostile, Permission: "SELECT", Schema: schemaName}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             permissionCheck(db, p, ""),
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          permConfig(db, hostile, "GRANT", "SELECT", schemaName),
			Check:           permissionCheck(db, p, "G"),
		}},
	})
	if exists, err := acc.Container.UserExists(db, "victim"); err != nil || !exists {
		t.Errorf("the user victim was dropped (exists=%v, err=%v)", exists, err)
	}
}

func TestAccDatabasePermission_missingPrincipalReportsEngineError(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          permConfig(db, "ghost", "GRANT", "VIEW DEFINITION", ""),
			ExpectError:     regexp.MustCompile(`(?s)Cannot set.*ghost`),
		}},
	})
	if exists, err := acc.Container.UserExists(db, "ghost"); err != nil || exists {
		t.Errorf("the provider created the missing principal (exists=%v, err=%v)", exists, err)
	}
}

// Guards the static allowlists against typos: every name must be known to the engine.
// A newer engine may know more names than the lists hold.
func TestAccPermissionAllowlistKnownToEngine(t *testing.T) {
	accPreCheck(t)
	conn, err := acc.Container.SA("master")
	if err != nil {
		t.Fatal(err)
	}
	for class, names := range map[string][]string{
		"DATABASE": azuresql.DatabasePermissions(),
		"SCHEMA":   azuresql.SchemaPermissions(),
	} {
		known := engineKnownPermissions(t, conn, class)
		for _, n := range names {
			if !known[n] {
				t.Errorf("%s permission %q is not known to the engine", class, n)
			}
		}
	}
}

func engineKnownPermissions(t *testing.T, conn *sql.DB, class string) map[string]bool {
	t.Helper()
	rows, err := conn.Query("SELECT permission_name FROM sys.fn_builtin_permissions(DEFAULT) WHERE class_desc = @p1", class)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	known := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		known[n] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(known) == 0 {
		t.Fatalf("the engine lists no %s permissions", class)
	}
	return known
}
