package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql"
)

const userAddr = "conative_azuresql_database_user.u"

func userConfig(db, name, userType, entraID string) string {
	return providerConfig() + fmt.Sprintf(`
resource "conative_azuresql_database_user" "u" {
  database = %q
  name     = %q
  type     = %q
  entra_id = %q
}
`, db, name, userType, entraID)
}

const someEntraID = "00000000-0000-0000-0000-000000000001"

func userGone(db, name string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		exists, err := acc.Container().UserExists(db, name)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("user %q still exists in database %q", name, db)
		}
		return nil
	}
}

func importFixtureStep(db, name string, cfg string) resource.TestStep {
	return resource.TestStep{
		ConfigVariables:    tokenVariables(),
		Config:             cfg,
		ResourceName:       userAddr,
		ImportState:        true,
		ImportStateId:      azuresql.UserID(db, name),
		ImportStatePersist: true,
		ImportStateCheck: func(states []*terraform.InstanceState) error {
			if len(states) != 1 {
				return fmt.Errorf("imported %d resources, want 1", len(states))
			}
			a := states[0].Attributes
			if a["name"] != name || a["database"] != db || a["id"] != azuresql.UserID(db, name) {
				return fmt.Errorf("imported attributes = %v", a)
			}
			if a["principal_type"] != "SQL_USER" || !strings.HasPrefix(a["sid"], "0x") {
				return fmt.Errorf("principal_type = %q, sid = %q", a["principal_type"], a["sid"])
			}
			if v, ok := a["entra_id"]; ok && v != "" {
				return fmt.Errorf("entra_id = %q, want none for a SQL user", v)
			}
			if v, ok := a["type"]; ok && v != "" {
				return fmt.Errorf("type = %q, want none after an import", v)
			}
			return nil
		},
	}
}

func TestAccDatabaseUser_existsSuggestsImport(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container().CreateUserWithoutLogin(db, "dup"); err != nil {
		t.Fatal(err)
	}
	sidBefore, err := acc.Container().QueryStringAsSA(db, "SELECT CONVERT(varchar(100), sid, 1) FROM sys.database_principals WHERE name = 'dup'")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          userConfig(db, "dup", "application", someEntraID),
			ExpectError:     regexp.MustCompile(`(?s)already\s+exists\s+in\s+database.*import\s+it\s+with\s+terraform\s+import`),
		}},
	})

	sidAfter, err := acc.Container().QueryStringAsSA(db, "SELECT CONVERT(varchar(100), sid, 1) FROM sys.database_principals WHERE name = 'dup'")
	if err != nil || sidAfter != sidBefore {
		t.Errorf("the existing user changed: sid %q -> %q (%v)", sidBefore, sidAfter, err)
	}
}

// A container cannot create external users, so an imported SQL user stands in for a
// principal whose identity differs from the configuration: the plan must replace it
// instead of adopting it. The replacement is executed here: the drop succeeds, and
// creating an external user then fails because this engine does not support it.
func TestAccDatabaseUser_importShowsMismatch(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container().CreateUserWithoutLogin(db, "imp"); err != nil {
		t.Fatal(err)
	}
	cfg := userConfig(db, "imp", "application", someEntraID)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			importFixtureStep(db, "imp", cfg),
			{
				ConfigVariables: tokenVariables(),
				Config:          cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(userAddr, plancheck.ResourceActionDestroyBeforeCreate),
				}},
				ExpectError: regexp.MustCompile(`Cannot create`),
			},
		},
	})
	if err := userGone(db, "imp")(nil); err != nil {
		t.Errorf("the replacement did not drop the imported user first: %v", err)
	}
}

func TestAccDatabaseUser_destroyDropsUser(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container().CreateUserWithoutLogin(db, "doomed"); err != nil {
		t.Fatal(err)
	}
	cfg := userConfig(db, "doomed", "application", someEntraID)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             userGone(db, "doomed"),
		Steps:                    []resource.TestStep{importFixtureStep(db, "doomed", cfg)},
	})
}

func TestAccDatabaseUser_destroyRefusedWhenOwningSchema(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container().CreateUserWithoutLogin(db, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := acc.Container().ExecAsSA(db, "CREATE SCHEMA [owned] AUTHORIZATION [owner];"); err != nil {
		t.Fatal(err)
	}
	cfg := userConfig(db, "owner", "application", someEntraID)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             userGone(db, "owner"),
		Steps: []resource.TestStep{
			importFixtureStep(db, "owner", cfg),
			{
				ConfigVariables: tokenVariables(),
				Config:          cfg,
				Destroy:         true,
				ExpectError:     regexp.MustCompile(`(?s)Cannot drop.*owner`),
			},
			{
				// The user is still there; hand the schema back so the final cleanup works.
				PreConfig: func() {
					exists, err := acc.Container().UserExists(db, "owner")
					if err != nil || !exists {
						t.Errorf("the user was dropped although it owns a schema (exists=%v, err=%v)", exists, err)
					}
					if err := acc.Container().ExecAsSA(db, "ALTER AUTHORIZATION ON SCHEMA::[owned] TO [dbo];"); err != nil {
						t.Errorf("cannot release the schema: %v", err)
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

func TestAccDatabaseUser_drift(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container().CreateUserWithoutLogin(db, "vanishing"); err != nil {
		t.Fatal(err)
	}
	cfg := userConfig(db, "vanishing", "application", someEntraID)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			importFixtureStep(db, "vanishing", cfg),
			{
				PreConfig: func() {
					if err := acc.Container().ExecAsSA(db, "DROP USER [vanishing];"); err != nil {
						t.Fatal(err)
					}
				},
				ConfigVariables: tokenVariables(),
				Config:          cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(userAddr, plancheck.ResourceActionCreate),
				}},
				// Creating an external user is not possible in this engine; the plan is
				// what is under test.
				ExpectError: regexp.MustCompile(`Cannot create`),
			},
		},
	})
}

func TestAccDatabaseUser_hostileNames(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	names := []string{"we]ird", "o'brien; --", "x]]; DROP TABLE y; --", "with space", "naïve-名前", strings.Repeat("n", 128)}
	for _, n := range names {
		if err := acc.Container().CreateUserWithoutLogin(db, n); err != nil {
			t.Fatalf("cannot create fixture %q: %v", n, err)
		}
	}

	for i, n := range names {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			CheckDestroy:             userGone(db, n),
			Steps:                    []resource.TestStep{importFixtureStep(db, n, userConfig(db, n, "application", someEntraID))},
		})
		// Each test case destroyed its imported user; the others are untouched.
		for _, other := range names[i+1:] {
			if exists, err := acc.Container().UserExists(db, other); err != nil || !exists {
				t.Fatalf("user %q disappeared (exists=%v, err=%v)", other, exists, err)
			}
		}
	}
}

func TestAccDatabaseUser_rejectsInvalidConfiguration(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	long := strings.Repeat("n", 129)
	tests := map[string]struct {
		cfg   string
		match string
	}{
		"unknown type":    {userConfig(db, "u", "robot", someEntraID), `is not a valid type`},
		"bad entra id":    {userConfig(db, "u", "user", "not-a-guid"), `must be a GUID`},
		"empty name":      {userConfig(db, "", "user", someEntraID), `must be 1 to 128 characters`},
		"over-long name":  {userConfig(db, long, "user", someEntraID), `must be 1 to 128 characters`},
		"empty database":  {userConfig("", "u", "user", someEntraID), `must be 1 to 128 characters`},
		"braced entra id": {userConfig(db, "u", "user", "{"+someEntraID+"}"), `must be a GUID`},
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

// The byte order the provider derives for a security identifier is the byte order the
// engine uses for a uniqueidentifier.
func TestAccSIDMatchesEngineGUIDBytes(t *testing.T) {
	accPreCheck(t)
	db, err := acc.Container().SA("master")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"00112233-4455-6677-8899-aabbccddeeff",
		"00000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
		"01234567-89ab-cdef-0123-456789abcdef",
		"d3b07384-d113-4ec6-a7b0-7c5e2a3f9f01",
	} {
		var engine []byte
		if err := db.QueryRow("SELECT CAST(CAST(@p1 AS uniqueidentifier) AS varbinary(16))", id).Scan(&engine); err != nil {
			t.Fatal(err)
		}
		mine, err := azuresql.SIDFromEntraID(id)
		if err != nil {
			t.Fatal(err)
		}
		if azuresql.SIDHex(mine) != azuresql.SIDHex(engine) {
			t.Errorf("%s: derived %s, engine %s", id, azuresql.SIDHex(mine), azuresql.SIDHex(engine))
		}
		back, ok := azuresql.EntraIDFromSID(engine)
		if !ok || back != id {
			t.Errorf("%s: reverse derivation gave %q", id, back)
		}
	}
}
