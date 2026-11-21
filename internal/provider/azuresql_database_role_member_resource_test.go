package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql"
)

func memberConfig(db, role, member string) string {
	return providerConfig() + fmt.Sprintf(`
resource "conative_azuresql_database_role_member" "m" {
  database = %q
  role     = %q
  member   = %q
}
`, db, role, member)
}

func isMember(db, role, member string) (bool, error) {
	n, err := acc.Container.QueryIntAsSA(db, azuresql.RoleMembershipQuery, role, member)
	return n > 0, err
}

func memberCheck(db, role, member string, want bool) resource.TestCheckFunc {
	return func(*terraform.State) error {
		got, err := isMember(db, role, member)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("%q membership of %q in %q: got %t, want %t", member, role, db, got, want)
		}
		return nil
	}
}

func TestAccDatabaseRoleMember_lifecycle(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "worker"); err != nil {
		t.Fatal(err)
	}
	// A membership the resource must never touch.
	if err := acc.Container.ExecAsSA(db, "ALTER ROLE [db_datawriter] ADD MEMBER [worker];"); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: resource.ComposeTestCheckFunc(
			memberCheck(db, "db_owner", "worker", false),
			memberCheck(db, "db_datawriter", "worker", true),
		),
		Steps: []resource.TestStep{
			{
				ConfigVariables: tokenVariables(),
				Config:          memberConfig(db, "db_owner", "worker"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("conative_azuresql_database_role_member.m", "id", db+"/db_owner/worker"),
					memberCheck(db, "db_owner", "worker", true),
					memberCheck(db, "db_datawriter", "worker", true),
					memberCheck(db, "db_datareader", "worker", false),
				),
			},
			{
				ConfigVariables:   tokenVariables(),
				Config:            memberConfig(db, "db_owner", "worker"),
				ResourceName:      "conative_azuresql_database_role_member.m",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccDatabaseRoleMember_twoRoles(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "both"); err != nil {
		t.Fatal(err)
	}
	cfg := providerConfig() + fmt.Sprintf(`
resource "conative_azuresql_database_role_member" "owner" {
  database = %[1]q
  role     = "db_owner"
  member   = "both"
}

resource "conative_azuresql_database_role_member" "reader" {
  database = %[1]q
  role     = "db_datareader"
  member   = "both"
}
`, db)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: resource.ComposeTestCheckFunc(
			memberCheck(db, "db_owner", "both", false),
			memberCheck(db, "db_datareader", "both", false),
		),
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          cfg,
			Check: resource.ComposeTestCheckFunc(
				memberCheck(db, "db_owner", "both", true),
				memberCheck(db, "db_datareader", "both", true),
			),
		}},
	})
}

func TestAccDatabaseRoleMember_rejectsRolesOutsideTheFixedSet(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	for _, role := range []string{"db_superuser", "DB_OWNER", "public", "db_owner]; DROP USER x; --"} {
		t.Run(role, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					ConfigVariables: tokenVariables(),
					Config:          memberConfig(db, role, "anyone"),
					PlanOnly:        true,
					ExpectError:     regexp.MustCompile(`is not a fixed database role`),
				}},
			})
		})
	}
}

func TestAccDatabaseRoleMember_drift(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "drifter"); err != nil {
		t.Fatal(err)
	}
	const addr = "conative_azuresql_database_role_member.m"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             memberCheck(db, "db_datareader", "drifter", false),
		Steps: []resource.TestStep{
			{
				ConfigVariables: tokenVariables(),
				Config:          memberConfig(db, "db_datareader", "drifter"),
				Check:           memberCheck(db, "db_datareader", "drifter", true),
			},
			{
				PreConfig: func() {
					if err := acc.Container.ExecAsSA(db, "ALTER ROLE [db_datareader] DROP MEMBER [drifter];"); err != nil {
						t.Fatal(err)
					}
				},
				ConfigVariables: tokenVariables(),
				Config:          memberConfig(db, "db_datareader", "drifter"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(addr, plancheck.ResourceActionCreate),
				}},
				Check: memberCheck(db, "db_datareader", "drifter", true),
			},
		},
	})
}

func TestAccDatabaseRoleMember_alreadyMemberSuggestsImport(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "veteran"); err != nil {
		t.Fatal(err)
	}
	if err := acc.Container.ExecAsSA(db, "ALTER ROLE [db_ddladmin] ADD MEMBER [veteran];"); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          memberConfig(db, "db_ddladmin", "veteran"),
			ExpectError:     regexp.MustCompile(`(?s)already\s+a\s+member.*import\s+it\s+with\s+terraform\s+import`),
		}},
	})
	if err := memberCheck(db, "db_ddladmin", "veteran", true)(nil); err != nil {
		t.Errorf("the existing membership was changed: %v", err)
	}
}

func TestAccDatabaseRoleMember_importExisting(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "imported"); err != nil {
		t.Fatal(err)
	}
	if err := acc.Container.ExecAsSA(db, "ALTER ROLE [db_backupoperator] ADD MEMBER [imported];"); err != nil {
		t.Fatal(err)
	}
	cfg := memberConfig(db, "db_backupoperator", "imported")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             memberCheck(db, "db_backupoperator", "imported", false),
		Steps: []resource.TestStep{
			{
				ConfigVariables:    tokenVariables(),
				Config:             cfg,
				ResourceName:       "conative_azuresql_database_role_member.m",
				ImportState:        true,
				ImportStateId:      azuresql.RoleMemberID(db, "db_backupoperator", "imported"),
				ImportStatePersist: true,
			},
			{
				// After the import, a plan with a matching configuration is empty.
				ConfigVariables: tokenVariables(),
				Config:          cfg,
				PlanOnly:        true,
			},
		},
	})
}

func TestAccDatabaseRoleMember_importRejectsBadIDs(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	cfg := memberConfig(db, "db_owner", "x")
	for name, id := range map[string]string{
		"too few parts":    db + "/db_owner",
		"too many parts":   db + "/db_owner/x/y",
		"not a fixed role": db + "/db_nope/x",
		"bad escape":       db + "/db_owner/x%zz",
	} {
		t.Run(name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					ConfigVariables: tokenVariables(),
					Config:          cfg,
					ResourceName:    "conative_azuresql_database_role_member.m",
					ImportState:     true,
					ImportStateId:   id,
					ExpectError:     regexp.MustCompile(`Invalid import ID`),
				}},
			})
		})
	}
}

// Names with '/' and '%' in the database and the member are written with the
// documented escapes in the import ID.
func TestAccDatabaseRoleMember_escapedImportID(t *testing.T) {
	accPreCheck(t)
	db := newDatabaseWithName(t, "acc/slash%")
	member := "team/alpha%1"
	if err := acc.Container.CreateUserWithoutLogin(db, member); err != nil {
		t.Fatal(err)
	}
	if err := acc.Container.ExecAsSA(db, "ALTER ROLE [db_datareader] ADD MEMBER [team/alpha%1];"); err != nil {
		t.Fatal(err)
	}
	id := azuresql.RoleMemberID(db, "db_datareader", member)
	if id == db+"/db_datareader/"+member {
		t.Fatalf("the ID %q was not escaped", id)
	}
	cfg := memberConfig(db, "db_datareader", member)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             memberCheck(db, "db_datareader", member, false),
		Steps: []resource.TestStep{
			{
				ConfigVariables:    tokenVariables(),
				Config:             cfg,
				ResourceName:       "conative_azuresql_database_role_member.m",
				ImportState:        true,
				ImportStateId:      id,
				ImportStatePersist: true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					a := states[0].Attributes
					if a["database"] != db || a["member"] != member || a["id"] != id {
						return fmt.Errorf("imported attributes = %v", a)
					}
					return nil
				},
			},
			{ConfigVariables: tokenVariables(), Config: cfg, PlanOnly: true},
		},
	})
}

func TestAccDatabaseRoleMember_hostileMemberNames(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container.CreateUserWithoutLogin(db, "victim"); err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{"we]ird", "o'brien; --", "x]]; DROP USER victim; --"} {
		t.Run(member, func(t *testing.T) {
			if err := acc.Container.CreateUserWithoutLogin(db, member); err != nil {
				t.Fatal(err)
			}
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				CheckDestroy:             memberCheck(db, "db_datareader", member, false),
				Steps: []resource.TestStep{{
					ConfigVariables: tokenVariables(),
					Config:          memberConfig(db, "db_datareader", member),
					Check:           memberCheck(db, "db_datareader", member, true),
				}},
			})
			if exists, err := acc.Container.UserExists(db, "victim"); err != nil || !exists {
				t.Errorf("the user %q was dropped through %q (exists=%v, err=%v)", "victim", member, exists, err)
			}
		})
	}
}

func TestAccDatabaseRoleMember_missingUserReportsEngineError(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          memberConfig(db, "db_owner", "nobody"),
			ExpectError:     regexp.MustCompile(`(?s)Cannot add.*nobody`),
		}},
	})
	if exists, err := acc.Container.UserExists(db, "nobody"); err != nil || exists {
		t.Errorf("the provider created the missing user (exists=%v, err=%v)", exists, err)
	}
}
