package azuresql

import (
	"strings"
	"testing"
)

func mustSID(t *testing.T, id string) []byte {
	t.Helper()
	sid, err := SIDFromEntraID(id)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func TestCreateUserStmt(t *testing.T) {
	t.Parallel()

	sid := mustSID(t, vectorID)
	tests := []struct {
		name, userType, want string
	}{
		{"app-orders", "application", "CREATE USER [app-orders] WITH SID = 0x33221100554477668899AABBCCDDEEFF, TYPE = E;"},
		{"jane", "user", "CREATE USER [jane] WITH SID = 0x33221100554477668899AABBCCDDEEFF, TYPE = E;"},
		{"ops", "group", "CREATE USER [ops] WITH SID = 0x33221100554477668899AABBCCDDEEFF, TYPE = X;"},
		{"ops]; DROP TABLE x; --", "group", "CREATE USER [ops]]; DROP TABLE x; --] WITH SID = 0x33221100554477668899AABBCCDDEEFF, TYPE = X;"},
		{"o'brien", "user", "CREATE USER [o'brien] WITH SID = 0x33221100554477668899AABBCCDDEEFF, TYPE = E;"},
	}
	for _, tt := range tests {
		got, err := CreateUserStmt(tt.name, tt.userType, sid)
		if err != nil || got != tt.want {
			t.Errorf("CreateUserStmt(%q, %q) = %q, %v; want %q", tt.name, tt.userType, got, err, tt.want)
		}
	}

	if _, err := CreateUserStmt("", "user", sid); err == nil {
		t.Error("empty name accepted")
	}
	if _, err := CreateUserStmt("x", "robot", sid); err == nil {
		t.Error("unknown type accepted")
	}
	if _, err := CreateUserStmt("x", "user", sid[:8]); err == nil {
		t.Error("short SID accepted")
	}
}

func TestUserStatementsAndQueries(t *testing.T) {
	t.Parallel()

	got, err := DropUserStmt("ops]; DROP TABLE x; --")
	if err != nil || got != "DROP USER [ops]]; DROP TABLE x; --];" {
		t.Errorf("DropUserStmt = %q, %v", got, err)
	}
	if _, err := DropUserStmt(strings.Repeat("a", 129)); err == nil {
		t.Error("over-long name accepted")
	}

	exact := map[string]string{
		PrincipalExistsQuery:    "SELECT COUNT(*) FROM sys.database_principals WHERE name = @p1;",
		ReadUserQuery:           "SELECT name, type, type_desc, sid FROM sys.database_principals WHERE name = @p1 AND type IN ('S', 'U', 'G', 'E', 'X', 'C', 'K');",
		DataSourceUserQuery:     "SELECT name, type, type_desc, sid FROM sys.database_principals WHERE name = @p1 AND principal_id > 4 AND type IN ('S', 'U', 'G', 'E', 'X', 'C', 'K');",
		DataSourceUsersQuery:    "SELECT name, type, type_desc, sid FROM sys.database_principals WHERE principal_id > 4 AND type IN ('S', 'U', 'G', 'E', 'X', 'C', 'K') AND (@p1 IS NULL OR name = @p1) AND (@p2 IS NULL OR type_desc = @p2) ORDER BY name;",
		RoleMembershipQuery:     "SELECT COUNT(*) FROM sys.database_role_members AS rm JOIN sys.database_principals AS r ON r.principal_id = rm.role_principal_id JOIN sys.database_principals AS m ON m.principal_id = rm.member_principal_id WHERE r.name = @p1 AND m.name = @p2;",
		DatabasePermissionQuery: "SELECT state FROM sys.database_permissions WHERE class = 0 AND major_id = 0 AND grantee_principal_id = DATABASE_PRINCIPAL_ID(@p1) AND permission_name = @p2;",
		SchemaPermissionQuery:   "SELECT state FROM sys.database_permissions WHERE class = 3 AND major_id = SCHEMA_ID(@p3) AND grantee_principal_id = DATABASE_PRINCIPAL_ID(@p1) AND permission_name = @p2;",
	}
	for got, want := range exact {
		if got != want {
			t.Errorf("query = %q, want %q", got, want)
		}
	}
}

func TestRoleMemberStatements(t *testing.T) {
	t.Parallel()

	add, err := AddRoleMemberStmt("db_owner", "u")
	if err != nil || add != "ALTER ROLE [db_owner] ADD MEMBER [u];" {
		t.Errorf("AddRoleMemberStmt = %q, %v", add, err)
	}
	drop, err := DropRoleMemberStmt("db_datareader", "a]b")
	if err != nil || drop != "ALTER ROLE [db_datareader] DROP MEMBER [a]]b];" {
		t.Errorf("DropRoleMemberStmt = %q, %v", drop, err)
	}

	for _, role := range []string{"db_superuser", "DB_OWNER", "db_owner]; DROP TABLE x; --", ""} {
		if s, err := AddRoleMemberStmt(role, "u"); err == nil {
			t.Errorf("AddRoleMemberStmt(%q) built %q", role, s)
		}
		if s, err := DropRoleMemberStmt(role, "u"); err == nil {
			t.Errorf("DropRoleMemberStmt(%q) built %q", role, s)
		}
	}
	if _, err := AddRoleMemberStmt("db_owner", ""); err == nil {
		t.Error("empty member accepted")
	}
}

func TestPermissionStatements(t *testing.T) {
	t.Parallel()

	dbGrant := Permission{Principal: "r", State: "GRANT", Permission: "VIEW DEFINITION"}
	schemaDeny := Permission{Principal: "r", State: "DENY", Permission: "SELECT", Schema: "sales"}

	tests := []struct {
		name string
		got  func() (string, error)
		want string
	}{
		{"grant database", func() (string, error) { return GrantStmt(dbGrant) }, "GRANT VIEW DEFINITION TO [r];"},
		{"deny schema", func() (string, error) { return GrantStmt(schemaDeny) }, "DENY SELECT ON SCHEMA::[sales] TO [r];"},
		{"revoke database", func() (string, error) { return RevokeStmt(dbGrant) }, "REVOKE VIEW DEFINITION FROM [r];"},
		{"revoke schema", func() (string, error) { return RevokeStmt(schemaDeny) }, "REVOKE SELECT ON SCHEMA::[sales] FROM [r];"},
		{
			"hostile names",
			func() (string, error) {
				return GrantStmt(Permission{Principal: "p]; DROP USER x; --", State: "GRANT", Permission: "SELECT", Schema: "s]]t"})
			},
			"GRANT SELECT ON SCHEMA::[s]]]]t] TO [p]]; DROP USER x; --];",
		},
		{
			"hostile revoke",
			func() (string, error) {
				return RevokeStmt(Permission{Principal: "a'b", Permission: "CONTROL", Schema: "x]"})
			},
			"REVOKE CONTROL ON SCHEMA::[x]]] FROM [a'b];",
		},
	}
	for _, tt := range tests {
		got, err := tt.got()
		if err != nil || got != tt.want {
			t.Errorf("%s = %q, %v; want %q", tt.name, got, err, tt.want)
		}
	}

	// No statement ever carries a grant option, a cascade or an impersonation clause.
	for _, perm := range append(DatabasePermissions(), SchemaPermissions()...) {
		for _, schema := range []string{"", "s"} {
			for _, state := range []string{"GRANT", "DENY"} {
				p := Permission{Principal: "u", State: state, Permission: perm, Schema: schema}
				if ValidatePermission(p.Scope(), perm) != nil {
					continue
				}
				g, err1 := GrantStmt(p)
				r, err2 := RevokeStmt(p)
				if err1 != nil || err2 != nil {
					t.Fatalf("unexpected error for %+v: %v %v", p, err1, err2)
				}
				for _, s := range []string{g, r} {
					for _, banned := range []string{"WITH GRANT OPTION", "CASCADE", " AS ", "GRANT OPTION FOR"} {
						if strings.Contains(s, banned) {
							t.Errorf("%q contains %q", s, banned)
						}
					}
				}
			}
		}
	}

	bad := []Permission{
		{Principal: "u", State: "REVOKE", Permission: "SELECT"},
		{Principal: "u", State: "grant", Permission: "SELECT"},
		{Principal: "u", State: "GRANT", Permission: "CREATE TABLE", Schema: "s"},
		{Principal: "u", State: "GRANT", Permission: "SELECT; DROP TABLE x"},
		{Principal: "", State: "GRANT", Permission: "SELECT"},
		{Principal: "u", State: "GRANT", Permission: "SELECT", Schema: strings.Repeat("s", 129)},
	}
	for _, p := range bad {
		if s, err := GrantStmt(p); err == nil {
			t.Errorf("GrantStmt(%+v) built %q", p, s)
		}
	}
	if s, err := RevokeStmt(Permission{Principal: "u", Permission: "nonsense"}); err == nil {
		t.Errorf("RevokeStmt accepted an unknown permission: %q", s)
	}
}

func TestPermissionQuery(t *testing.T) {
	t.Parallel()

	q, args := PermissionQuery(Permission{Principal: "r", Permission: "CONNECT"})
	if q != DatabasePermissionQuery || len(args) != 2 || args[0] != "r" || args[1] != "CONNECT" {
		t.Errorf("database-level query = %q %v", q, args)
	}
	q, args = PermissionQuery(Permission{Principal: "r", Permission: "SELECT", Schema: "sales"})
	if q != SchemaPermissionQuery || len(args) != 3 || args[2] != "sales" {
		t.Errorf("schema-level query = %q %v", q, args)
	}
}
