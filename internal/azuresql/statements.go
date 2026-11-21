package azuresql

import (
	"fmt"
	"strings"
)

// Queries use driver parameters (@p1, @p2, ...). DDL cannot take parameters, so it is
// built only from fixed keywords, QuoteName output, allowlisted role and permission
// names, and the SID literal produced from parsed GUID bytes.

const userTypesList = "'S', 'U', 'G', 'E', 'X', 'C', 'K'"

// Queries on sys.database_principals.
const (
	// PrincipalExistsQuery counts principals of any kind with a name (parameter: name).
	PrincipalExistsQuery = "SELECT COUNT(*) FROM sys.database_principals WHERE name = @p1;"

	// ReadUserQuery reads one user by name (parameter: name).
	ReadUserQuery = "SELECT name, type, type_desc, sid FROM sys.database_principals WHERE name = @p1 AND type IN (" + userTypesList + ");"

	// DataSourceUserQuery reads one user by name for the data source, leaving out
	// the built-in principals (parameter: name).
	DataSourceUserQuery = "SELECT name, type, type_desc, sid FROM sys.database_principals WHERE name = @p1 AND principal_id > 4 AND type IN (" + userTypesList + ");"

	// DataSourceUsersQuery lists users, leaving out the built-in principals
	// (parameters: name or NULL, type_desc or NULL).
	DataSourceUsersQuery = "SELECT name, type, type_desc, sid FROM sys.database_principals WHERE principal_id > 4 AND type IN (" + userTypesList + ") AND (@p1 IS NULL OR name = @p1) AND (@p2 IS NULL OR type_desc = @p2) ORDER BY name;"

	// RoleMembershipQuery counts the memberships of a member in a role
	// (parameters: role, member).
	RoleMembershipQuery = "SELECT COUNT(*) FROM sys.database_role_members AS rm JOIN sys.database_principals AS r ON r.principal_id = rm.role_principal_id JOIN sys.database_principals AS m ON m.principal_id = rm.member_principal_id WHERE r.name = @p1 AND m.name = @p2;"

	// DatabasePermissionQuery reads the state codes of a database-level permission
	// (parameters: principal, permission).
	DatabasePermissionQuery = "SELECT state FROM sys.database_permissions WHERE class = 0 AND major_id = 0 AND grantee_principal_id = DATABASE_PRINCIPAL_ID(@p1) AND permission_name = @p2;"

	// SchemaPermissionQuery reads the state codes of a schema-level permission
	// (parameters: principal, permission, schema).
	SchemaPermissionQuery = "SELECT state FROM sys.database_permissions WHERE class = 3 AND major_id = SCHEMA_ID(@p3) AND grantee_principal_id = DATABASE_PRINCIPAL_ID(@p1) AND permission_name = @p2;"
)

// CreateUserStmt returns the statement that creates a contained user of external type
// with a security identifier: TYPE = E for an application or a user, TYPE = X for a
// group.
func CreateUserStmt(name, userType string, sid []byte) (string, error) {
	q, err := QuoteName(name)
	if err != nil {
		return "", fmt.Errorf("user name %w", err)
	}
	var kind string
	switch userType {
	case UserTypeApplication, UserTypeUser:
		kind = "E"
	case UserTypeGroup:
		kind = "X"
	default:
		return "", ValidateUserType(userType)
	}
	if len(sid) != 16 {
		return "", fmt.Errorf("security identifier must be 16 bytes, got %d", len(sid))
	}
	return fmt.Sprintf("CREATE USER %s WITH SID = %s, TYPE = %s;", q, SIDHex(sid), kind), nil
}

// DropUserStmt returns the statement that drops a user. It never forces.
func DropUserStmt(name string) (string, error) {
	q, err := QuoteName(name)
	if err != nil {
		return "", fmt.Errorf("user name %w", err)
	}
	return "DROP USER " + q + ";", nil
}

// AddRoleMemberStmt returns the statement that adds member to a fixed database role.
func AddRoleMemberStmt(role, member string) (string, error) {
	return roleMemberStmt("ADD", role, member)
}

// DropRoleMemberStmt returns the statement that removes member from a fixed database role.
func DropRoleMemberStmt(role, member string) (string, error) {
	return roleMemberStmt("DROP", role, member)
}

func roleMemberStmt(verb, role, member string) (string, error) {
	if err := ValidateRole(role); err != nil {
		return "", err
	}
	qr, err := QuoteName(role)
	if err != nil {
		return "", fmt.Errorf("role %w", err)
	}
	qm, err := QuoteName(member)
	if err != nil {
		return "", fmt.Errorf("member name %w", err)
	}
	return fmt.Sprintf("ALTER ROLE %s %s MEMBER %s;", qr, verb, qm), nil
}

// Permission identifies one permission of one principal on the database or on one
// schema. Schema is empty for the database level.
type Permission struct {
	Principal  string
	State      string // GRANT or DENY
	Permission string
	Schema     string
}

// Scope returns the securable class of the permission.
func (p Permission) Scope() Scope {
	if p.Schema == "" {
		return ScopeDatabase
	}
	return ScopeSchema
}

// PermissionQuery returns the query that reads the state of a permission and the
// arguments to run it with.
func PermissionQuery(p Permission) (query string, args []any) {
	if p.Schema == "" {
		return DatabasePermissionQuery, []any{p.Principal, p.Permission}
	}
	return SchemaPermissionQuery, []any{p.Principal, p.Permission, p.Schema}
}

// GrantStmt returns the GRANT or DENY statement for p. It never grants with grant
// option.
func GrantStmt(p Permission) (string, error) {
	if err := ValidatePermissionState(p.State); err != nil {
		return "", err
	}
	return permissionStmt(p.State, "TO", p)
}

// RevokeStmt returns the REVOKE statement for p. It never cascades.
func RevokeStmt(p Permission) (string, error) {
	return permissionStmt("REVOKE", "FROM", p)
}

func permissionStmt(verb, preposition string, p Permission) (string, error) {
	if err := ValidatePermission(p.Scope(), p.Permission); err != nil {
		return "", err
	}
	qp, err := QuoteName(p.Principal)
	if err != nil {
		return "", fmt.Errorf("principal name %w", err)
	}
	var b strings.Builder
	b.WriteString(verb + " " + p.Permission)
	if p.Schema != "" {
		qs, err := QuoteName(p.Schema)
		if err != nil {
			return "", fmt.Errorf("schema name %w", err)
		}
		b.WriteString(" ON SCHEMA::" + qs)
	}
	b.WriteString(" " + preposition + " " + qp + ";")
	return b.String(), nil
}
