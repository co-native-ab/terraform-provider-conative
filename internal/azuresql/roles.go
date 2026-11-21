package azuresql

import (
	"fmt"
	"strings"
)

// The fixed database roles, as reported by
//
//	SELECT name FROM sys.database_principals WHERE type = 'R' AND is_fixed_role = 1
//
// on SQL Server 2022 16.0.4295.3. The names are case-sensitive and lower case, as the
// engine reports them.
var fixedRoles = []string{
	"db_accessadmin",
	"db_backupoperator",
	"db_datareader",
	"db_datawriter",
	"db_ddladmin",
	"db_denydatareader",
	"db_denydatawriter",
	"db_owner",
	"db_securityadmin",
}

// FixedRoles returns the fixed database roles a user can be made a member of.
func FixedRoles() []string { return append([]string(nil), fixedRoles...) }

// ValidateRole reports whether role is one of the fixed database roles.
func ValidateRole(role string) error {
	for _, r := range fixedRoles {
		if r == role {
			return nil
		}
	}
	msg := fmt.Sprintf("%q is not a fixed database role; allowed roles are %s", role, strings.Join(fixedRoles, ", "))
	for _, r := range fixedRoles {
		if strings.EqualFold(r, role) {
			msg += fmt.Sprintf(" (role names are lower case: did you mean %q?)", r)
			break
		}
	}
	return fmt.Errorf("%s", msg)
}
