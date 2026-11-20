package azuresql

import (
	"fmt"
	"strings"
)

// User types as written in configuration.
const (
	UserTypeApplication = "application"
	UserTypeUser        = "user"
	UserTypeGroup       = "group"
)

// UserTypes returns the values accepted for the type of a database user.
func UserTypes() []string {
	return []string{UserTypeApplication, UserTypeUser, UserTypeGroup}
}

// ValidateUserType reports whether t is one of the supported user types.
func ValidateUserType(t string) error {
	switch t {
	case UserTypeApplication, UserTypeUser, UserTypeGroup:
		return nil
	}
	return fmt.Errorf("%q is not a valid type; allowed values are %s", t, strings.Join(UserTypes(), ", "))
}

// Principal types as reported by sys.database_principals.type_desc for the kinds of
// user the data sources return.
const (
	PrincipalTypeExternalUser  = "EXTERNAL_USER"
	PrincipalTypeExternalGroup = "EXTERNAL_GROUP"
)

var principalTypes = []string{
	"ASYMMETRIC_KEY_MAPPED_USER",
	"CERTIFICATE_MAPPED_USER",
	PrincipalTypeExternalGroup,
	PrincipalTypeExternalUser,
	"SQL_USER",
	"WINDOWS_GROUP",
	"WINDOWS_USER",
}

// PrincipalTypes returns the type_desc values a database user can report.
func PrincipalTypes() []string { return append([]string(nil), principalTypes...) }

// ValidatePrincipalType reports whether t is a type_desc value of a database user.
func ValidatePrincipalType(t string) error {
	for _, p := range principalTypes {
		if p == t {
			return nil
		}
	}
	return fmt.Errorf("%q is not a database user type; allowed values are %s", t, strings.Join(principalTypes, ", "))
}

// UserRow is one row of sys.database_principals as the shell reads it.
type UserRow struct {
	Name     string
	Type     string // single-letter type code
	TypeDesc string
	SID      []byte
}

// User is what the provider reports about a database user.
type User struct {
	Name          string
	SID           string  // 0x-prefixed upper-case hexadecimal
	PrincipalType string  // type_desc as reported
	EntraID       *string // derived from the SID when the principal is external and the SID is a GUID
}

// MapUser maps a catalog row to a User.
func MapUser(row UserRow) User {
	u := User{
		Name:          row.Name,
		SID:           SIDHex(row.SID),
		PrincipalType: row.TypeDesc,
	}
	if row.Type == "E" || row.Type == "X" {
		if id, ok := EntraIDFromSID(row.SID); ok {
			u.EntraID = &id
		}
	}
	return u
}

// Permission states as written in configuration.
const (
	StateGrant = "GRANT"
	StateDeny  = "DENY"
	// StateGrantWithGrantOption is only ever read from the database; the provider
	// never grants with grant option.
	StateGrantWithGrantOption = "GRANT_WITH_GRANT_OPTION"
)

// ValidatePermissionState reports whether s may be configured: GRANT or DENY.
func ValidatePermissionState(s string) error {
	if s == StateGrant || s == StateDeny {
		return nil
	}
	return fmt.Errorf("%q is not a valid state; allowed values are %s, %s", s, StateGrant, StateDeny)
}

// MapPermissionState maps the sys.database_permissions state code to a state name.
func MapPermissionState(code string) (string, error) {
	switch code {
	case "G":
		return StateGrant, nil
	case "D":
		return StateDeny, nil
	case "W":
		return StateGrantWithGrantOption, nil
	case "R":
		return "", fmt.Errorf("unexpected permission state code %q", code)
	}
	return "", fmt.Errorf("unknown permission state code %q", code)
}

// TypeDecision is the outcome of TypePlanDecision.
type TypeDecision int

// The possible outcomes for a planned user type.
const (
	// TypeKeep means the type is unchanged.
	TypeKeep TypeDecision = iota
	// TypeUpdate means the type can be recorded in state without touching the
	// database: the database user was imported and matches the configuration.
	TypeUpdate
	// TypeReplace means the user must be replaced.
	TypeReplace
)

// TypePlanDecision decides what a planned `type` means for an existing user. The
// catalog cannot tell an application from a user (both are external users), so the
// type is owned by configuration and is empty (prior == nil) after an import.
//
//   - prior set and equal: keep.
//   - prior set and different: replace.
//   - prior empty (imported): the user can be updated in place if the reported
//     principal type fits the planned type, otherwise it is replaced.
func TypePlanDecision(prior *string, planned, principalType string) TypeDecision {
	if prior != nil {
		if *prior == planned {
			return TypeKeep
		}
		return TypeReplace
	}
	switch {
	case (planned == UserTypeApplication || planned == UserTypeUser) && principalType == PrincipalTypeExternalUser:
		return TypeUpdate
	case planned == UserTypeGroup && principalType == PrincipalTypeExternalGroup:
		return TypeUpdate
	}
	return TypeReplace
}
