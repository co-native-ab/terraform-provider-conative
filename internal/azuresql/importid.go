package azuresql

import (
	"errors"
	"fmt"
	"strings"
)

// Import IDs join their parts with '/'. Inside a part, '%' is written %25 and '/' is
// written %2F; no other escapes exist.

var errBadEscape = errors.New("contains an invalid % escape (only %25 and %2F are allowed)")

var (
	escaper   = strings.NewReplacer("%", "%25", "/", "%2F")
	unescaper = strings.NewReplacer("%25", "%", "%2F", "/")
)

// EscapeIDPart escapes one part of an import ID.
func EscapeIDPart(s string) string { return escaper.Replace(s) }

// UnescapeIDPart reverses EscapeIDPart and rejects any other % sequence.
func UnescapeIDPart(s string) (string, error) {
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		if rest := s[i:]; !strings.HasPrefix(rest, "%25") && !strings.HasPrefix(rest, "%2F") {
			return "", errBadEscape
		}
		i += 2
	}
	return unescaper.Replace(s), nil
}

// FormatID joins parts into an import ID.
func FormatID(parts ...string) string {
	escaped := make([]string, len(parts))
	for i, p := range parts {
		escaped[i] = EscapeIDPart(p)
	}
	return strings.Join(escaped, "/")
}

// ParseID splits an import ID into its unescaped parts. Every part must be non-empty
// and the ID must have a number of parts between minParts and maxParts.
func ParseID(id string, minParts, maxParts int) ([]string, error) {
	raw := strings.Split(id, "/")
	if len(raw) < minParts || len(raw) > maxParts {
		return nil, fmt.Errorf("has %d parts, expected %s", len(raw), partRange(minParts, maxParts))
	}
	parts := make([]string, len(raw))
	for i, r := range raw {
		if r == "" {
			return nil, fmt.Errorf("part %d is empty", i+1)
		}
		p, err := UnescapeIDPart(r)
		if err != nil {
			return nil, fmt.Errorf("part %d %w", i+1, err)
		}
		parts[i] = p
	}
	return parts, nil
}

func partRange(lo, hi int) string {
	if lo == hi {
		return fmt.Sprint(lo)
	}
	return fmt.Sprintf("%d or %d", lo, hi)
}

// UserID formats the import ID of a database user: database/name.
func UserID(database, name string) string { return FormatID(database, name) }

// ParseUserID parses database/name.
func ParseUserID(id string) (database, name string, err error) {
	p, err := ParseID(id, 2, 2)
	if err != nil {
		return "", "", fmt.Errorf("invalid import ID %q: %w; expected database/name", id, err)
	}
	return p[0], p[1], nil
}

// RoleMemberID formats the import ID of a role membership: database/role/member.
func RoleMemberID(database, role, member string) string { return FormatID(database, role, member) }

// ParseRoleMemberID parses database/role/member.
func ParseRoleMemberID(id string) (database, role, member string, err error) {
	p, err := ParseID(id, 3, 3)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid import ID %q: %w; expected database/role/member", id, err)
	}
	return p[0], p[1], p[2], nil
}

// PermissionID formats the import ID of a permission:
// database/principal/STATE/PERMISSION, with /schema appended for a schema-level
// permission (schema non-empty).
func PermissionID(database, principal, state, permission, schema string) string {
	if schema == "" {
		return FormatID(database, principal, state, permission)
	}
	return FormatID(database, principal, state, permission, schema)
}

// ParsePermissionID parses database/principal/STATE/PERMISSION[/schema]. The schema
// is empty for a database-level permission.
func ParsePermissionID(id string) (database, principal, state, permission, schema string, err error) {
	p, err := ParseID(id, 4, 5)
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("invalid import ID %q: %w; expected database/principal/STATE/PERMISSION[/schema]", id, err)
	}
	if len(p) == 5 {
		schema = p[4]
	}
	return p[0], p[1], p[2], p[3], schema, nil
}
