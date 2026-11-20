package azuresql

import (
	"fmt"
	"strings"
)

// Scope is the securable class a permission applies to.
type Scope string

// The supported scopes.
const (
	ScopeDatabase Scope = "DATABASE"
	ScopeSchema   Scope = "SCHEMA"
)

// DatabasePermissions returns the permissions that can be granted on a database.
func DatabasePermissions() []string { return append([]string(nil), databasePermissions...) }

// SchemaPermissions returns the permissions that can be granted on a schema.
func SchemaPermissions() []string { return append([]string(nil), schemaPermissions...) }

func permissionsFor(scope Scope) []string {
	if scope == ScopeSchema {
		return schemaPermissions
	}
	return databasePermissions
}

// ValidatePermission reports whether permission is valid for scope. Names are
// compared case-sensitively against upper-case input; a different casing is
// rejected with a hint, and an unknown name with the closest allowed one.
func ValidatePermission(scope Scope, permission string) error {
	allowed := permissionsFor(scope)
	for _, p := range allowed {
		if p == permission {
			return nil
		}
	}
	if upper := strings.ToUpper(permission); upper != permission {
		for _, p := range allowed {
			if p == upper {
				return fmt.Errorf("%q is not a %s permission name; permission names are upper case, did you mean %q?", permission, scope, upper)
			}
		}
	}
	msg := fmt.Sprintf("%q is not a permission that can be granted on a %s", permission, strings.ToLower(string(scope)))
	if best := closest(allowed, strings.ToUpper(permission)); best != "" {
		msg += fmt.Sprintf("; the closest allowed permission is %q", best)
	}
	return fmt.Errorf("%s", msg)
}

// closest returns the entry of candidates with the smallest edit distance to s, or
// "" when nothing is reasonably close.
func closest(candidates []string, s string) string {
	best, bestDist := "", len(s)/2+3
	for _, c := range candidates {
		if d := editDistance(c, s); d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
