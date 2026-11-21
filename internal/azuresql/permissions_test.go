package azuresql

import (
	"slices"
	"strings"
	"testing"
)

func TestPermissionAllowlistSizes(t *testing.T) {
	t.Parallel()

	if n := len(DatabasePermissions()); n != 105 {
		t.Errorf("database allowlist has %d entries, want 105", n)
	}
	if n := len(SchemaPermissions()); n != 13 {
		t.Errorf("schema allowlist has %d entries, want 13", n)
	}
	for _, list := range [][]string{DatabasePermissions(), SchemaPermissions()} {
		seen := map[string]bool{}
		for _, p := range list {
			if seen[p] {
				t.Errorf("duplicate permission %q", p)
			}
			seen[p] = true
			if p != strings.ToUpper(p) || strings.TrimSpace(p) != p {
				t.Errorf("permission %q is not canonical upper case", p)
			}
		}
		if !slices.IsSorted(list) {
			t.Error("allowlist is not sorted")
		}
	}
	// Every schema permission is also known at the database level or is schema-only.
	schemaOnly := []string{"CREATE SEQUENCE", "VIEW CHANGE TRACKING"}
	for _, p := range SchemaPermissions() {
		if !slices.Contains(DatabasePermissions(), p) && !slices.Contains(schemaOnly, p) {
			t.Errorf("schema permission %q is unexpectedly absent from the database list", p)
		}
	}
}

func TestValidatePermission(t *testing.T) {
	t.Parallel()

	ok := []struct {
		scope Scope
		perm  string
	}{
		{ScopeDatabase, "VIEW DEFINITION"},
		{ScopeSchema, "VIEW DEFINITION"},
		{ScopeDatabase, "CREATE TABLE"},
		{ScopeSchema, "SELECT"},
		{ScopeDatabase, "CONNECT"},
		{ScopeSchema, "CREATE SEQUENCE"},
	}
	for _, tt := range ok {
		if err := ValidatePermission(tt.scope, tt.perm); err != nil {
			t.Errorf("ValidatePermission(%s, %q) = %v", tt.scope, tt.perm, err)
		}
	}

	if err := ValidatePermission(ScopeSchema, "CREATE TABLE"); err == nil {
		t.Error("CREATE TABLE must not be valid for a schema")
	}
	if err := ValidatePermission(ScopeDatabase, "CREATE SEQUENCE"); err == nil {
		t.Error("CREATE SEQUENCE is a schema permission only")
	}

	err := ValidatePermission(ScopeDatabase, "view definition")
	if err == nil || !strings.Contains(err.Error(), `"VIEW DEFINITION"`) {
		t.Errorf("lower-case input: %v, want a hint naming VIEW DEFINITION", err)
	}

	err = ValidatePermission(ScopeDatabase, "VEIW DEFINITION")
	if err == nil || !strings.Contains(err.Error(), `closest allowed permission is "VIEW DEFINITION"`) {
		t.Errorf("typo: %v, want the closest name suggested", err)
	}

	for _, bad := range []string{"", "SELECT; DROP TABLE x", "ALL", "SELECT]"} {
		if err := ValidatePermission(ScopeDatabase, bad); err == nil {
			t.Errorf("ValidatePermission(%q) = nil, want error", bad)
		}
	}
	err = ValidatePermission(ScopeDatabase, "COMPLETELY UNRELATED NONSENSE TEXT")
	if err == nil || strings.Contains(err.Error(), "closest") {
		t.Errorf("unrelated input: %v, want no suggestion", err)
	}
}
