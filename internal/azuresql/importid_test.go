package azuresql

import "testing"

func TestEscapeRoundTrip(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"plain", "a/b", "x%y", "%2F", "%252F", "//", "%/%", "naïve", "with space"} {
		got, err := UnescapeIDPart(EscapeIDPart(s))
		if err != nil || got != s {
			t.Errorf("round trip of %q = %q, %v", s, got, err)
		}
	}
	if got := EscapeIDPart("a/b%c"); got != "a%2Fb%25c" {
		t.Errorf("EscapeIDPart = %q", got)
	}
}

func TestUnescapeRejectsOtherEscapes(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"%", "a%", "%2", "%2f", "%20", "%zz", "%25%", "100%"} {
		if _, err := UnescapeIDPart(s); err == nil {
			t.Errorf("UnescapeIDPart(%q) = nil error, want error", s)
		}
	}
}

func TestUserID(t *testing.T) {
	t.Parallel()

	if got := UserID("a/b", "x%y"); got != "a%2Fb/x%25y" {
		t.Errorf("UserID = %q", got)
	}
	db, name, err := ParseUserID("a%2Fb/x%25y")
	if err != nil || db != "a/b" || name != "x%y" {
		t.Errorf("ParseUserID = %q, %q, %v", db, name, err)
	}
	for _, bad := range []string{"", "db", "db/", "/name", "a/b/c", "db/na%me"} {
		if _, _, err := ParseUserID(bad); err == nil {
			t.Errorf("ParseUserID(%q) = nil error, want error", bad)
		}
	}
}

func TestRoleMemberID(t *testing.T) {
	t.Parallel()

	id := RoleMemberID("orders", "db_owner", "orders-app")
	if id != "orders/db_owner/orders-app" {
		t.Errorf("RoleMemberID = %q", id)
	}
	db, role, member, err := ParseRoleMemberID(id)
	if err != nil || db != "orders" || role != "db_owner" || member != "orders-app" {
		t.Errorf("ParseRoleMemberID = %q, %q, %q, %v", db, role, member, err)
	}
	db, _, member, err = ParseRoleMemberID(RoleMemberID("a/b", "db_owner", "m/n"))
	if err != nil || db != "a/b" || member != "m/n" {
		t.Errorf("slash round trip = %q, %q, %v", db, member, err)
	}
	for _, bad := range []string{"", "a/b", "a/b/c/d", "a//c", "a/b/%"} {
		if _, _, _, err := ParseRoleMemberID(bad); err == nil {
			t.Errorf("ParseRoleMemberID(%q) = nil error, want error", bad)
		}
	}
}

func TestPermissionID(t *testing.T) {
	t.Parallel()

	dbLevel := PermissionID("orders", "plan-reader", "GRANT", "VIEW DEFINITION", "")
	if dbLevel != "orders/plan-reader/GRANT/VIEW DEFINITION" {
		t.Errorf("database-level ID = %q", dbLevel)
	}
	schemaLevel := PermissionID("orders", "plan-reader", "DENY", "SELECT", "sales")
	if schemaLevel != "orders/plan-reader/DENY/SELECT/sales" {
		t.Errorf("schema-level ID = %q", schemaLevel)
	}

	db, pr, st, pe, sc, err := ParsePermissionID(dbLevel)
	if err != nil || db != "orders" || pr != "plan-reader" || st != "GRANT" || pe != "VIEW DEFINITION" || sc != "" {
		t.Errorf("ParsePermissionID(database level) = %q %q %q %q %q %v", db, pr, st, pe, sc, err)
	}
	db, pr, st, pe, sc, err = ParsePermissionID(schemaLevel)
	if err != nil || db != "orders" || pr != "plan-reader" || st != "DENY" || pe != "SELECT" || sc != "sales" {
		t.Errorf("ParsePermissionID(schema level) = %q %q %q %q %q %v", db, pr, st, pe, sc, err)
	}

	weird := PermissionID("d/b", "p%q", "GRANT", "SELECT", "s/t")
	db, pr, _, _, sc, err = ParsePermissionID(weird)
	if err != nil || db != "d/b" || pr != "p%q" || sc != "s/t" {
		t.Errorf("escaped round trip = %q %q %q %v", db, pr, sc, err)
	}

	for _, bad := range []string{"", "a/b/c", "a/b/c/d/e/f", "a//c/d", "a/b/c/d/", "a/b/c/%x"} {
		if _, _, _, _, _, err := ParsePermissionID(bad); err == nil {
			t.Errorf("ParsePermissionID(%q) = nil error, want error", bad)
		}
	}
}
