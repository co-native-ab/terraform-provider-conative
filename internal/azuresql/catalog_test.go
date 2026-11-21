package azuresql

import "testing"

func TestMapUser(t *testing.T) {
	t.Parallel()

	sid := mustSID(t, vectorID)

	ext := MapUser(UserRow{Name: "app", Type: "E", TypeDesc: "EXTERNAL_USER", SID: sid})
	if ext.SID != "0x33221100554477668899AABBCCDDEEFF" || ext.PrincipalType != "EXTERNAL_USER" || ext.EntraID == nil || *ext.EntraID != vectorID {
		t.Errorf("external user = %+v", ext)
	}
	grp := MapUser(UserRow{Name: "g", Type: "X", TypeDesc: "EXTERNAL_GROUP", SID: sid})
	if grp.EntraID == nil || *grp.EntraID != vectorID {
		t.Errorf("external group = %+v", grp)
	}

	// A SQL user's SID is a GUID-sized value too, but it does not name an Entra principal.
	sqlUser := MapUser(UserRow{Name: "s", Type: "S", TypeDesc: "SQL_USER", SID: sid})
	if sqlUser.EntraID != nil {
		t.Errorf("SQL user got an Entra ID: %v", *sqlUser.EntraID)
	}
	// An external principal with an identifier of another length has none either.
	long := MapUser(UserRow{Name: "w", Type: "E", TypeDesc: "EXTERNAL_USER", SID: make([]byte, 28)})
	if long.EntraID != nil {
		t.Errorf("28-byte SID got an Entra ID: %v", *long.EntraID)
	}
	if empty := MapUser(UserRow{Name: "n", Type: "E", TypeDesc: "EXTERNAL_USER"}); empty.EntraID != nil || empty.SID != "0x" {
		t.Errorf("empty SID = %+v", empty)
	}
}

func TestMapPermissionState(t *testing.T) {
	t.Parallel()

	want := map[string]string{"G": "GRANT", "D": "DENY", "W": "GRANT_WITH_GRANT_OPTION"}
	for code, state := range want {
		got, err := MapPermissionState(code)
		if err != nil || got != state {
			t.Errorf("MapPermissionState(%q) = %q, %v; want %q", code, got, err, state)
		}
	}
	for _, code := range []string{"R", "", "X", "g"} {
		if got, err := MapPermissionState(code); err == nil {
			t.Errorf("MapPermissionState(%q) = %q, want error", code, got)
		}
	}
}

func TestValidators(t *testing.T) {
	t.Parallel()

	for _, ok := range []string{"application", "user", "group"} {
		if err := ValidateUserType(ok); err != nil {
			t.Errorf("ValidateUserType(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Application", "service_principal"} {
		if ValidateUserType(bad) == nil {
			t.Errorf("ValidateUserType(%q) = nil", bad)
		}
	}
	if len(PrincipalTypes()) != 7 {
		t.Errorf("PrincipalTypes has %d entries, want 7", len(PrincipalTypes()))
	}
	for _, ok := range PrincipalTypes() {
		if err := ValidatePrincipalType(ok); err != nil {
			t.Errorf("ValidatePrincipalType(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "DATABASE_ROLE", "external_user", "SQL_LOGIN"} {
		if ValidatePrincipalType(bad) == nil {
			t.Errorf("ValidatePrincipalType(%q) = nil", bad)
		}
	}
	if ValidatePermissionState("GRANT") != nil || ValidatePermissionState("DENY") != nil {
		t.Error("GRANT and DENY must be valid states")
	}
	for _, bad := range []string{"", "grant", "REVOKE", "GRANT_WITH_GRANT_OPTION"} {
		if ValidatePermissionState(bad) == nil {
			t.Errorf("ValidatePermissionState(%q) = nil", bad)
		}
	}
}

func TestTypePlanDecision(t *testing.T) {
	t.Parallel()

	str := func(s string) *string { return &s }
	tests := []struct {
		name          string
		prior         *string
		planned, desc string
		want          TypeDecision
	}{
		{"prior equal", str("application"), "application", "EXTERNAL_USER", TypeKeep},
		{"prior equal ignores principal type", str("group"), "group", "SQL_USER", TypeKeep},
		{"prior different", str("application"), "user", "EXTERNAL_USER", TypeReplace},
		{"prior different group", str("user"), "group", "EXTERNAL_GROUP", TypeReplace},
		{"imported application", nil, "application", "EXTERNAL_USER", TypeUpdate},
		{"imported user", nil, "user", "EXTERNAL_USER", TypeUpdate},
		{"imported group", nil, "group", "EXTERNAL_GROUP", TypeUpdate},
		{"imported group but external user", nil, "group", "EXTERNAL_USER", TypeReplace},
		{"imported application but external group", nil, "application", "EXTERNAL_GROUP", TypeReplace},
		{"imported application but SQL user", nil, "application", "SQL_USER", TypeReplace},
		{"imported group but SQL user", nil, "group", "SQL_USER", TypeReplace},
	}
	for _, tt := range tests {
		if got := TypePlanDecision(tt.prior, tt.planned, tt.desc); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}
