package azuresql

import (
	"strings"
	"testing"
)

func TestFixedRoles(t *testing.T) {
	t.Parallel()

	want := []string{
		"db_accessadmin", "db_backupoperator", "db_datareader", "db_datawriter", "db_ddladmin",
		"db_denydatareader", "db_denydatawriter", "db_owner", "db_securityadmin",
	}
	got := FixedRoles()
	if len(got) != len(want) {
		t.Fatalf("FixedRoles has %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("FixedRoles()[%d] = %q, want %q", i, got[i], want[i])
		}
		if err := ValidateRole(want[i]); err != nil {
			t.Errorf("ValidateRole(%q) = %v", want[i], err)
		}
	}

	// The returned slice is a copy.
	got[0] = "tampered"
	if FixedRoles()[0] != "db_accessadmin" {
		t.Error("FixedRoles returns shared state")
	}
}

func TestValidateRole(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"", "db_superuser", "public", "dbmanager", "db_owner]; DROP", " db_owner"} {
		if err := ValidateRole(bad); err == nil {
			t.Errorf("ValidateRole(%q) = nil, want error", bad)
		}
	}
	err := ValidateRole("DB_OWNER")
	if err == nil || !strings.Contains(err.Error(), `"db_owner"`) {
		t.Errorf("ValidateRole(DB_OWNER) = %v, want a hint naming db_owner", err)
	}
	err = ValidateRole("nope")
	if err == nil || !strings.Contains(err.Error(), "db_datareader") {
		t.Errorf("ValidateRole(nope) = %v, want the allowed roles listed", err)
	}
}
