package acme

import (
	"strings"
	"testing"
)

func TestValidateIdentifier(t *testing.T) {
	t.Parallel()
	long63 := strings.Repeat("a", 63)
	name253 := strings.Join([]string{long63, long63, long63, strings.Repeat("a", 61)}, ".")
	if len(name253) != 253 {
		t.Fatalf("test name has %d characters", len(name253))
	}
	for _, ok := range []string{"example.com", "*.example.com", "xn--bcher-kva.example", long63 + ".com", name253} {
		if err := ValidateIdentifier(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"Example.com", "example.com.", "*", "a.*.example.com", "*.*.example.com", "w*.example.com", "example..com",
		"com", "under_score.example.com", "bücher.example", "", "*.", "-a.example.com", "a-.example.com",
		long63 + "a.com", name253 + "a",
	} {
		if err := ValidateIdentifier(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := ValidateIdentifier("Example.COM"); err == nil || !strings.Contains(err.Error(), "example.com") {
		t.Errorf("upper case: want a hint with the lower-case form, got %v", err)
	}
}

func TestValidateMatchDomain(t *testing.T) {
	t.Parallel()
	if err := ValidateMatchDomain("apps.example.net"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"*.", "*.example.com", "example", "Example.com"} {
		if err := ValidateMatchDomain(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestIdentifiers(t *testing.T) {
	t.Parallel()
	got, err := Identifiers("example.com", []string{"*.example.com", "www.example.com"})
	if err != nil || strings.Join(got, ",") != "example.com,*.example.com,www.example.com" {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := Identifiers("example.com", []string{"example.com"}); err == nil {
		t.Error("common name repeated among the alternative names was accepted")
	}
	if _, err := Identifiers("example.com", []string{"a.example.com", "a.example.com"}); err == nil {
		t.Error("duplicate accepted")
	}
	if _, err := Identifiers("example.com", []string{"A.example.com"}); err == nil {
		t.Error("upper case accepted")
	}
	if Base("*.example.com") != "example.com" || Base("example.com") != "example.com" {
		t.Error("Base")
	}
}

func TestCommonNameLength(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 60) + ".example.com" // 72 characters
	if ValidateCommonName("example.com") != nil || ValidateCommonName(strings.Repeat("a", 64)) != nil {
		t.Error("a short common name was refused")
	}
	if ValidateCommonName(strings.Repeat("a", 65)) == nil {
		t.Error("a 65 character common name was accepted")
	}
	if _, err := Identifiers(long, nil); err == nil {
		t.Error("a long common name was accepted")
	}
	// Alternative names may be longer than a common name can be.
	if _, err := Identifiers("example.com", []string{long}); err != nil {
		t.Errorf("a long alternative name was refused: %v", err)
	}
}
