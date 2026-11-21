package dnscheck

import "testing"

func TestAbsolute(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"_acme-challenge.example.com":  "_acme-challenge.example.com.",
		"_acme-challenge.example.com.": "_acme-challenge.example.com.",
		"example.com":                  "example.com.",
	} {
		if got := absolute(in); got != want {
			t.Errorf("absolute(%q) = %q, want %q", in, got, want)
		}
	}
}
