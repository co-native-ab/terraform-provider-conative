package dnsstore_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/dnsstore"
)

func TestStoreValuesAndChecker(t *testing.T) {
	s := dnsstore.New()
	s.Add("_Acme-Challenge.Example.com.", "a")
	s.Add("_acme-challenge.example.com", "b")
	if got := s.Values("_acme-challenge.example.com"); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("names are case-insensitive and ignore a trailing dot: %v", got)
	}
	ctx := context.Background()
	if err := s.Checker().Wait(ctx, "_acme-challenge.example.com", "example.com", []string{"a", "b"}); err != nil {
		t.Error(err)
	}
	if err := s.Checker().Wait(ctx, "_acme-challenge.example.com", "example.com", []string{"c"}); err == nil || !strings.Contains(err.Error(), `"c"`) {
		t.Errorf("a missing value: %v", err)
	}
	s.NeverPropagate("_acme-challenge.example.com")
	if err := s.Checker().Wait(ctx, "_acme-challenge.example.com", "example.com", []string{"a"}); err == nil {
		t.Error("NeverPropagate has no effect")
	}
	s.Remove("_acme-challenge.example.com", "a")
	s.Remove("_acme-challenge.example.com", "b")
	if len(s.All()) != 0 {
		t.Errorf("an emptied name remains: %v", s.All())
	}
	s.Set("x.example.com", []string{"v"})
	s.Reset()
	if len(s.All()) != 0 {
		t.Error("Reset left values")
	}
}
