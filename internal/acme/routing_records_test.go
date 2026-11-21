package acme

import (
	"reflect"
	"strings"
	"testing"
)

func TestRoute(t *testing.T) {
	t.Parallel()
	cf := Block{Kind: KindCloudflare, Index: 0, Zone: "example.com", MatchDomains: []string{"example.com"}}
	az := Block{Kind: KindAzureDNS, Index: 0, Zone: "apps.example.com", MatchDomains: []string{"apps.example.com"}}
	got, err := Route([]string{"example.com", "*.example.com", "x.apps.example.com", "*.apps.example.com", "www.example.com"}, []Block{cf, az})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]BlockKind{
		"example.com": KindCloudflare, "*.example.com": KindCloudflare, "www.example.com": KindCloudflare,
		"x.apps.example.com": KindAzureDNS, "*.apps.example.com": KindAzureDNS,
	}
	for id, kind := range want {
		if got[id].Kind != kind {
			t.Errorf("%s routed to %s, want %s", id, got[id], kind)
		}
	}
	if _, err := Route([]string{"badexample.com"}, []Block{cf}); err == nil || !strings.Contains(err.Error(), "badexample.com") {
		t.Errorf("label boundary: %v", err)
	}
	if _, err := Route([]string{"example.org"}, []Block{cf}); err == nil || !strings.Contains(err.Error(), "example.org") {
		t.Errorf("no match: %v", err)
	}
	if _, err := Route([]string{"example.com"}, nil); err == nil {
		t.Error("zero blocks accepted")
	}
	dup := Block{Kind: KindAzureDNS, Index: 1, Zone: "example.com", MatchDomains: []string{"example.com"}}
	if err := ValidateBlocks([]Block{cf, dup}); err == nil || !strings.Contains(err.Error(), "cloudflare[0]") || !strings.Contains(err.Error(), "azure_dns[1]") {
		t.Errorf("duplicate entry: %v", err)
	}
	outside := Block{Kind: KindCloudflare, Zone: "example.com", MatchDomains: []string{"example.net"}}
	if err := ValidateBlocks([]Block{outside}); err == nil {
		t.Error("entry outside its zone accepted")
	}
}

func TestRecords(t *testing.T) {
	t.Parallel()
	if ChallengeFQDN("*.example.com") != "_acme-challenge.example.com" {
		t.Error("fqdn")
	}
	for fqdn, want := range map[string]string{
		"_acme-challenge.example.net":      "_acme-challenge",
		"_acme-challenge.apps.example.net": "_acme-challenge.apps",
	} {
		if got, err := AzureRelativeName(fqdn, "example.net"); err != nil || got != want {
			t.Errorf("%s: %q, %v", fqdn, got, err)
		}
	}
	if _, err := AzureRelativeName("_acme-challenge.example.org", "example.net"); err == nil {
		t.Error("name outside the zone accepted")
	}
	recs := ChallengeRecords(map[string]string{"example.com": "v1", "*.example.com": "v2", "x.example.com": "v3"})
	if !reflect.DeepEqual(recs["_acme-challenge.example.com"], []string{"v1", "v2"}) || len(recs) != 2 {
		t.Errorf("records: %v", recs)
	}

	existing := [][]string{{"foreign"}, {"multi", "string"}}
	added := AddValues(existing, []string{"ours", "foreign"})
	if !reflect.DeepEqual(added, [][]string{{"foreign"}, {"multi", "string"}, {"ours"}}) {
		t.Errorf("AddValues: %v", added)
	}
	if !reflect.DeepEqual(RemoveValues(added, []string{"ours"}), existing) {
		t.Errorf("RemoveValues keeps foreign values and their order")
	}
	if got := RemoveValues([][]string{{"ours"}}, []string{"ours"}); len(got) != 0 {
		t.Errorf("an emptied set is reported empty: %v", got)
	}
}
