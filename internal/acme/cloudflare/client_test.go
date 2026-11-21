package cloudflare_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/cloudflarefake"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/dnsstore"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/cloudflare"
)

const token = "a-cloudflare-test-token"

func start(t *testing.T) (*cloudflarefake.Server, *dnsstore.Store, *cloudflare.Client, *acctest.Certs) {
	t.Helper()
	certs, err := acctest.NewCerts(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := dnsstore.New()
	srv := cloudflarefake.Start(certs.Server, store)
	t.Cleanup(srv.Close)
	srv.AddZone("example.com")
	srv.AddToken(token, "example.com")
	c, err := cloudflare.New(srv.APIURL(), token, certs.HTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	return srv, store, c, certs
}

func TestPublishAndRemoveOnlyOwnRecords(t *testing.T) {
	srv, store, c, _ := start(t)
	ctx := context.Background()
	srv.Seed("example.com", "_acme-challenge.example.com", "foreign")

	p := cloudflare.NewZonePublisher(c, "example.com")
	if err := p.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(ctx, "_acme-challenge.example.com", []string{"v1", "v2"}); err != nil {
		t.Fatal(err)
	}
	if got := store.Values("_acme-challenge.example.com"); len(got) != 3 {
		t.Fatalf("after publish: %v", got)
	}
	if err := p.Remove(ctx, "_acme-challenge.example.com", []string{"v1", "v2", "foreign"}); err != nil {
		t.Fatal(err)
	}
	if got := store.Values("_acme-challenge.example.com"); !slices.Equal(got, []string{"foreign"}) {
		t.Errorf("only the records this publisher created may be removed: %v", got)
	}
}

func TestZoneLookupAndErrors(t *testing.T) {
	srv, _, c, certs := start(t)
	ctx := context.Background()
	if id, err := c.FindZone(ctx, "example.com"); err != nil || id == "" {
		t.Errorf("zone: %q %v", id, err)
	}
	if _, err := c.FindZone(ctx, "example.org"); err == nil || !strings.Contains(err.Error(), "not found or cannot be read") {
		t.Errorf("unknown zone: %v", err)
	}
	other := srv.AddZone("example.net") // the token may not use it
	if _, err := c.FindZone(ctx, "example.net"); err == nil {
		t.Error("a zone the token cannot read was found")
	}
	if _, err := c.CreateTXT(ctx, other, "_acme-challenge.example.net", "v"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("a zone the token cannot edit: %v", err)
	}

	wrong, _ := cloudflare.New(srv.APIURL(), "another-token", certs.HTTPClient())
	if _, err := wrong.FindZone(ctx, "example.com"); err == nil || strings.Contains(err.Error(), "another-token") || !strings.Contains(err.Error(), "401") {
		t.Errorf("a wrong token: %v", err)
	}

	srv.FailWrites(true)
	if _, err := c.CreateTXT(ctx, "zone0001", "_acme-challenge.example.com", "v"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("failing writes: %v", err)
	}
	srv.FailWrites(false)
	// A record that is already gone counts as removed.
	zone, _ := c.FindZone(ctx, "example.com")
	if err := c.DeleteRecord(ctx, zone, "rec9999"); err != nil {
		t.Errorf("deleting a missing record: %v", err)
	}
	if _, err := cloudflare.New("http://api.cloudflare.com/client/v4", token, nil); err == nil {
		t.Error("an http URL was accepted")
	}
}
