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

// Two orders for one name can publish the same value. The second finds the identical
// record, uses it and never deletes it: the first one owns it.
func TestIdenticalRecordIsUsedButNotOwned(t *testing.T) {
	srv, store, c, _ := start(t)
	srv.RefuseIdenticalRecords(true)
	ctx := context.Background()
	const name = "_acme-challenge.example.com"

	first := cloudflare.NewZonePublisher(c, "example.com")
	second := cloudflare.NewZonePublisher(c, "example.com")
	if err := first.Publish(ctx, name, []string{"shared"}); err != nil {
		t.Fatal(err)
	}
	if err := second.Publish(ctx, name, []string{"shared", "own"}); err != nil {
		t.Fatalf("an identical record must not fail the publish: %v", err)
	}
	if got := store.Values(name); len(got) != 2 {
		t.Fatalf("records: %v", got)
	}
	if err := second.Remove(ctx, name, []string{"shared", "own"}); err != nil {
		t.Fatal(err)
	}
	if got := store.Values(name); !slices.Equal(got, []string{"shared"}) {
		t.Errorf("the second publisher removed a record it does not own: %v", got)
	}
	if err := first.Remove(ctx, name, []string{"shared"}); err != nil {
		t.Fatal(err)
	}
	if got := store.Values(name); len(got) != 0 {
		t.Errorf("records are left: %v", got)
	}
}

// A create that failed after Cloudflare stored the record leaves no ID. Remove looks
// the record up by name and content and deletes it.
func TestUnknownCreateOutcomeIsCleanedUp(t *testing.T) {
	srv, store, c, _ := start(t)
	srv.CommitThenFail(true)
	ctx := context.Background()
	const name = "_acme-challenge.example.com"
	srv.Seed("example.com", name, "foreign")

	p := cloudflare.NewZonePublisher(c, "example.com")
	if err := p.Publish(ctx, name, []string{"ours"}); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("want the failure, got %v", err)
	}
	if got := store.Values(name); len(got) != 2 {
		t.Fatalf("the fake should have committed the record: %v", got)
	}
	srv.CommitThenFail(false)
	if err := p.Remove(ctx, name, []string{"ours"}); err != nil {
		t.Fatal(err)
	}
	if got := store.Values(name); !slices.Equal(got, []string{"foreign"}) {
		t.Errorf("want only the foreign record left, got %v", got)
	}
}

func TestForbiddenWriteSaysWhichPermissionIsNeeded(t *testing.T) {
	srv, _, _, certs := start(t)
	srv.AddReadOnlyToken("read-only-token", "example.com")
	c, err := cloudflare.New(srv.APIURL(), "read-only-token", certs.HTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	p := cloudflare.NewZonePublisher(c, "example.com")
	err = p.Publish(context.Background(), "_acme-challenge.example.com", []string{"v"})
	if err == nil || !strings.Contains(err.Error(), "DNS Edit permission on the zone") || !strings.Contains(err.Error(), "read-only token can plan but not apply") {
		t.Fatalf("want a hint about DNS Edit, got %v", err)
	}
	if strings.Contains(err.Error(), "read-only-token") {
		t.Errorf("the token is in the error: %v", err)
	}
}
