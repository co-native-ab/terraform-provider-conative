package azuredns_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/azurednsfake"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/dnsstore"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/azuredns"
)

const (
	token = "an-azure-test-token"
	sub   = "00000000-0000-0000-0000-000000000000"
)

// interposer lets a test act between the client's read and write of a record set.
type interposer struct {
	base      http.RoundTripper
	beforePut func()
}

func (i interposer) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPut && i.beforePut != nil {
		i.beforePut()
	}
	return i.base.RoundTrip(r)
}

func start(t *testing.T, beforePut func()) (*azurednsfake.Server, *dnsstore.Store, *azuredns.Client, *acctest.Certs) {
	t.Helper()
	certs, err := acctest.NewCerts(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := dnsstore.New()
	srv := azurednsfake.Start(certs.Server, token, store)
	t.Cleanup(srv.Close)
	srv.AddZone(sub, "dns", "example.net")
	hc := certs.HTTPClient()
	hc.Transport = interposer{base: hc.Transport, beforePut: beforePut}
	c, err := azuredns.New(srv.URL, token, hc)
	if err != nil {
		t.Fatal(err)
	}
	return srv, store, c, certs
}

func TestAddAndRemoveKeepForeignValues(t *testing.T) {
	srv, store, c, _ := start(t, nil)
	ctx := context.Background()
	srv.Seed(sub, "dns", "example.net", "_acme-challenge.apps", "foreign")

	if err := c.Add(ctx, sub, "dns", "example.net", "_acme-challenge.apps", []string{"ours-1", "ours-2"}); err != nil {
		t.Fatal(err)
	}
	if got := store.Values("_acme-challenge.apps.example.net"); !slices.Equal(got, []string{"foreign", "ours-1", "ours-2"}) {
		t.Fatalf("after add: %v", got)
	}
	if err := c.Remove(ctx, sub, "dns", "example.net", "_acme-challenge.apps", []string{"ours-1", "ours-2"}); err != nil {
		t.Fatal(err)
	}
	if got := store.Values("_acme-challenge.apps.example.net"); !slices.Equal(got, []string{"foreign"}) {
		t.Fatalf("after remove: %v", got)
	}

	// A set that holds only our values is deleted.
	if err := c.Add(ctx, sub, "dns", "example.net", "_acme-challenge", []string{"only"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Remove(ctx, sub, "dns", "example.net", "_acme-challenge", []string{"only"}); err != nil {
		t.Fatal(err)
	}
	if got := store.Values("_acme-challenge.example.net"); len(got) != 0 {
		t.Errorf("an emptied set remains: %v", got)
	}
	// Removing from a set that is gone is not an error.
	if err := c.Remove(ctx, sub, "dns", "example.net", "_acme-challenge", []string{"only"}); err != nil {
		t.Error(err)
	}
}

func TestAChangedEtagIsRetriedAtMostTenTimes(t *testing.T) {
	var puts atomic.Int32
	var srv *azurednsfake.Server
	conflict := func() {
		// Another writer changes the set between our read and our write.
		puts.Add(1)
		srv.Seed(sub, "dns", "example.net", "_acme-challenge", "concurrent")
	}
	var c *azuredns.Client
	var store *dnsstore.Store
	srv, store, c, _ = start(t, conflict)
	c.SetRetryBase(time.Millisecond)
	ctx := context.Background()
	srv.Seed(sub, "dns", "example.net", "_acme-challenge", "first")

	err := c.Add(ctx, sub, "dns", "example.net", "_acme-challenge", []string{"ours"})
	if err == nil || !strings.Contains(err.Error(), "changed too often") {
		t.Fatalf("want an error after repeated conflicts, got %v", err)
	}
	if n := puts.Load(); n != 10 {
		t.Errorf("%d attempts, want 10", n)
	}
	if got := store.Values("_acme-challenge.example.net"); slices.Contains(got, "ours") {
		t.Errorf("a write went through despite the conflict: %v", got)
	}
}

// Several orders for names that share a challenge record name write one record set at
// once; four lost races in a row are survived.
func TestFourConflictsInARowAreSurvived(t *testing.T) {
	var puts atomic.Int32
	var srv *azurednsfake.Server
	conflict := func() {
		if puts.Add(1) <= 4 {
			srv.Seed(sub, "dns", "example.net", "_acme-challenge", fmt.Sprintf("concurrent-%d", puts.Load()))
		}
	}
	var c *azuredns.Client
	var store *dnsstore.Store
	srv, store, c, _ = start(t, conflict)
	c.SetRetryBase(time.Millisecond)
	ctx := context.Background()

	if err := c.Add(ctx, sub, "dns", "example.net", "_acme-challenge", []string{"ours"}); err != nil {
		t.Fatal(err)
	}
	if n := puts.Load(); n != 5 {
		t.Errorf("%d writes, want 4 conflicts and one success", n)
	}
	got := store.Values("_acme-challenge.example.net")
	for _, want := range []string{"ours", "concurrent-1", "concurrent-2", "concurrent-3", "concurrent-4"} {
		if !slices.Contains(got, want) {
			t.Errorf("%q is missing from %v", want, got)
		}
	}
	// Removing is guarded in the same way.
	if err := c.Remove(ctx, sub, "dns", "example.net", "_acme-challenge", []string{"ours"}); err != nil {
		t.Fatal(err)
	}
	if got := store.Values("_acme-challenge.example.net"); slices.Contains(got, "ours") {
		t.Errorf("our value is still there: %v", got)
	}
}

func TestContextEndsTheWaitBetweenAttempts(t *testing.T) {
	var srv *azurednsfake.Server
	var c *azuredns.Client
	srv, _, c, _ = start(t, func() { srv.Seed(sub, "dns", "example.net", "_acme-challenge", "concurrent") })
	c.SetRetryBase(time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	srv.Seed(sub, "dns", "example.net", "_acme-challenge", "first")
	start := time.Now()
	if err := c.Add(ctx, sub, "dns", "example.net", "_acme-challenge", []string{"ours"}); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("the wait was not cut short: %v after %s", err, time.Since(start))
	}
}

func TestErrorsAndZones(t *testing.T) {
	srv, _, c, certs := start(t, nil)
	ctx := context.Background()
	if z, err := c.GetZone(ctx, sub, "dns", "example.net"); err != nil || z.Name != "example.net" || len(z.NameServers) == 0 {
		t.Errorf("zone: %+v %v", z, err)
	}
	_, err := c.GetZone(ctx, sub, "dns", "missing.example.net")
	if !errors.Is(err, azuredns.ErrNotFound) || !strings.Contains(err.Error(), "ResourceNotFound") {
		t.Errorf("missing zone: %v", err)
	}
	srv.FailWrites(true)
	if err := c.Add(ctx, sub, "dns", "example.net", "_acme-challenge", []string{"x"}); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("failing writes: %v", err)
	}
	wrong, _ := azuredns.New(srv.URL, "another-token", certs.HTTPClient())
	if _, err := wrong.GetZone(ctx, sub, "dns", "example.net"); err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "another-token") {
		t.Errorf("wrong token: %v", err)
	}
	if _, err := azuredns.New("http://management.azure.com", token, nil); err == nil {
		t.Error("an http URL was accepted")
	}
}
