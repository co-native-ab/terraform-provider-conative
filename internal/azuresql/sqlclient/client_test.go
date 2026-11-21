package sqlclient

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDBSharesOneOpenAndRemembersFailure(t *testing.T) {
	t.Parallel()

	var opens atomic.Int32
	boom := errors.New("unreachable")
	c := New(Settings{})
	c.open = func(context.Context, Settings, string) (*sql.DB, error) {
		opens.Add(1)
		return nil, boom
	}
	for range 3 {
		if _, err := c.db(context.Background(), "orders"); !errors.Is(err, boom) {
			t.Fatalf("got %v, want the open error", err)
		}
	}
	if n := opens.Load(); n != 1 {
		t.Errorf("open ran %d times, want 1", n)
	}
}

func TestDBSlowOpenDoesNotBlockOtherDatabases(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	started := make(chan struct{})
	c := New(Settings{})
	c.open = func(_ context.Context, _ Settings, database string) (*sql.DB, error) {
		if database == "slow" {
			close(started)
			<-release
		}
		return nil, errors.New("closed in test")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.db(context.Background(), "slow")
	}()
	<-started

	// A waiter for the same database honours its context.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.db(ctx, "slow"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("waiter: got %v, want deadline exceeded", err)
	}

	// Another database is not held up.
	other := make(chan struct{})
	go func() {
		defer close(other)
		_, _ = c.db(context.Background(), "fast")
	}()
	select {
	case <-other:
	case <-time.After(5 * time.Second):
		t.Fatal("a second database waited for the slow one")
	}
	close(release)
	<-done
}

func TestDBDoesNotRememberACancelledOpen(t *testing.T) {
	t.Parallel()

	var opens atomic.Int32
	c := New(Settings{})
	c.open = func(ctx context.Context, _ Settings, _ string) (*sql.DB, error) {
		if opens.Add(1) == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, errors.New("reached the server")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.db(ctx, "orders"); !errors.Is(err, context.Canceled) {
		t.Fatalf("first call: got %v, want context canceled", err)
	}
	if _, err := c.db(context.Background(), "orders"); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("second call: got %v, want a fresh open error", err)
	}
	if n := opens.Load(); n != 2 {
		t.Errorf("open ran %d times, want 2", n)
	}
}
