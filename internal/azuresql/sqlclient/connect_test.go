package sqlclient

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
)

const testToken = "eyJ0b2tlbi1zZWNyZXQ"

type fakeConn struct{ driver.Conn }

type fakeConnector struct {
	errs     []error // returned in order; nil entries succeed
	attempts int
}

func (f *fakeConnector) Connect(context.Context) (driver.Conn, error) {
	f.attempts++
	if f.attempts > len(f.errs) {
		return fakeConn{}, nil
	}
	if err := f.errs[f.attempts-1]; err != nil {
		return nil, err
	}
	return fakeConn{}, nil
}

func (f *fakeConnector) Driver() driver.Driver { return nil }

// harness runs a retryConnector against a fake connector with a fake clock: sleeping
// advances the clock and records the delay.
type harness struct {
	conn   *retryConnector
	inner  *fakeConnector
	delays []time.Duration
	clock  time.Time
}

func newHarness(budget time.Duration, errs ...error) *harness {
	h := &harness{inner: &fakeConnector{errs: errs}, clock: time.Unix(0, 0)}
	h.conn = &retryConnector{
		inner:  h.inner,
		budget: budget,
		token:  testToken,
		now:    func() time.Time { return h.clock },
		sleep: func(_ context.Context, d time.Duration) error {
			h.delays = append(h.delays, d)
			h.clock = h.clock.Add(d)
			return nil
		},
	}
	return h
}

func sqlError(n int32) error { return mssql.Error{Number: n, Message: "failure"} }

func TestRetryTransientThenSuccess(t *testing.T) {
	t.Parallel()

	h := newHarness(2*time.Minute, sqlError(40613), sqlError(40613))
	if _, err := h.conn.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.inner.attempts != 3 {
		t.Errorf("attempts = %d, want 3", h.inner.attempts)
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second}
	if fmt.Sprint(h.delays) != fmt.Sprint(want) {
		t.Errorf("delays = %v, want %v", h.delays, want)
	}
}

func TestNoRetryForOtherErrors(t *testing.T) {
	t.Parallel()

	for name, err := range map[string]error{
		"sign-in failure": sqlError(18456),
		"network error":   errors.New("dial tcp 127.0.0.1:1: connect: connection refused"),
		"wrapped plain":   fmt.Errorf("login error: %w", errors.New("tls failure")),
	} {
		h := newHarness(2*time.Minute, err, nil)
		if _, got := h.conn.Connect(context.Background()); got == nil {
			t.Errorf("%s: want an error", name)
		}
		if h.inner.attempts != 1 || len(h.delays) != 0 {
			t.Errorf("%s: attempts = %d, delays = %v; want one attempt and no waiting", name, h.inner.attempts, h.delays)
		}
	}
}

func TestRetryWrappedTransientError(t *testing.T) {
	t.Parallel()

	h := newHarness(time.Minute, fmt.Errorf("login error: %w", sqlError(40501)))
	if _, err := h.conn.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.inner.attempts != 2 {
		t.Errorf("attempts = %d, want 2", h.inner.attempts)
	}
}

func TestBudgetExhaustedReturnsLastError(t *testing.T) {
	t.Parallel()

	errs := make([]error, 20)
	for i := range errs {
		errs[i] = sqlError(40613)
	}
	errs[3] = sqlError(49920) // the last error before giving up is the one returned
	h := newHarness(2*time.Minute, errs...)
	_, err := h.conn.Connect(context.Background())
	if err == nil {
		t.Fatal("want an error")
	}
	var sqlErr mssql.Error
	if !errors.As(err, &sqlErr) || sqlErr.Number != 40613 && sqlErr.Number != 49920 {
		t.Fatalf("error %v does not carry the last SQL error", err)
	}
	// 5 + 10 + 20 + 40 seconds fit in two minutes; the next delay would not.
	if h.inner.attempts != 5 || len(h.delays) != 4 {
		t.Errorf("attempts = %d, delays = %v", h.inner.attempts, h.delays)
	}
	if !strings.Contains(err.Error(), "giving up after 5 attempts") {
		t.Errorf("error = %v", err)
	}
}

func TestZeroBudgetMakesOneAttempt(t *testing.T) {
	t.Parallel()

	h := newHarness(0, sqlError(40613), nil)
	if _, err := h.conn.Connect(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	if h.inner.attempts != 1 || len(h.delays) != 0 {
		t.Errorf("attempts = %d, delays = %v", h.inner.attempts, h.delays)
	}
}

func TestContextCancellationStopsWaiting(t *testing.T) {
	t.Parallel()

	h := newHarness(2*time.Minute, sqlError(40613), nil)
	h.conn.sleep = func(ctx context.Context, _ time.Duration) error {
		return context.Canceled
	}
	_, err := h.conn.Connect(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	if h.inner.attempts != 1 {
		t.Errorf("attempts = %d, want 1", h.inner.attempts)
	}

	// The real sleeper returns promptly once the context is done.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := sleepContext(ctx, time.Minute); !errors.Is(err, context.Canceled) {
		t.Errorf("sleepContext = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("sleepContext did not return promptly")
	}
}

func TestTokenNeverInReturnedErrors(t *testing.T) {
	t.Parallel()

	leaky := []error{
		errors.New("login failed for token " + testToken),
		mssql.Error{Number: 18456, Message: "Login failed " + testToken},
		mssql.Error{Number: 40613, Message: "unavailable " + testToken},
	}
	for _, e := range leaky {
		h := newHarness(0, e)
		_, err := h.conn.Connect(context.Background())
		if err == nil {
			t.Fatal("want an error")
		}
		if strings.Contains(err.Error(), testToken) {
			t.Errorf("error leaks the token: %v", err)
		}
	}

	c := New(Settings{Token: testToken})
	if err := c.sanitize(errors.New("x " + testToken + " y")); strings.Contains(err.Error(), testToken) {
		t.Errorf("sanitize leaks the token: %v", err)
	}
	if c.sanitize(nil) != nil {
		t.Error("sanitize(nil) must be nil")
	}
}

func TestConnectorConfig(t *testing.T) {
	t.Parallel()

	cfg := newConnectorConfig("example.database.windows.net", 1433, "orders")
	if cfg.Encryption != msdsn.EncryptionRequired {
		t.Error("encryption must be required")
	}
	if cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify {
		t.Error("the server certificate must be verified")
	}
	if cfg.TLSConfig.ServerName != "example.database.windows.net" {
		t.Errorf("TLS server name = %q", cfg.TLSConfig.ServerName)
	}
	if cfg.TLSConfig.MinVersion < 0x0303 {
		t.Error("TLS 1.2 is the minimum")
	}
	if cfg.TrustServerCertificate {
		t.Error("the server certificate must not be trusted blindly")
	}
	if cfg.Database != "orders" || cfg.AppName != "terraform-provider-conative" || cfg.Port != 1433 {
		t.Errorf("config = %+v", cfg)
	}
	if !cfg.DisableRetry {
		t.Error("statements must not be retried by the pool")
	}
	if cfg.User != "" || cfg.Password != "" {
		t.Error("no SQL credentials may be configured")
	}
}

func TestClientRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	c := New(Settings{Server: "tcp://example.com", Token: testToken})
	if err := c.Exec(context.Background(), "", "SELECT 1"); err == nil {
		t.Error("empty database name accepted")
	}
	if err := c.Exec(context.Background(), "orders", "SELECT 1"); err == nil || !strings.Contains(err.Error(), "server") {
		t.Errorf("invalid server: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
