// Package sqlclient is the thin database layer of the Azure SQL area. It opens
// connections with a caller-supplied access token and runs statements; every decision
// about what to run lives in the parent package.
package sqlclient

import (
	"context"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql"
)

const (
	appName     = "terraform-provider-conative"
	dialTimeout = 15 * time.Second
)

// DefaultRetryTimeout is how long a connection is retried when the provider
// configuration does not say otherwise.
const DefaultRetryTimeout = 2 * time.Minute

// newConnectorConfig builds the driver configuration in code. No configuration value
// is ever parsed as connection-string syntax, encryption is always required and the
// server certificate is always validated against the server's host name.
func newConnectorConfig(host string, port int, database string) msdsn.Config {
	return msdsn.Config{
		Host:        host,
		Port:        uint64(port), //nolint:gosec // ParseServer limits the port to 1..65535
		Database:    database,
		Encryption:  msdsn.EncryptionRequired,
		TLSConfig:   tlsConfig(host),
		AppName:     appName,
		DialTimeout: dialTimeout,
		KeepAlive:   30 * time.Second,
		// Statements are never retried, including by database/sql.
		DisableRetry:       true,
		Protocols:          []string{"tcp"},
		ProtocolParameters: map[string]interface{}{},
		Encoding:           msdsn.EncodeParameters{Timezone: time.UTC},
	}
}

func tlsConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName:                  host,
		MinVersion:                  tls.VersionTLS12,
		DynamicRecordSizingDisabled: true,
	}
}

// openConnector returns a driver connector that signs in with the access token, wrapped
// so that establishing a connection is retried on documented transient errors.
func openConnector(settings Settings, host string, port int, database string) (driver.Connector, error) {
	token := settings.Token
	inner, err := mssql.NewSecurityTokenConnector(newConnectorConfig(host, port, database),
		func(context.Context) (string, error) { return token, nil })
	if err != nil {
		return nil, err
	}
	return &retryConnector{
		inner:  inner,
		budget: settings.RetryTimeout,
		token:  token,
		sleep:  sleepContext,
		now:    time.Now,
	}, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// retryConnector retries Connect only when it fails with an error number Microsoft
// documents as transient, with growing delays, for at most budget. Every other error
// is returned at once, and when the budget runs out the last error is returned.
type retryConnector struct {
	inner  driver.Connector
	budget time.Duration
	token  string
	sleep  func(context.Context, time.Duration) error
	now    func() time.Time
}

func (c *retryConnector) Driver() driver.Driver { return c.inner.Driver() }

func (c *retryConnector) Connect(ctx context.Context) (driver.Conn, error) {
	start := c.now()
	for attempt := 0; ; attempt++ {
		conn, err := c.inner.Connect(ctx)
		if err == nil {
			return conn, nil
		}
		err = redact(err, c.token)

		var sqlErr mssql.Error
		if !errors.As(err, &sqlErr) || !azuresql.IsTransient(sqlErr.Number) {
			return nil, err
		}
		delay, ok := azuresql.NextDelay(attempt, c.now().Sub(start), c.budget)
		if !ok && attempt == 0 {
			return nil, err // nothing was retried: report the error as it is
		}
		if !ok {
			return nil, fmt.Errorf("giving up after %d attempts over %s: %w", attempt+1, c.now().Sub(start).Round(time.Second), err)
		}
		if err := c.sleep(ctx, delay); err != nil {
			return nil, err
		}
	}
}

// redact makes sure an error never carries the access token. The driver does not put
// the token in its errors; this is a second line of defence.
func redact(err error, token string) error {
	if token == "" || !strings.Contains(err.Error(), token) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token, "[redacted]"))
}

// openDB opens a pool for one database and checks the first connection.
func openDB(ctx context.Context, settings Settings, database string) (*sql.DB, error) {
	host, port, err := azuresql.ParseServer(settings.Server)
	if err != nil {
		return nil, fmt.Errorf("server %w", err)
	}
	connector, err := openConnector(settings, host, port, database)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("cannot connect to database %q on %s: %w", database, settings.Server, err)
	}
	return db, nil
}
