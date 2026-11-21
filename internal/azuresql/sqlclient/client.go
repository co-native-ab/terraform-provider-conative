package sqlclient

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql"
)

// Settings configure a Client for one logical server.
type Settings struct {
	Server       string        // host or host:port
	Token        string        // access token; used only to sign in, never logged
	RetryTimeout time.Duration // total time to retry transient connection errors
}

// Client holds one connection pool per database of one server. Pools are opened on
// first use and closed by Close.
type Client struct {
	settings Settings
	open     func(ctx context.Context, settings Settings, database string) (*sql.DB, error)

	mu  sync.Mutex
	dbs map[string]*pool
}

// pool is the one attempt to open a database. Callers share it: ready is closed once
// db or err is set, and a failed open is kept for the rest of the run.
type pool struct {
	ready chan struct{}
	db    *sql.DB
	err   error
}

// New returns a Client for settings. It does not connect.
func New(settings Settings) *Client {
	return &Client{settings: settings, open: openDB, dbs: map[string]*pool{}}
}

func (c *Client) db(ctx context.Context, database string) (*sql.DB, error) {
	if err := azuresql.ValidateName(database); err != nil {
		return nil, fmt.Errorf("database name %w", err)
	}
	for {
		c.mu.Lock()
		p, ok := c.dbs[database]
		if !ok {
			p = &pool{ready: make(chan struct{})}
			c.dbs[database] = p
		}
		c.mu.Unlock()
		if !ok {
			// Open outside the lock so other databases are not held up. The first
			// caller's context bounds the attempt.
			db, err := c.open(ctx, c.settings, database)
			if err != nil && ctx.Err() != nil {
				// The caller gave up; that says nothing about the database, so the
				// next caller tries again instead of inheriting this error.
				c.forget(database, p)
			}
			p.db, p.err = db, err
			close(p.ready)
		}
		select {
		case <-p.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if p.err != nil && ok && isContextError(p.err) && ctx.Err() == nil {
			// The caller that opened gave up; try again with this caller's context.
			continue
		}
		return p.db, p.err
	}
}

// forget removes p from the pools if it is still the entry for database.
func (c *Client) forget(database string, p *pool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dbs[database] == p {
		delete(c.dbs, database)
	}
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// Exec runs one statement in a database. Statements are never retried.
func (c *Client) Exec(ctx context.Context, database, statement string) error {
	db, err := c.db(ctx, database)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, statement); err != nil {
		return c.sanitize(err)
	}
	return nil
}

// Query runs a query with parameters and calls scan for every row.
func (c *Client) Query(ctx context.Context, database, query string, args []any, scan func(*sql.Rows) error) error {
	db, err := c.db(ctx, database)
	if err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return c.sanitize(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return c.sanitize(rows.Err())
}

// Count runs a query that returns a single integer, such as SELECT COUNT(*).
func (c *Client) Count(ctx context.Context, database, query string, args ...any) (int, error) {
	n, seen := 0, false
	err := c.Query(ctx, database, query, args, func(r *sql.Rows) error {
		seen = true
		return r.Scan(&n)
	})
	if err != nil {
		return 0, err
	}
	if !seen {
		return 0, errors.New("the query returned no rows")
	}
	return n, nil
}

// Strings runs a query that returns a single text column.
func (c *Client) Strings(ctx context.Context, database, query string, args ...any) ([]string, error) {
	var out []string
	err := c.Query(ctx, database, query, args, func(r *sql.Rows) error {
		var s string
		if err := r.Scan(&s); err != nil {
			return err
		}
		out = append(out, s)
		return nil
	})
	return out, err
}

// Users runs one of the user queries and returns its rows.
func (c *Client) Users(ctx context.Context, database, query string, args ...any) ([]azuresql.UserRow, error) {
	var out []azuresql.UserRow
	err := c.Query(ctx, database, query, args, func(r *sql.Rows) error {
		var row azuresql.UserRow
		if err := r.Scan(&row.Name, &row.Type, &row.TypeDesc, &row.SID); err != nil {
			return err
		}
		out = append(out, row)
		return nil
	})
	return out, err
}

// Close closes every pool that opened. The provider does not call it: pools are meant
// to live as long as the plugin process and are released when it exits.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var errs []error
	for name, p := range c.dbs {
		select {
		case <-p.ready:
			if p.db != nil {
				errs = append(errs, p.db.Close())
			}
		default: // still opening; nothing to close yet
		}
		delete(c.dbs, name)
	}
	return errors.Join(errs...)
}

// sanitize keeps the access token out of any error that leaves the package.
func (c *Client) sanitize(err error) error {
	if err == nil {
		return nil
	}
	return redact(err, c.settings.Token)
}

// ErrorNumber returns the SQL Server error number carried by err, if any.
func ErrorNumber(err error) (int32, bool) {
	var e interface{ SQLErrorNumber() int32 }
	if errors.As(err, &e) {
		return e.SQLErrorNumber(), true
	}
	return 0, false
}
