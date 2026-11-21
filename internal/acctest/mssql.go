package acctest

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql"
)

// DefaultImage is the SQL Server image used unless ACC_MSSQL_IMAGE says otherwise.
const DefaultImage = "mcr.microsoft.com/mssql/server:2022-latest"

// Container is a SQL Server container started for one test run.
type Container struct {
	ID       string
	Name     string
	Addr     string // "127.0.0.1:port" on the host
	Password string // password of the sa login

	db *sql.DB // connection as sa, to the master database
}

// StartContainer starts SQL Server in Docker on a random loopback port and waits until
// it accepts SQL-authenticated connections. Callers must call Remove.
func StartContainer(ctx context.Context) (*Container, error) {
	image := os.Getenv("ACC_MSSQL_IMAGE")
	if image == "" {
		image = DefaultImage
	}
	password, err := randomPassword()
	if err != nil {
		return nil, err
	}
	suffix, err := randomHex(4)
	if err != nil {
		return nil, err
	}
	c := &Container{Name: "conative-acc-" + suffix, Password: password}

	out, err := docker(ctx, "run", "-d", "--rm",
		"--name", c.Name,
		"-p", "127.0.0.1::1433",
		"-e", "ACCEPT_EULA=Y",
		"-e", "MSSQL_SA_PASSWORD="+password,
		image)
	if err != nil {
		return nil, fmt.Errorf("docker run: %w", err)
	}
	c.ID = strings.TrimSpace(out)

	port, err := docker(ctx, "port", c.ID, "1433/tcp")
	if err != nil {
		c.Remove()
		return nil, fmt.Errorf("docker port: %w", err)
	}
	// The output has one "address:port" line per bound address family.
	line := strings.TrimSpace(strings.SplitN(port, "\n", 2)[0])
	c.Addr = strings.Replace(line, "0.0.0.0", "127.0.0.1", 1)

	if err := c.waitReady(ctx, 3*time.Minute); err != nil {
		c.Remove()
		return nil, err
	}
	return c, nil
}

func docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // arguments come from the test tooling, not from input
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

func (c *Container) waitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		db, err := c.open("master")
		if err == nil {
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = db.PingContext(pctx)
			cancel()
			if err == nil {
				c.db = db
				return nil
			}
			_ = db.Close()
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("SQL Server did not become ready within %s: %w", timeout, last)
}

// open connects as sa with SQL authentication. The container's certificate is
// self-signed, so it is not verified here: this is the test's own direct connection
// to a container on a loopback address, not the provider's connection.
func (c *Container) open(database string) (*sql.DB, error) {
	host, port, err := splitAddr(c.Addr)
	if err != nil {
		return nil, err
	}
	cfg := msdsn.Config{
		Host:                   host,
		Port:                   port,
		Database:               database,
		User:                   "sa",
		Password:               c.Password,
		Encryption:             msdsn.EncryptionRequired,
		TLSConfig:              &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, DynamicRecordSizingDisabled: true}, //nolint:gosec // see above
		TrustServerCertificate: true,
		DialTimeout:            10 * time.Second,
		DisableRetry:           true,
		Protocols:              []string{"tcp"},
		ProtocolParameters:     map[string]interface{}{},
		Encoding:               msdsn.EncodeParameters{Timezone: time.UTC},
	}
	return sql.OpenDB(mssql.NewConnectorConfig(cfg)), nil
}

// Remove stops and removes the container and closes the connections to it. It is safe
// to call more than once.
func (c *Container) Remove() {
	if c.db != nil {
		_ = c.db.Close()
		c.db = nil
	}
	if c.ID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = docker(ctx, "rm", "-f", c.ID)
		c.ID = ""
	}
}

// SA returns a connection pool signed in as sa to the named database. Callers must not
// close it; Remove does.
func (c *Container) SA(database string) (*sql.DB, error) {
	if database == "master" || database == "" {
		return c.db, nil
	}
	return c.open(database)
}

// ExecAsSA runs statements in a database as sa.
func (c *Container) ExecAsSA(database string, statements ...string) error {
	db, err := c.SA(database)
	if err != nil {
		return err
	}
	if database != "master" && database != "" {
		defer db.Close()
	}
	for _, s := range statements {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}
	return nil
}

// QueryIntAsSA runs a query that returns one integer as sa.
func (c *Container) QueryIntAsSA(database, query string, args ...any) (int, error) {
	db, err := c.SA(database)
	if err != nil {
		return 0, err
	}
	if database != "master" && database != "" {
		defer db.Close()
	}
	var n int
	err = db.QueryRow(query, args...).Scan(&n)
	return n, err
}

// QueryStringAsSA runs a query that returns one string as sa.
func (c *Container) QueryStringAsSA(database, query string, args ...any) (string, error) {
	db, err := c.SA(database)
	if err != nil {
		return "", err
	}
	if database != "master" && database != "" {
		defer db.Close()
	}
	var s string
	err = db.QueryRow(query, args...).Scan(&s)
	return s, err
}

// CreateDatabase creates an empty database.
func (c *Container) CreateDatabase(name string) error {
	q, err := azuresql.QuoteName(name)
	if err != nil {
		return err
	}
	return c.ExecAsSA("master", "CREATE DATABASE "+q+";")
}

// CreateUserWithoutLogin creates a database user that no login maps to. A container
// cannot hold Entra users, so tests use such users as stand-ins to exercise reads,
// imports, role memberships and permissions.
func (c *Container) CreateUserWithoutLogin(database, name string) error {
	q, err := azuresql.QuoteName(name)
	if err != nil {
		return err
	}
	return c.ExecAsSA(database, "CREATE USER "+q+" WITHOUT LOGIN;")
}

// UserExists reports whether a database principal with the name exists.
func (c *Container) UserExists(database, name string) (bool, error) {
	n, err := c.QueryIntAsSA(database, "SELECT COUNT(*) FROM sys.database_principals WHERE name = @p1;", name)
	return n > 0, err
}

func splitAddr(addr string) (string, uint64, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", 0, errors.New("address has no port: " + addr)
	}
	var port uint64
	if _, err := fmt.Sscanf(addr[i+1:], "%d", &port); err != nil {
		return "", 0, err
	}
	return addr[:i], port, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// randomPassword returns a password that satisfies SQL Server's complexity rules.
func randomPassword() (string, error) {
	h, err := randomHex(12)
	if err != nil {
		return "", err
	}
	return "Aa1!" + h, nil
}
