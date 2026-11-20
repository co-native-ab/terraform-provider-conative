package tdsproxy_test

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/tdsproxy"
)

// TestDriverTokenLoginIsRefused connects the real driver with the security-token
// login. The upstream address is unused: refused logins never reach it. This proves
// that the driver's PRELOGIN, TLS-in-TDS handshake and LOGIN7 are understood and that
// refusals arrive as proper SQL Server errors.
func TestDriverTokenLoginIsRefused(t *testing.T) {
	t.Parallel()

	certs, err := acctest.NewCerts(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const token = "the-right-token"
	proxy, err := tdsproxy.Start(tdsproxy.Config{
		ListenAddr:   "127.0.0.1:0",
		Certificate:  certs.Server,
		Token:        token,
		UpstreamAddr: "127.0.0.1:1",
		UpstreamUser: "sa",
		UpstreamPass: "unused",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	connect := func(tok string) error {
		cfg := msdsn.Config{
			Host:         "127.0.0.1",
			Port:         mustPort(t, proxy.Addr()),
			Database:     "master",
			Encryption:   msdsn.EncryptionRequired,
			TLSConfig:    &tls.Config{RootCAs: certs.CAPool, ServerName: "localhost", MinVersion: tls.VersionTLS12},
			AppName:      "tdsproxy-test",
			DialTimeout:  5 * time.Second,
			DisableRetry: true,
			Protocols:    []string{"tcp"},
			Encoding:     msdsn.EncodeParameters{Timezone: time.UTC},
		}
		connector, err := mssql.NewSecurityTokenConnector(cfg, func(context.Context) (string, error) { return tok, nil })
		if err != nil {
			t.Fatal(err)
		}
		db := sql.OpenDB(connector)
		defer db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return db.PingContext(ctx)
	}

	for name, tok := range map[string]string{"wrong token": "a-different-token", "empty token": ""} {
		err := connect(tok)
		var sqlErr mssql.Error
		if !errors.As(err, &sqlErr) || sqlErr.Number != 18456 {
			t.Errorf("%s: error = %v, want SQL Server error 18456", name, err)
		}
		if err != nil && tok != "" && strings.Contains(err.Error(), tok) {
			t.Errorf("%s: the error contains the token", name)
		}
	}

	proxy.RejectAll(true)
	err = connect(token)
	var sqlErr mssql.Error
	if !errors.As(err, &sqlErr) || sqlErr.Number != 18456 {
		t.Errorf("RejectAll: error = %v, want 18456", err)
	}
	if err != nil && strings.Contains(err.Error(), token) {
		t.Error("RejectAll: the error contains the token")
	}
}

func TestClosedProxyRefusesConnections(t *testing.T) {
	t.Parallel()

	certs, err := acctest.NewCerts(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := tdsproxy.Start(tdsproxy.Config{ListenAddr: "127.0.0.1:0", Certificate: certs.Server, Token: "t", UpstreamAddr: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	addr := proxy.Addr()
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := proxy.Close(); err != nil && !strings.Contains(err.Error(), "closed") {
		t.Errorf("second Close: %v", err)
	}
	if _, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
		t.Error("connected to a closed proxy")
	}
}
