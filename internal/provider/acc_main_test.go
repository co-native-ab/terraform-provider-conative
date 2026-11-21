package provider

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/config"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
)

// acc is the acceptance environment: the fakes of the ACME area and, started on first
// use, a SQL Server container behind a sign-in proxy. It is nil unless TF_ACC is set.
var acc *acctest.Env

func TestMain(m *testing.M) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		os.Exit(m.Run())
	}

	env, err := acctest.SetupEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot set up the acceptance environment: %v\n", err)
		os.Exit(1)
	}
	acc = env

	code := m.Run()
	env.Close()
	os.Exit(code)
}

var databaseCounter atomic.Int64

// newDatabase creates an empty database for one test and returns its name.
func newDatabase(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("acc_%d_%d", time.Now().UnixNano()%1_000_000, databaseCounter.Add(1))
	if err := acc.Container(t).CreateDatabase(name); err != nil {
		t.Fatalf("cannot create database %s: %v", name, err)
	}
	return name
}

// newDatabaseWithName creates an empty database whose name is the given text followed
// by a unique suffix, for tests that need unusual characters in database names.
func newDatabaseWithName(t *testing.T, prefix string) string {
	t.Helper()
	name := fmt.Sprintf("%s_%d", prefix, databaseCounter.Add(1))
	if err := acc.Container(t).CreateDatabase(name); err != nil {
		t.Fatalf("cannot create database %s: %v", name, err)
	}
	return name
}

// tokenVariables supplies the access token to the ephemeral variable the test
// configurations declare.
func tokenVariables() config.Variables {
	return config.Variables{"sql_token": config.StringVariable(acc.Token)}
}

// providerConfig is the provider block every acceptance configuration starts with.
// The token comes from an ephemeral, sensitive variable, as it would in practice.
func providerConfig(t testing.TB) string { t.Helper(); return providerConfigFor(acc.Server(t), "") }

func providerConfigFor(server, extra string) string {
	return fmt.Sprintf(`
variable "sql_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

provider "conative" {
  azuresql = {
    server       = %q
    access_token = var.sql_token
    %s
  }
}
`, server, extra)
}

// accPreCheck skips a test unless the acceptance environment is available.
func accPreCheck(t *testing.T) {
	t.Helper()
	if acc == nil {
		t.Skip("acceptance tests need TF_ACC to be set")
	}
}
