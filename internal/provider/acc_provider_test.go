package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/config"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
)

func TestAccProvider_connects(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container().CreateUserWithoutLogin(db, "smoke"); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config: providerConfig() + `
data "conative_azuresql_database_users" "all" {
  database = "` + db + `"
}
`,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("data.conative_azuresql_database_users.all", "users.#", "1"),
				resource.TestCheckResourceAttr("data.conative_azuresql_database_users.all", "users.0.name", "smoke"),
				resource.TestCheckResourceAttr("data.conative_azuresql_database_users.all", "users.0.principal_type", "SQL_USER"),
			),
		}},
	})
}

func tokenVariablesFor(token string) config.Variables {
	return config.Variables{"sql_token": config.StringVariable(token)}
}

// readDataSourceDiagnostics runs one data source read through the provider protocol,
// exactly as Terraform does, and returns the text of every diagnostic. Tests use it to
// inspect error messages, which Terraform's own output would reword and wrap.
func readDataSourceDiagnostics(t *testing.T, server, token, typeName string, cfg map[string]tftypes.Value) string {
	t.Helper()
	ctx := context.Background()
	srv, err := testAccProtoV6ProviderFactories["conative"]()
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := srv.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}

	str := tftypes.String
	settingsType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"server": str, "access_token": str, "retry_timeout": str}}
	providerType := schemas.Provider.ValueType()
	acmeType := providerType.(tftypes.Object).AttributeTypes["acme"]
	providerCfg, err := tfprotov6.NewDynamicValue(providerType, tftypes.NewValue(providerType, map[string]tftypes.Value{
		"acme": tftypes.NewValue(acmeType, nil),
		"azuresql": tftypes.NewValue(settingsType, map[string]tftypes.Value{
			"server":        tftypes.NewValue(str, server),
			"access_token":  tftypes.NewValue(str, token),
			"retry_timeout": tftypes.NewValue(str, "0s"),
		}),
	}))
	if err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	collect := func(diags []*tfprotov6.Diagnostic) {
		for _, d := range diags {
			out.WriteString(d.Summary + ": " + d.Detail + "\n")
		}
	}
	configured, err := srv.ConfigureProvider(ctx, &tfprotov6.ConfigureProviderRequest{Config: &providerCfg, TerraformVersion: "1.16.0"})
	if err != nil {
		t.Fatal(err)
	}
	collect(configured.Diagnostics)

	dsType := schemas.DataSourceSchemas[typeName].ValueType()
	values := map[string]tftypes.Value{}
	for name, typ := range dsType.(tftypes.Object).AttributeTypes {
		values[name] = tftypes.NewValue(typ, nil)
	}
	for name, v := range cfg {
		values[name] = v
	}
	dsCfg, err := tfprotov6.NewDynamicValue(dsType, tftypes.NewValue(dsType, values))
	if err != nil {
		t.Fatal(err)
	}
	read, err := srv.ReadDataSource(ctx, &tfprotov6.ReadDataSourceRequest{TypeName: typeName, Config: &dsCfg})
	if err != nil {
		t.Fatal(err)
	}
	collect(read.Diagnostics)
	return out.String()
}

func TestAccProvider_settingsRequiredOnlyOnUse(t *testing.T) {
	accPreCheck(t)
	noSettings := `provider "conative" {}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Nothing uses Azure SQL: no settings are needed.
				Config: noSettings + `
output "unrelated" {
  value = "ok"
}
`,
				Check: resource.TestCheckOutput("unrelated", "ok"),
			},
			{
				Config: noSettings + `
data "conative_azuresql_database_users" "all" {
  database = "master"
}
`,
				ExpectError: regexp.MustCompile(`(?s)azuresql\s+settings\s+\(server,\s+access_token\)\s+are\s+required`),
			},
			{
				Config: noSettings + `
resource "conative_azuresql_database_role_member" "m" {
  database = "master"
  role     = "db_owner"
  member   = "someone"
}
`,
				ExpectError: regexp.MustCompile(`(?s)azuresql\s+settings\s+\(server,\s+access_token\)\s+are\s+required`),
			},
		},
	})
}

func TestAccProvider_unknownTokenFailsAtTheResourceThatNeedsIt(t *testing.T) {
	accPreCheck(t)
	// The token comes from a resource that does not exist yet, so it is unknown at plan time.
	cfg := `
resource "terraform_data" "token" {
  input = "not-known-until-apply"
}

provider "conative" {
  azuresql = {
    server       = "localhost:1"
    access_token = terraform_data.token.output
  }
}

data "conative_azuresql_database_users" "all" {
  database = "master"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      cfg,
			ExpectError: regexp.MustCompile(`(?s)access_token\s+is\s+not\s+known\s+until\s+apply`),
		}},
	})
}

func TestAccProvider_wrongTokenFailsFast(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)

	start := time.Now()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariablesFor(acc.WrongToken),
			Config: providerConfig() + `
data "conative_azuresql_database_users" "all" {
  database = "` + db + `"
}
`,
			ExpectError: regexp.MustCompile(`(?s)Login\s+failed`),
		}},
	})
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("the wrong token took %s to fail, want under 10s", elapsed)
	}

	// Terraform rewraps diagnostics, so the messages themselves are read from the
	// provider protocol.
	text := readDataSourceDiagnostics(t, acc.Server(), acc.WrongToken, "conative_azuresql_database_users", map[string]tftypes.Value{
		"database": tftypes.NewValue(tftypes.String, db),
	})
	if !strings.Contains(text, "Login failed") {
		t.Fatalf("diagnostics = %q, want a sign-in failure", text)
	}
	for name, tok := range map[string]string{"wrong token": acc.WrongToken, "right token": acc.Token} {
		if acctest.ContainsSecret([]byte(text), tok) {
			t.Errorf("the diagnostics contain the %s", name)
		}
	}
	if strings.Contains(text, "giving up") {
		t.Errorf("a sign-in failure was retried: %s", text)
	}
}

// A database that does not exist is reported by this engine with an error that is not on
// the transient list, so it fails at once whatever the retry timeout.
func TestAccProvider_missingDatabaseFailsWithTheEngineError(t *testing.T) {
	accPreCheck(t)
	start := time.Now()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config: providerConfig() + `
data "conative_azuresql_database_users" "all" {
  database = "does_not_exist"
}
`,
			ExpectError: regexp.MustCompile(`(?s)Cannot\s+open\s+database`),
		}},
	})
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("failed after %s", elapsed)
	}
}

func transientConfig(server, retry string, db string) string {
	return providerConfigFor(server, retry) + `
data "conative_azuresql_database_users" "all" {
  database = "` + db + `"
}
`
}

// While the server answers with a documented transient error, the provider waits and
// tries again, and the run succeeds as soon as the server recovers.
func TestAccProvider_transientErrorIsRetriedUntilSuccess(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	proxy, err := acc.NewProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	proxy.FailLogins(40613, 1)

	start := time.Now()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          transientConfig(acctest.ServerName(proxy), "", db),
			Check:           resource.TestCheckResourceAttr("data.conative_azuresql_database_users.all", "users.#", "0"),
		}},
	})
	if elapsed := time.Since(start); elapsed < 5*time.Second {
		t.Errorf("the run took %s, want at least the first 5s retry delay", elapsed)
	}
}

// The retry is bounded: after the retry timeout the run fails with the last error.
func TestAccProvider_transientErrorStopsAtTheRetryTimeout(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	proxy, err := acc.NewProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	proxy.FailLogins(40613, 1000)

	start := time.Now()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			// One retry after 5s fits in 6s; a second wait of 10s does not.
			Config:      transientConfig(acctest.ServerName(proxy), `retry_timeout = "6s"`, db),
			ExpectError: regexp.MustCompile(`(?s)giving\s+up\s+after\s+2\s+attempts.*40613`),
		}},
	})
	if elapsed := time.Since(start); elapsed < 5*time.Second || elapsed > 20*time.Second {
		t.Errorf("the run took %s, want about 5s", elapsed)
	}
}

func TestAccProvider_retryDisabledFailsAtOnce(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	proxy, err := acc.NewProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	proxy.FailLogins(40613, 1000)

	start := time.Now()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          transientConfig(acctest.ServerName(proxy), `retry_timeout = "0s"`, db),
			ExpectError:     regexp.MustCompile(`40613`),
		}},
	})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("failed after %s although retries were disabled", elapsed)
	}
}

// Errors that are not on the documented list fail at once, without a wait.
func TestAccProvider_otherErrorsAreNotRetried(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	proxy, err := acc.NewProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	proxy.FailLogins(18487, 1000) // the account is disabled: not transient

	start := time.Now()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			ConfigVariables: tokenVariables(),
			Config:          transientConfig(acctest.ServerName(proxy), "", db),
			ExpectError:     regexp.MustCompile(`18487`),
		}},
	})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("failed after %s, which means it was retried", elapsed)
	}
}

func TestAccProvider_rejectsInvalidSettings(t *testing.T) {
	accPreCheck(t)
	for name, tt := range map[string]struct{ cfg, match string }{
		"server with a scheme":   {providerConfigFor("tcp://example.com", ""), `must\s+be\s+a\s+host\s+name`},
		"server with options":    {providerConfigFor("example.com;Encrypt=false", ""), `must\s+be\s+a\s+host\s+name`},
		"server with a bad port": {providerConfigFor("example.com:99999", ""), `port\s+must\s+be\s+1\s+to\s+65535`},
		"invalid retry timeout":  {providerConfigFor("example.com", `retry_timeout = "soon"`), `must\s+be\s+a\s+duration`},
		"negative retry timeout": {providerConfigFor("example.com", `retry_timeout = "-1m"`), `must\s+be\s+a\s+duration|must\s+not\s+be\s+negative`},
	} {
		t.Run(name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					ConfigVariables: tokenVariables(),
					Config: tt.cfg + `
data "conative_azuresql_database_users" "all" {
  database = "master"
}
`,
					PlanOnly:    true,
					ExpectError: regexp.MustCompile("(?s)" + tt.match),
				}},
			})
		})
	}
}

// A failure to connect, sign in or read is never taken to mean that the object is gone.
func TestAccProvider_connectionFailureKeepsState(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container().CreateUserWithoutLogin(db, "stays"); err != nil {
		t.Fatal(err)
	}
	proxy, err := acc.NewProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	addr := proxy.Addr()

	cfg := providerConfigFor(acctest.ServerName(proxy), "") + fmt.Sprintf(`
resource "conative_azuresql_database_role_member" "m" {
  database = %q
  role     = "db_datareader"
  member   = "stays"
}
`, db)
	const member = "conative_azuresql_database_role_member.m"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{ConfigVariables: tokenVariables(), Config: cfg, Check: memberCheck(db, "db_datareader", "stays", true)},
			{
				// Sign-in refused: the refresh fails, and the resource must stay in state.
				PreConfig:    func() { proxy.RejectAll(true) },
				RefreshState: true, ConfigVariables: tokenVariables(),
				ExpectError: regexp.MustCompile(`(?s)Login\s+failed`),
			},
			{
				PreConfig:    func() { proxy.RejectAll(false) },
				RefreshState: true, ConfigVariables: tokenVariables(),
				Check: resource.TestCheckResourceAttr(member, "role", "db_datareader"),
			},
			{ConfigVariables: tokenVariables(), Config: cfg, PlanOnly: true},
			{
				// Server unreachable: the refresh fails, and the resource must stay in state.
				PreConfig: func() {
					if err := proxy.Close(); err != nil {
						t.Fatal(err)
					}
				},
				RefreshState: true, ConfigVariables: tokenVariables(),
				ExpectError: regexp.MustCompile(`(?s)Cannot\s+read|cannot\s+connect`),
			},
			{
				// Bring the server back on the same address: nothing was lost.
				PreConfig: func() {
					p, err := acc.NewProxyAt(addr)
					if err != nil {
						t.Fatal(err)
					}
					proxy = p
				},
				RefreshState: true, ConfigVariables: tokenVariables(),
				Check: resource.TestCheckResourceAttr(member, "member", "stays"),
			},
			{ConfigVariables: tokenVariables(), Config: cfg, PlanOnly: true},
		},
	})
	if ok, err := isMember(db, "db_datareader", "stays"); err == nil && ok {
		t.Error("the membership survived the final destroy")
	}
}

// planNeverContains is a plan check that fails if the saved plan, as `terraform show
// -json` renders it, holds the secret in any form.
type planNeverContains struct {
	t      *testing.T
	secret string
	checks *int
}

func (c planNeverContains) CheckPlan(_ context.Context, req plancheck.CheckPlanRequest, _ *plancheck.CheckPlanResponse) {
	data, err := json.Marshal(req.Plan)
	if err != nil {
		c.t.Errorf("cannot render the plan: %v", err)
		return
	}
	*c.checks++
	if acctest.ContainsSecret(data, c.secret) {
		c.t.Error("the saved plan contains the access token")
	}
}

// workdirHasNoToken searches the working directory of the running test for state files
// and saved plans, and the state Terraform reports, for the token.
func workdirHasNoToken(t *testing.T, dir string, files *int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		data, err := json.Marshal(s)
		if err != nil {
			return err
		}
		if acctest.ContainsSecret(data, acc.Token) {
			return fmt.Errorf("the state reported by Terraform contains the access token")
		}
		*files += acctest.AssertNoSecretInFiles(t, dir, acc.Token, "terraform.tfstate*", "tfplan*")
		return nil
	}
}

// The token is supplied from an ephemeral, sensitive variable. It must appear in no
// state file, no saved plan, and no state or plan as Terraform renders them.
func TestAccProvider_tokenNotInStateOrPlan(t *testing.T) {
	accPreCheck(t)
	dir := t.TempDir()
	t.Setenv("TF_ACC_TEMP_DIR", dir)
	db := newDatabase(t)
	for _, n := range []string{"holder", "imported"} {
		if err := acc.Container().CreateUserWithoutLogin(db, n); err != nil {
			t.Fatal(err)
		}
	}
	if err := acc.Container().CreateUserWithoutLogin(db, "viewer"); err != nil {
		t.Fatal(err)
	}
	var files, plans int

	// Everything that can be applied in the container: a membership, a permission at
	// database and schema level, and both data sources.
	cfg := providerConfig() + fmt.Sprintf(`
resource "conative_azuresql_database_role_member" "m" {
  database = %[1]q
  role     = "db_datareader"
  member   = "holder"
}

resource "conative_azuresql_database_permission" "db" {
  database   = %[1]q
  principal  = "viewer"
  state      = "GRANT"
  permission = "VIEW DEFINITION"
}

data "conative_azuresql_database_user" "one" {
  database = %[1]q
  name     = "holder"
}

data "conative_azuresql_database_users" "all" {
  database = %[1]q
}
`, db)
	planCheck := resource.ConfigPlanChecks{
		PreApply:             []plancheck.PlanCheck{planNeverContains{t, acc.Token, &plans}},
		PostApplyPostRefresh: []plancheck.PlanCheck{planNeverContains{t, acc.Token, &plans}},
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				ConfigVariables:  tokenVariables(),
				Config:           cfg,
				ConfigPlanChecks: planCheck,
				Check:            workdirHasNoToken(t, dir, &files),
			},
			{
				// A second apply with the token variable must not change anything.
				ConfigVariables:  tokenVariables(),
				Config:           cfg,
				ConfigPlanChecks: planCheck,
				Check:            workdirHasNoToken(t, dir, &files),
			},
		},
	})

	// The database user resource: an imported user, with the token searched for in the
	// state after the import and the refresh.
	userCfg := userConfig(db, "imported", "application", someEntraID)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             userGone(db, "imported"),
		Steps: []resource.TestStep{
			importFixtureStep(db, "imported", userCfg),
			{
				ConfigVariables: tokenVariables(), RefreshState: true,
				// The imported SQL user does not match the configuration; that is expected.
				ExpectNonEmptyPlan: true,
				Check:              workdirHasNoToken(t, dir, &files),
			},
		},
	})

	if files == 0 {
		t.Error("no state file was searched, so the check proved nothing")
	}
	if plans == 0 {
		t.Error("no plan was searched, so the check proved nothing")
	}
}

// At the most verbose logging level, the token must not appear in the logs of Terraform,
// the plugin SDK or the provider, in plain, UTF-16 or base64 form, for a full
// create, read and destroy and for a run with a wrong token.
func TestAccProvider_tokenNotInLogs(t *testing.T) {
	accPreCheck(t)
	db := newDatabase(t)
	if err := acc.Container().CreateUserWithoutLogin(db, "logged"); err != nil {
		t.Fatal(err)
	}
	logPath := acctest.EnableTraceLogs(t, t.TempDir())

	cfg := providerConfig() + fmt.Sprintf(`
resource "conative_azuresql_database_role_member" "m" {
  database = %[1]q
  role     = "db_datareader"
  member   = "logged"
}
`, db)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				ConfigVariables: tokenVariablesFor(acc.WrongToken),
				Config:          cfg,
				ExpectError:     regexp.MustCompile(`(?s)Login\s+failed`),
			},
			{ConfigVariables: tokenVariables(), Config: cfg, Check: memberCheck(db, "db_datareader", "logged", true)},
			{ConfigVariables: tokenVariables(), Config: cfg, PlanOnly: true},
		},
	})

	acctest.AssertSecretAbsent(t, logPath, acc.Token)
	acctest.AssertSecretAbsent(t, logPath, acc.WrongToken)

	// The check is not vacuous: the log holds the provider's own trace output.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"adding role member", "reading role member", "removing role member"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("the log has no %q line, so provider logging was not captured", want)
		}
	}
	t.Logf("searched %d bytes of trace logs", len(data))
}
