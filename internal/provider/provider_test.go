package provider

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme/dnscheck"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"conative": providerserver.NewProtocol6WithError(New("test")()),
}

func providerSchema(t *testing.T) provider.SchemaResponse {
	t.Helper()
	var resp provider.SchemaResponse
	New("test")().Schema(context.Background(), provider.SchemaRequest{}, &resp)
	if diags := resp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatalf("provider schema is invalid: %v", diags)
	}
	return resp
}

func TestProviderSchemaValidates(t *testing.T) {
	t.Parallel()
	providerSchema(t)
}

func TestProviderAccessTokenIsSensitive(t *testing.T) {
	t.Parallel()

	nested, ok := providerSchema(t).Schema.Attributes["azuresql"].(schema.SingleNestedAttribute)
	if !ok {
		t.Fatal("azuresql is not a single nested attribute")
	}
	if !nested.Optional {
		t.Error("azuresql must be optional: it is required only when used")
	}
	token := nested.Attributes["access_token"]
	if !token.IsSensitive() || !token.IsRequired() {
		t.Error("access_token must be required and sensitive")
	}
	if nested.Attributes["server"].IsSensitive() {
		t.Error("server must not be sensitive")
	}
	if !nested.Attributes["retry_timeout"].IsOptional() {
		t.Error("retry_timeout must be optional")
	}
}

func TestServerAndRetryTimeoutValidation(t *testing.T) {
	t.Parallel()

	for _, ok := range []string{"example.database.windows.net", "localhost:14330"} {
		if err := parseServerOnly(ok); err != nil {
			t.Errorf("server %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "tcp://x", "x;Encrypt=false", "x:0", "x y"} {
		if err := parseServerOnly(bad); err == nil {
			t.Errorf("server %q accepted", bad)
		}
	}
	for _, ok := range []string{"0s", "2m", "90s", "1h30m"} {
		if err := validateDuration(ok); err != nil {
			t.Errorf("retry_timeout %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "2", "-1m", "soon"} {
		if err := validateDuration(bad); err == nil {
			t.Errorf("retry_timeout %q accepted", bad)
		}
	}
}

func TestStringCheckReportsAttributeError(t *testing.T) {
	t.Parallel()

	v := checkString("must be a duration such as 2m", validateDuration)
	var resp validator.StringResponse
	v.ValidateString(context.Background(), validator.StringRequest{
		Path:        path.Root("azuresql").AtName("retry_timeout"),
		ConfigValue: types.StringValue("soon"),
	}, &resp)
	if !resp.Diagnostics.HasError() {
		t.Error("an invalid value must produce an error")
	}
	// Unknown and null values are not validated.
	for _, val := range []types.String{types.StringUnknown(), types.StringNull()} {
		resp = validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{ConfigValue: val}, &resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("%v produced an error", val)
		}
	}
}

func unknownConfig(t *testing.T, server, token tftypes.Value) provider.ConfigureRequest {
	t.Helper()
	resp := providerSchema(t)
	objType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"server": tftypes.String, "access_token": tftypes.String, "retry_timeout": tftypes.String,
	}}
	acmeType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"key_vault_access_token": tftypes.String, "resource_manager_access_token": tftypes.String,
		"dns_propagation_check": tftypes.Bool, "dns_propagation_timeout": tftypes.String,
	}}
	root := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"azuresql": objType, "acme": acmeType}}
	return provider.ConfigureRequest{Config: tfsdk.Config{
		Schema: resp.Schema,
		Raw: tftypes.NewValue(root, map[string]tftypes.Value{
			"acme": tftypes.NewValue(acmeType, nil),
			"azuresql": tftypes.NewValue(objType, map[string]tftypes.Value{
				"server": server, "access_token": token, "retry_timeout": tftypes.NewValue(tftypes.String, nil),
			}),
		}),
	}}
}

func TestConfigureWithUnknownValuesDoesNotConnect(t *testing.T) {
	t.Parallel()

	unknown := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	known := tftypes.NewValue(tftypes.String, "example.database.windows.net")
	token := tftypes.NewValue(tftypes.String, "a-token")

	for name, req := range map[string]provider.ConfigureRequest{
		"unknown token":  unknownConfig(t, known, unknown),
		"unknown server": unknownConfig(t, unknown, token),
	} {
		var resp provider.ConfigureResponse
		New("test")().Configure(context.Background(), req, &resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("%s: Configure failed: %v", name, resp.Diagnostics)
		}
		data := azureSQLOf(resp.ResourceData)
		if data == nil || data.client != nil || data.reason == "" {
			t.Errorf("%s: want an unusable configuration with a reason, got %+v", name, resp.ResourceData)
		}
	}

	var resp provider.ConfigureResponse
	New("test")().Configure(context.Background(), unknownConfig(t, known, token), &resp)
	data := azureSQLOf(resp.ResourceData)
	if resp.Diagnostics.HasError() || data == nil || data.client == nil {
		t.Errorf("known settings: want a client, got %+v, %v", resp.ResourceData, resp.Diagnostics)
	}
}

func TestRequireClientFailsClosed(t *testing.T) {
	t.Parallel()

	for name, data := range map[string]any{
		"no provider data":   nil,
		"no settings":        &providerData{azuresql: &azureSQL{reason: "not configured"}},
		"no azuresql area":   &providerData{},
		"unexpected payload": "x",
	} {
		var diags diag.Diagnostics
		if c := requireClient(data, &diags); c != nil || !diags.HasError() {
			t.Errorf("%s: client %v, errors %v; want no client and an error", name, c, diags.HasError())
		}
	}
}

// azureSQLOf returns the Azure SQL part of the data Configure produced.
func azureSQLOf(data any) *azureSQL {
	pd, _ := data.(*providerData)
	if pd == nil {
		return nil
	}
	return pd.azuresql
}

func acmeConfig(t *testing.T, kv, rm tftypes.Value, block bool) provider.ConfigureRequest {
	t.Helper()
	null := tftypes.NewValue(tftypes.String, nil)
	return acmeConfigWith(t, kv, rm, tftypes.NewValue(tftypes.Bool, nil), null, block)
}

func acmeConfigWith(t *testing.T, kv, rm, check, timeout tftypes.Value, block bool) provider.ConfigureRequest {
	t.Helper()
	resp := providerSchema(t)
	sqlType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"server": tftypes.String, "access_token": tftypes.String, "retry_timeout": tftypes.String,
	}}
	acmeType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"key_vault_access_token": tftypes.String, "resource_manager_access_token": tftypes.String,
		"dns_propagation_check": tftypes.Bool, "dns_propagation_timeout": tftypes.String,
	}}
	root := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"azuresql": sqlType, "acme": acmeType}}
	acmeValue := tftypes.NewValue(acmeType, nil)
	if block {
		acmeValue = tftypes.NewValue(acmeType, map[string]tftypes.Value{
			"key_vault_access_token": kv, "resource_manager_access_token": rm,
			"dns_propagation_check": check, "dns_propagation_timeout": timeout,
		})
	}
	return provider.ConfigureRequest{Config: tfsdk.Config{Schema: resp.Schema, Raw: tftypes.NewValue(root, map[string]tftypes.Value{
		"azuresql": tftypes.NewValue(sqlType, nil), "acme": acmeValue,
	})}}
}

func TestACMETokensAreSensitive(t *testing.T) {
	t.Parallel()
	nested, ok := providerSchema(t).Schema.Attributes["acme"].(schema.SingleNestedAttribute)
	if !ok || !nested.Optional {
		t.Fatal("acme must be an optional single nested attribute: it is required only when used")
	}
	kv, rm := nested.Attributes["key_vault_access_token"], nested.Attributes["resource_manager_access_token"]
	if !kv.IsSensitive() || !kv.IsRequired() {
		t.Error("key_vault_access_token must be required and sensitive")
	}
	if !rm.IsSensitive() || !rm.IsOptional() {
		t.Error("resource_manager_access_token must be optional and sensitive")
	}
}

func TestConfigureACMEWithUnknownValuesDoesNotPanic(t *testing.T) {
	t.Parallel()
	unknown := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	known := tftypes.NewValue(tftypes.String, "a-token")
	null := tftypes.NewValue(tftypes.String, nil)

	for name, c := range map[string]struct {
		req     provider.ConfigureRequest
		unknown bool
		hasKV   bool
	}{
		"no block":              {acmeConfig(t, null, null, false), false, false},
		"unknown Key Vault":     {acmeConfig(t, unknown, known, true), true, false},
		"unknown Resource Mgr":  {acmeConfig(t, known, unknown, true), false, true},
		"both known":            {acmeConfig(t, known, known, true), false, true},
		"only Key Vault is set": {acmeConfig(t, known, null, true), false, true},
	} {
		var resp provider.ConfigureResponse
		New("test")().Configure(context.Background(), c.req, &resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("%s: %v", name, resp.Diagnostics)
			continue
		}
		pd, _ := resp.ResourceData.(*providerData)
		if pd == nil || pd.acme == nil {
			t.Errorf("%s: no ACME access", name)
			continue
		}
		if pd.acme.unknown != c.unknown || (pd.acme.keyVaultToken != "") != c.hasKV {
			t.Errorf("%s: %+v", name, pd.acme)
		}
		if !c.hasKV && pd.acme.reason == "" {
			t.Errorf("%s: an unusable configuration needs a reason", name)
		}
	}
}

func TestRequireACMENamesTheMissingSetting(t *testing.T) {
	t.Parallel()
	var diags diag.Diagnostics
	if a := requireACME(&providerData{acme: &acmeAccess{reason: "the acme block is not set"}}, &diags, false); a != nil || !diags.HasError() ||
		!strings.Contains(diags.Errors()[0].Detail(), "key_vault_access_token") {
		t.Errorf("a missing Key Vault token: %v", diags)
	}
	diags = nil
	if a := requireACME(&providerData{acme: &acmeAccess{keyVaultToken: "t"}}, &diags, true); a != nil || !diags.HasError() ||
		!strings.Contains(diags.Errors()[0].Detail(), "resource_manager_access_token") {
		t.Errorf("a missing Resource Manager token: %v", diags)
	}
	diags = nil
	if a := requireACME(&providerData{acme: &acmeAccess{keyVaultToken: "t", resourceManagerToken: "r"}}, &diags, true); a == nil || diags.HasError() {
		t.Errorf("complete settings: %v", diags)
	}
	diags = nil
	if a := requireACME(nil, &diags, false); a != nil || !diags.HasError() {
		t.Error("no provider data must fail closed")
	}
}

func TestNewUsesTheProductionEndpoints(t *testing.T) {
	t.Parallel()
	p, ok := New("test")().(*conativeProvider)
	if !ok {
		t.Fatal("unexpected provider type")
	}
	if p.acmeEnv.resourceManagerURL != "https://management.azure.com" || p.acmeEnv.cloudflareURL != "https://api.cloudflare.com/client/v4" || p.acmeEnv.propagationFor != nil {
		t.Errorf("%+v", p.acmeEnv)
	}
}

func TestConfigureACMEPropagationSettings(t *testing.T) {
	t.Parallel()
	token := tftypes.NewValue(tftypes.String, "a-token")
	null := tftypes.NewValue(tftypes.String, nil)
	nullBool := tftypes.NewValue(tftypes.Bool, nil)
	str := func(s string) tftypes.Value { return tftypes.NewValue(tftypes.String, s) }
	boolean := func(b bool) tftypes.Value { return tftypes.NewValue(tftypes.Bool, b) }

	for name, c := range map[string]struct {
		check, timeout tftypes.Value
		want           dnscheck.Checker
	}{
		"defaults": {nullBool, null, dnscheck.Authoritative{
			InitialDelay: 5 * time.Second, Timeout: 2 * time.Minute, Interval: 5 * time.Second,
		}},
		"on with a timeout": {boolean(true), str("90s"), dnscheck.Authoritative{
			InitialDelay: 5 * time.Second, Timeout: 90 * time.Second, Interval: 5 * time.Second,
		}},
		"longest timeout": {nullBool, str("30m"), dnscheck.Authoritative{
			InitialDelay: 5 * time.Second, Timeout: 30 * time.Minute, Interval: 5 * time.Second,
		}},
		"off":                     {boolean(false), null, dnscheck.DelayOnly{Delay: 5 * time.Second}},
		"off ignores the timeout": {boolean(false), str("10m"), dnscheck.DelayOnly{Delay: 5 * time.Second}},
	} {
		var resp provider.ConfigureResponse
		New("test")().Configure(context.Background(), acmeConfigWith(t, token, null, c.check, c.timeout, true), &resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("%s: %v", name, resp.Diagnostics)
			continue
		}
		pd, _ := resp.ResourceData.(*providerData)
		if got := pd.acme.propagation(); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: propagation check %+v, want %+v", name, got, c.want)
		}
	}
}

func TestACMEPropagationTimeoutIsValidated(t *testing.T) {
	t.Parallel()
	nested, ok := providerSchema(t).Schema.Attributes["acme"].(schema.SingleNestedAttribute)
	if !ok {
		t.Fatal("acme must be a single nested attribute")
	}
	attr, ok := nested.Attributes["dns_propagation_timeout"].(schema.StringAttribute)
	if !ok || !attr.IsOptional() {
		t.Fatal("dns_propagation_timeout must be an optional string")
	}
	if b, ok := nested.Attributes["dns_propagation_check"].(schema.BoolAttribute); !ok || !b.IsOptional() {
		t.Fatal("dns_propagation_check must be an optional bool")
	}
	for in, valid := range map[string]bool{
		"10s": true, "2m": true, "90s": true, "30m": true, "1h": false, "9s": false, "30m1s": false,
		"0": false, "-5m": false, "two minutes": false, "": false, "120": false,
	} {
		var resp validator.StringResponse
		for _, v := range attr.Validators {
			v.ValidateString(context.Background(), validator.StringRequest{ConfigValue: types.StringValue(in)}, &resp)
		}
		if got := !resp.Diagnostics.HasError(); got != valid {
			t.Errorf("%q: valid = %v, want %v", in, got, valid)
		}
	}
}
