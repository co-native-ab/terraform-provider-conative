package provider

import (
	"context"
	"testing"

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
	root := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"azuresql": objType}}
	return provider.ConfigureRequest{Config: tfsdk.Config{
		Schema: resp.Schema,
		Raw: tftypes.NewValue(root, map[string]tftypes.Value{
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
		data, _ := resp.ResourceData.(*azureSQL)
		if data == nil || data.client != nil || data.reason == "" {
			t.Errorf("%s: want an unusable configuration with a reason, got %+v", name, resp.ResourceData)
		}
	}

	var resp provider.ConfigureResponse
	New("test")().Configure(context.Background(), unknownConfig(t, known, token), &resp)
	data, _ := resp.ResourceData.(*azureSQL)
	if resp.Diagnostics.HasError() || data == nil || data.client == nil {
		t.Errorf("known settings: want a client, got %+v, %v", resp.ResourceData, resp.Diagnostics)
	}
}

func TestRequireClientFailsClosed(t *testing.T) {
	t.Parallel()

	for name, data := range map[string]any{
		"no provider data":   nil,
		"no settings":        &azureSQL{reason: "not configured"},
		"unexpected payload": "x",
	} {
		var diags diag.Diagnostics
		if c := requireClient(data, &diags); c != nil || !diags.HasError() {
			t.Errorf("%s: client %v, errors %v; want no client and an error", name, c, diags.HasError())
		}
	}
}
