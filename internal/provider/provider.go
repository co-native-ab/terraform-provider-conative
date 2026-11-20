// Package provider implements the conative Terraform provider.
package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql"
	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql/sqlclient"
)

var _ provider.Provider = (*conativeProvider)(nil)

type conativeProvider struct {
	version string
}

// New returns a provider factory for the given provider version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &conativeProvider{version: version}
	}
}

type providerModel struct {
	AzureSQL types.Object `tfsdk:"azuresql"`
}

type azureSQLModel struct {
	Server       types.String `tfsdk:"server"`
	AccessToken  types.String `tfsdk:"access_token"`
	RetryTimeout types.String `tfsdk:"retry_timeout"`
}

func (p *conativeProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "conative"
	resp.Version = p.version
}

func (p *conativeProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages resources that the major cloud providers do not cover, or do not cover well. " +
			"The first area is Azure SQL Database: Microsoft Entra principals as contained database users, " +
			"their role memberships and their permissions.",
		Attributes: map[string]schema.Attribute{
			"azuresql": schema.SingleNestedAttribute{
				Description: "Settings for Azure SQL Database resources and data sources. " +
					"Required only when one of them is used.",
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"server": schema.StringAttribute{
						Description: "Fully qualified name of the logical server, optionally with `:port` (default 1433). " +
							"One provider configuration manages one server; use provider aliases for more.",
						Required:   true,
						Validators: []validator.String{checkString("must be a host name, optionally with :port", parseServerOnly)},
					},
					"access_token": schema.StringAttribute{
						Description: "A Microsoft Entra access token for `https://database.windows.net/.default`. " +
							"The provider never signs in by itself, never stores the token and never writes it to logs. " +
							"Supply it from an ephemeral resource or ephemeral variable.",
						Required:  true,
						Sensitive: true,
					},
					"retry_timeout": schema.StringAttribute{
						Description: "Maximum total time to keep retrying a connection that fails with an error Microsoft " +
							"documents as transient. A duration such as `\"2m\"` (the default) or `\"0s\"` to disable. " +
							"Other errors are never retried.",
						Optional:   true,
						Validators: []validator.String{checkString("must be a duration such as 2m", validateDuration)},
					},
				},
			},
		},
	}
}

func parseServerOnly(s string) error {
	_, _, err := azuresql.ParseServer(s)
	return err
}

func validateDuration(s string) error {
	_, err := parseRetryTimeout(s)
	return err
}

func parseRetryTimeout(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q must be a duration such as 2m", s)
	}
	if d < 0 {
		return 0, fmt.Errorf("%q must not be negative", s)
	}
	return d, nil
}

func (p *conativeProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	access := &azureSQL{}
	switch {
	case cfg.AzureSQL.IsNull():
		access.reason = "the azuresql block is not set"
	case cfg.AzureSQL.IsUnknown():
		access.reason = "the azuresql block is not known until apply"
	default:
		var settings azureSQLModel
		resp.Diagnostics.Append(cfg.AzureSQL.As(ctx, &settings, basetypes.ObjectAsOptions{})...)
		if resp.Diagnostics.HasError() {
			return
		}
		access = newAzureSQL(settings, resp)
	}
	resp.ResourceData = access
	resp.DataSourceData = access
}

// newAzureSQL turns the settings into a client, or records why it cannot.
func newAzureSQL(s azureSQLModel, resp *provider.ConfigureResponse) *azureSQL {
	switch {
	case s.Server.IsUnknown():
		return &azureSQL{reason: "azuresql.server is not known until apply"}
	case s.AccessToken.IsUnknown():
		return &azureSQL{reason: "azuresql.access_token is not known until apply"}
	case s.Server.IsNull():
		return &azureSQL{reason: "azuresql.server is not set"}
	case s.AccessToken.IsNull():
		return &azureSQL{reason: "azuresql.access_token is not set"}
	case s.RetryTimeout.IsUnknown():
		return &azureSQL{reason: "azuresql.retry_timeout is not known until apply"}
	}

	timeout := sqlclient.DefaultRetryTimeout
	if !s.RetryTimeout.IsNull() {
		d, err := parseRetryTimeout(s.RetryTimeout.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("azuresql").AtName("retry_timeout"), "Invalid value", err.Error())
			return &azureSQL{reason: "azuresql.retry_timeout is invalid"}
		}
		timeout = d
	}
	return &azureSQL{client: sqlclient.New(sqlclient.Settings{
		Server:       s.Server.ValueString(),
		Token:        s.AccessToken.ValueString(),
		RetryTimeout: timeout,
	})}
}

func (p *conativeProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewDatabaseUserResource,
		NewDatabaseRoleMemberResource,
		NewDatabasePermissionResource,
	}
}

func (p *conativeProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}
