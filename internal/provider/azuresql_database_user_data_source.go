package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql"
)

var (
	_ datasource.DataSource              = (*databaseUserDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*databaseUserDataSource)(nil)
)

// NewDatabaseUserDataSource returns the conative_azuresql_database_user data source.
func NewDatabaseUserDataSource() datasource.DataSource { return &databaseUserDataSource{} }

type databaseUserDataSource struct {
	data any
}

type databaseUserDataSourceModel struct {
	ID            types.String `tfsdk:"id"`
	Database      types.String `tfsdk:"database"`
	Name          types.String `tfsdk:"name"`
	SID           types.String `tfsdk:"sid"`
	PrincipalType types.String `tfsdk:"principal_type"`
	EntraID       types.String `tfsdk:"entra_id"`
}

func (d *databaseUserDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azuresql_database_user"
}

func (d *databaseUserDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	nameCheck := []validator.String{checkString("must be 1 to 128 characters and contain no NUL", azuresql.ValidateName)}
	resp.Schema = schema.Schema{
		Description: "Reads one database user by name. The data source fails if the user does not exist; " +
			"use `conative_azuresql_database_users` to check for existence without failing.",
		Attributes: map[string]schema.Attribute{
			"id":       schema.StringAttribute{Description: "The import ID of the user, `database/name`.", Computed: true},
			"database": schema.StringAttribute{Description: "Database name.", Required: true, Validators: nameCheck},
			"name":     schema.StringAttribute{Description: "User name.", Required: true, Validators: nameCheck},
			"sid": schema.StringAttribute{
				Description: "The user's security identifier as reported by the database, as `0x` followed by hexadecimal digits.",
				Computed:    true,
			},
			"principal_type": schema.StringAttribute{
				Description: "The principal type as reported by the database, for example `EXTERNAL_USER`, " +
					"`EXTERNAL_GROUP` or `SQL_USER`.",
				Computed: true,
			},
			"entra_id": schema.StringAttribute{
				Description: "The Entra ID the security identifier was derived from. Null when it cannot be derived, " +
					"for example for a user that is not an external user.",
				Computed: true,
			},
		},
	}
}

func (d *databaseUserDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	d.data = req.ProviderData
}

func (d *databaseUserDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg databaseUserDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := requireClient(d.data, &resp.Diagnostics)
	if client == nil {
		return
	}
	database, name := cfg.Database.ValueString(), cfg.Name.ValueString()
	tflog.Debug(ctx, "reading database user data source", map[string]any{"database": database, "name": name})

	rows, err := client.Users(ctx, database, azuresql.DataSourceUserQuery, name)
	if err != nil {
		operationError(&resp.Diagnostics, "read", fmt.Sprintf("database user %q in database %q", name, database), err)
		return
	}
	if len(rows) == 0 {
		resp.Diagnostics.AddError("Database user not found", fmt.Sprintf("database user %q not found in database %q", name, database))
		return
	}
	u := azuresql.MapUser(rows[0])
	cfg.ID = types.StringValue(azuresql.UserID(database, name))
	cfg.SID = types.StringValue(u.SID)
	cfg.PrincipalType = types.StringValue(u.PrincipalType)
	cfg.EntraID = types.StringPointerValue(u.EntraID)
	resp.Diagnostics.Append(resp.State.Set(ctx, cfg)...)
}
