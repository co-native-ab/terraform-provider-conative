package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql"
)

var (
	_ datasource.DataSource              = (*databaseUsersDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*databaseUsersDataSource)(nil)
)

// NewDatabaseUsersDataSource returns the conative_azuresql_database_users data source.
func NewDatabaseUsersDataSource() datasource.DataSource { return &databaseUsersDataSource{} }

type databaseUsersDataSource struct {
	data any
}

type databaseUsersDataSourceModel struct {
	ID            types.String `tfsdk:"id"`
	Database      types.String `tfsdk:"database"`
	Name          types.String `tfsdk:"name"`
	PrincipalType types.String `tfsdk:"principal_type"`
	Users         types.List   `tfsdk:"users"`
}

var userObjectType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"name":           types.StringType,
	"sid":            types.StringType,
	"principal_type": types.StringType,
	"entra_id":       types.StringType,
}}

func (d *databaseUsersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azuresql_database_users"
}

func (d *databaseUsersDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	nameCheck := []validator.String{checkString("must be 1 to 128 characters and contain no NUL", azuresql.ValidateName)}
	resp.Schema = schema.Schema{
		Description: "Lists the users of a database, optionally filtered. An empty result is not an error. " +
			"The built-in principals `public`, `dbo`, `guest`, `INFORMATION_SCHEMA` and `sys` are not listed.",
		Attributes: map[string]schema.Attribute{
			"id":       schema.StringAttribute{Description: "The database name.", Computed: true},
			"database": schema.StringAttribute{Description: "Database name.", Required: true, Validators: nameCheck},
			"name": schema.StringAttribute{
				Description: "Return only the user with exactly this name.",
				Optional:    true,
				Validators:  nameCheck,
			},
			"principal_type": schema.StringAttribute{
				Description: "Return only users of this principal type, as the database reports it: " +
					strings.Join(azuresql.PrincipalTypes(), ", ") + ".",
				Optional:   true,
				Validators: []validator.String{checkString("must be a database user type", azuresql.ValidatePrincipalType)},
			},
			"users": schema.ListNestedAttribute{
				Description: "The matching users, ordered by name.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{Description: "User name.", Computed: true},
					"sid": schema.StringAttribute{
						Description: "The security identifier as `0x` followed by hexadecimal digits.",
						Computed:    true,
					},
					"principal_type": schema.StringAttribute{Description: "The principal type as reported by the database.", Computed: true},
					"entra_id": schema.StringAttribute{
						Description: "The Entra ID the security identifier was derived from, or null when it cannot be derived.",
						Computed:    true,
					},
				}},
			},
		},
	}
}

func (d *databaseUsersDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	d.data = req.ProviderData
}

func (d *databaseUsersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg databaseUsersDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := requireClient(d.data, &resp.Diagnostics)
	if client == nil {
		return
	}
	database := cfg.Database.ValueString()
	tflog.Debug(ctx, "reading database users data source", map[string]any{"database": database})

	// A null filter matches everything; the query treats NULL as "no filter".
	rows, err := client.Users(ctx, database, azuresql.DataSourceUsersQuery,
		nullableString(cfg.Name), nullableString(cfg.PrincipalType))
	if err != nil {
		operationError(&resp.Diagnostics, "list users of", fmt.Sprintf("database %q", database), err)
		return
	}

	users := make([]attr.Value, 0, len(rows))
	for _, row := range rows {
		u := azuresql.MapUser(row)
		obj, diags := types.ObjectValue(userObjectType.AttrTypes, map[string]attr.Value{
			"name":           types.StringValue(u.Name),
			"sid":            types.StringValue(u.SID),
			"principal_type": types.StringValue(u.PrincipalType),
			"entra_id":       types.StringPointerValue(u.EntraID),
		})
		resp.Diagnostics.Append(diags...)
		users = append(users, obj)
	}
	list, diags := types.ListValue(userObjectType, users)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg.ID = types.StringValue(database)
	cfg.Users = list
	resp.Diagnostics.Append(resp.State.Set(ctx, cfg)...)
}

// nullableString returns the value as a query parameter, or nil for a null value.
func nullableString(s types.String) any {
	if s.IsNull() || s.IsUnknown() {
		return nil
	}
	return s.ValueString()
}
