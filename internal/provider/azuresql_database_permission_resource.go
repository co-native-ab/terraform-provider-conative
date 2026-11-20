package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql"
	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql/sqlclient"
)

var (
	_ resource.Resource                   = (*databasePermissionResource)(nil)
	_ resource.ResourceWithConfigure      = (*databasePermissionResource)(nil)
	_ resource.ResourceWithImportState    = (*databasePermissionResource)(nil)
	_ resource.ResourceWithValidateConfig = (*databasePermissionResource)(nil)
)

// NewDatabasePermissionResource returns the conative_azuresql_database_permission resource.
func NewDatabasePermissionResource() resource.Resource { return &databasePermissionResource{} }

type databasePermissionResource struct {
	data any
}

type databasePermissionModel struct {
	ID         types.String `tfsdk:"id"`
	Database   types.String `tfsdk:"database"`
	Principal  types.String `tfsdk:"principal"`
	State      types.String `tfsdk:"state"`
	Permission types.String `tfsdk:"permission"`
	Schema     types.String `tfsdk:"schema"`
}

func (r *databasePermissionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azuresql_database_permission"
}

func (r *databasePermissionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	nameCheck := []validator.String{checkString("must be 1 to 128 characters and contain no NUL", azuresql.ValidateName)}
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "Grants or denies one permission to a database principal, on the database or on one schema. " +
			"The resource manages exactly that one permission; nothing else changes.\n\n" +
			"The provider never grants with grant option, and destroying the resource revokes exactly this " +
			"permission without cascading. A permission that was granted with grant option outside Terraform " +
			"is reported as `GRANT_WITH_GRANT_OPTION`, which shows as a difference and plans a replacement; " +
			"the revoke then fails until the grant option is removed.\n\n" +
			"Creating the resource fails if the principal already holds the permission in any state, " +
			"including the `CONNECT` permission that every new database user receives; import it instead.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The import ID, `database/principal/STATE/PERMISSION`, with `/schema` appended for a " +
					"schema-level permission.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"database": schema.StringAttribute{
				Description:   "Database name. Changing it replaces the permission.",
				Required:      true,
				Validators:    nameCheck,
				PlanModifiers: replace,
			},
			"principal": schema.StringAttribute{
				Description:   "Name of the database principal, a user or a role. Changing it replaces the permission.",
				Required:      true,
				Validators:    nameCheck,
				PlanModifiers: replace,
			},
			"state": schema.StringAttribute{
				Description: "`GRANT` or `DENY`. When read from the database it can also be `GRANT_WITH_GRANT_OPTION`. " +
					"Changing it replaces the permission.",
				Required:      true,
				Validators:    []validator.String{checkString("must be GRANT or DENY", azuresql.ValidatePermissionState)},
				PlanModifiers: replace,
			},
			"permission": schema.StringAttribute{
				Description: "The permission, in upper case, for example `VIEW DEFINITION` or `SELECT`. It must be " +
					"valid for the database, or for a schema when `schema` is set. Changing it replaces the permission.",
				Required:      true,
				PlanModifiers: replace,
			},
			"schema": schema.StringAttribute{
				Description: "Name of a schema. When set, the permission applies to that schema; otherwise it " +
					"applies to the database. Changing it replaces the permission.",
				Optional:      true,
				Validators:    nameCheck,
				PlanModifiers: replace,
			},
		},
	}
}

// ValidateConfig checks the permission against the allowlist for its scope before any
// statement runs.
func (r *databasePermissionResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg databasePermissionModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() || cfg.Permission.IsNull() || cfg.Permission.IsUnknown() || cfg.Schema.IsUnknown() {
		return
	}
	scope := azuresql.ScopeDatabase
	if !cfg.Schema.IsNull() {
		scope = azuresql.ScopeSchema
	}
	if err := azuresql.ValidatePermission(scope, cfg.Permission.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("permission"), "Invalid permission", err.Error())
	}
}

func (r *databasePermissionResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.data = req.ProviderData
}

func (m databasePermissionModel) permission() azuresql.Permission {
	return azuresql.Permission{
		Principal:  m.Principal.ValueString(),
		State:      m.State.ValueString(),
		Permission: m.Permission.ValueString(),
		Schema:     m.Schema.ValueString(),
	}
}

func (m databasePermissionModel) object() string {
	if m.Schema.IsNull() {
		return fmt.Sprintf("permission %s for %q on database %q", m.Permission.ValueString(), m.Principal.ValueString(), m.Database.ValueString())
	}
	return fmt.Sprintf("permission %s for %q on schema %q of database %q", m.Permission.ValueString(), m.Principal.ValueString(), m.Schema.ValueString(), m.Database.ValueString())
}

// readPermissionState returns the state the database reports for a permission. When
// several grantors hold rows for the same permission, DENY wins over a grant with
// grant option, which wins over a plain grant. found is false only when the query
// succeeded and no row exists.
func readPermissionState(ctx context.Context, client *sqlclient.Client, database string, p azuresql.Permission) (state string, found bool, err error) {
	query, args := azuresql.PermissionQuery(p)
	codes, err := client.Strings(ctx, database, query, args...)
	if err != nil || len(codes) == 0 {
		return "", false, err
	}
	rank := map[string]int{azuresql.StateGrant: 1, azuresql.StateGrantWithGrantOption: 2, azuresql.StateDeny: 3}
	for _, code := range codes {
		s, err := azuresql.MapPermissionState(code)
		if err != nil {
			return "", false, err
		}
		if rank[s] > rank[state] {
			state = s
		}
	}
	return state, true, nil
}

func (r *databasePermissionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan databasePermissionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := requireClient(r.data, &resp.Diagnostics)
	if client == nil {
		return
	}
	database, p := plan.Database.ValueString(), plan.permission()
	tflog.Debug(ctx, "setting permission", map[string]any{"database": database, "principal": p.Principal, "state": p.State, "permission": p.Permission, "schema": p.Schema})

	id := azuresql.PermissionID(database, p.Principal, p.State, p.Permission, p.Schema)
	existing, found, err := readPermissionState(ctx, client, database, p)
	if err != nil {
		operationError(&resp.Diagnostics, "check the existing", plan.object(), err)
		return
	}
	if found {
		resp.Diagnostics.AddError("Permission already exists", fmt.Sprintf(
			"%q already holds permission %s in state %s in database %q; import it with terraform import <address> %s",
			p.Principal, p.Permission, existing, database,
			azuresql.PermissionID(database, p.Principal, existingImportState(existing), p.Permission, p.Schema)))
		return
	}

	stmt, err := azuresql.GrantStmt(p)
	if err == nil {
		err = client.Exec(ctx, database, stmt)
	}
	if err != nil {
		operationError(&resp.Diagnostics, "set", plan.object(), err)
		return
	}
	reported, found, err := readPermissionState(ctx, client, database, p)
	if err != nil {
		operationError(&resp.Diagnostics, "read back", plan.object(), err)
		return
	}
	if !found || reported != p.State {
		operationError(&resp.Diagnostics, "read back", plan.object(),
			fmt.Errorf("the database reports state %q (found: %t) instead of %s", reported, found, p.State))
		return
	}
	plan.ID = types.StringValue(id)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// existingImportState is the state to put in an import ID for an existing permission.
func existingImportState(reported string) string {
	if reported == azuresql.StateGrantWithGrantOption {
		return azuresql.StateGrant
	}
	return reported
}

func (r *databasePermissionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state databasePermissionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := requireClient(r.data, &resp.Diagnostics)
	if client == nil {
		return
	}
	database, p := state.Database.ValueString(), state.permission()
	tflog.Debug(ctx, "reading permission", map[string]any{"database": database, "principal": p.Principal, "permission": p.Permission, "schema": p.Schema})

	reported, found, err := readPermissionState(ctx, client, database, p)
	if !readOrRemove(ctx, &resp.State, &resp.Diagnostics, "read", state.object(), found, err) {
		return
	}
	state.State = types.StringValue(reported)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update is never called: every attribute change replaces the permission.
func (r *databasePermissionResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update is not supported", "every change to a permission replaces it")
}

func (r *databasePermissionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state databasePermissionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := requireClient(r.data, &resp.Diagnostics)
	if client == nil {
		return
	}
	database, p := state.Database.ValueString(), state.permission()
	tflog.Debug(ctx, "revoking permission", map[string]any{"database": database, "principal": p.Principal, "permission": p.Permission, "schema": p.Schema})

	stmt, err := azuresql.RevokeStmt(p)
	if err == nil {
		err = client.Exec(ctx, database, stmt)
	}
	if err != nil {
		operationError(&resp.Diagnostics, "revoke", state.object(), err)
	}
}

func (r *databasePermissionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	database, principal, state, permission, schemaName, err := azuresql.ParsePermissionID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	if err := azuresql.ValidatePermissionState(state); err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	scope := azuresql.ScopeDatabase
	if schemaName != "" {
		scope = azuresql.ScopeSchema
	}
	if err := azuresql.ValidatePermission(scope, permission); err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), azuresql.PermissionID(database, principal, state, permission, schemaName))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("database"), database)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("principal"), principal)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("state"), state)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("permission"), permission)...)
	if schemaName != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("schema"), schemaName)...)
	}
}
