package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql"
)

var (
	_ resource.Resource                = (*databaseRoleMemberResource)(nil)
	_ resource.ResourceWithConfigure   = (*databaseRoleMemberResource)(nil)
	_ resource.ResourceWithImportState = (*databaseRoleMemberResource)(nil)
)

// NewDatabaseRoleMemberResource returns the conative_azuresql_database_role_member resource.
func NewDatabaseRoleMemberResource() resource.Resource { return &databaseRoleMemberResource{} }

type databaseRoleMemberResource struct {
	data any
}

type databaseRoleMemberModel struct {
	ID       types.String `tfsdk:"id"`
	Database types.String `tfsdk:"database"`
	Role     types.String `tfsdk:"role"`
	Member   types.String `tfsdk:"member"`
}

func (r *databaseRoleMemberResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azuresql_database_role_member"
}

func (r *databaseRoleMemberResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	nameCheck := []validator.String{checkString("must be 1 to 128 characters and contain no NUL", azuresql.ValidateName)}
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "Makes a database user a member of one fixed database role, for example `db_owner`. " +
			"The resource adds and removes exactly that one membership; the user and its other memberships " +
			"are never touched.\n\nOnly the fixed database roles are supported. Creating the resource fails " +
			"if the user is already a member; import the membership instead.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:   "The import ID, `database/role/member`.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"database": schema.StringAttribute{
				Description:   "Database name. Changing it replaces the membership.",
				Required:      true,
				Validators:    nameCheck,
				PlanModifiers: replace,
			},
			"role": schema.StringAttribute{
				Description: "A fixed database role: " + strings.Join(azuresql.FixedRoles(), ", ") +
					". Changing it replaces the membership.",
				Required:      true,
				Validators:    []validator.String{checkString("must be a fixed database role", azuresql.ValidateRole)},
				PlanModifiers: replace,
			},
			"member": schema.StringAttribute{
				Description:   "Name of the database user. Changing it replaces the membership.",
				Required:      true,
				Validators:    nameCheck,
				PlanModifiers: replace,
			},
		},
	}
}

func (r *databaseRoleMemberResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.data = req.ProviderData
}

func (m databaseRoleMemberModel) object() string {
	return fmt.Sprintf("membership of %q in role %q of database %q", m.Member.ValueString(), m.Role.ValueString(), m.Database.ValueString())
}

func (r *databaseRoleMemberResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan databaseRoleMemberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := requireClient(r.data, &resp.Diagnostics)
	if client == nil {
		return
	}
	database, role, member := plan.Database.ValueString(), plan.Role.ValueString(), plan.Member.ValueString()
	tflog.Debug(ctx, "adding role member", map[string]any{"database": database, "role": role, "member": member})

	n, err := client.Count(ctx, database, azuresql.RoleMembershipQuery, role, member)
	if err != nil {
		operationError(&resp.Diagnostics, "check the existing membership of", plan.object(), err)
		return
	}
	id := azuresql.RoleMemberID(database, role, member)
	if n > 0 {
		resp.Diagnostics.AddError("Role membership already exists", fmt.Sprintf(
			"%q is already a member of role %q in database %q; import it with terraform import <address> %s",
			member, role, database, id))
		return
	}

	stmt, err := azuresql.AddRoleMemberStmt(role, member)
	if err == nil {
		err = client.Exec(ctx, database, stmt)
	}
	if err != nil {
		operationError(&resp.Diagnostics, "add", plan.object(), err)
		return
	}
	plan.ID = types.StringValue(id)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *databaseRoleMemberResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state databaseRoleMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := requireClient(r.data, &resp.Diagnostics)
	if client == nil {
		return
	}
	database, role, member := state.Database.ValueString(), state.Role.ValueString(), state.Member.ValueString()
	tflog.Debug(ctx, "reading role member", map[string]any{"database": database, "role": role, "member": member})

	n, err := client.Count(ctx, database, azuresql.RoleMembershipQuery, role, member)
	if !readOrRemove(ctx, &resp.State, &resp.Diagnostics, "read", state.object(), n > 0, err) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update is never called: every attribute change replaces the membership.
func (r *databaseRoleMemberResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update is not supported", "every change to a role membership replaces it")
}

func (r *databaseRoleMemberResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state databaseRoleMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := requireClient(r.data, &resp.Diagnostics)
	if client == nil {
		return
	}
	database, role, member := state.Database.ValueString(), state.Role.ValueString(), state.Member.ValueString()
	tflog.Debug(ctx, "removing role member", map[string]any{"database": database, "role": role, "member": member})

	stmt, err := azuresql.DropRoleMemberStmt(role, member)
	if err == nil {
		err = client.Exec(ctx, database, stmt)
	}
	if err != nil {
		operationError(&resp.Diagnostics, "remove", state.object(), err)
	}
}

func (r *databaseRoleMemberResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	database, role, member, err := azuresql.ParseRoleMemberID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	if err := azuresql.ValidateRole(role); err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), azuresql.RoleMemberID(database, role, member))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("database"), database)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role"), role)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("member"), member)...)
}
