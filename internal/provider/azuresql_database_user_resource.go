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
	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql/sqlclient"
)

var (
	_ resource.Resource                = (*databaseUserResource)(nil)
	_ resource.ResourceWithConfigure   = (*databaseUserResource)(nil)
	_ resource.ResourceWithImportState = (*databaseUserResource)(nil)
)

// NewDatabaseUserResource returns the conative_azuresql_database_user resource.
func NewDatabaseUserResource() resource.Resource { return &databaseUserResource{} }

type databaseUserResource struct {
	data any
}

type databaseUserModel struct {
	ID            types.String `tfsdk:"id"`
	Database      types.String `tfsdk:"database"`
	Name          types.String `tfsdk:"name"`
	Type          types.String `tfsdk:"type"`
	EntraID       types.String `tfsdk:"entra_id"`
	SID           types.String `tfsdk:"sid"`
	PrincipalType types.String `tfsdk:"principal_type"`
}

func (r *databaseUserResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azuresql_database_user"
}

func (r *databaseUserResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	nameCheck := []validator.String{checkString("must be 1 to 128 characters and contain no NUL", azuresql.ValidateName)}
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "Manages a contained database user for a Microsoft Entra application, user or group, " +
			"created from its ID without a directory lookup.\n\n" +
			"Creating the resource fails if a principal with the same name already exists in the database; " +
			"import it instead. Destroying it drops the user and fails, rather than forcing, if the database " +
			"refuses (for example because the user owns a schema or other objects).\n\n" +
			"The database cannot tell an application from a user, so `type` is kept from configuration and is " +
			"not read back. After an import, the first apply records `type` without replacing the user, " +
			"provided the database reports a matching principal type (`EXTERNAL_USER` for `application` and " +
			"`user`, `EXTERNAL_GROUP` for `group`); otherwise the user is replaced.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:   "The import ID, `database/name`.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"database": schema.StringAttribute{
				Description:   "Database name. Changing it replaces the user.",
				Required:      true,
				Validators:    nameCheck,
				PlanModifiers: replace,
			},
			"name": schema.StringAttribute{
				Description: "User name in the database. Any name; it does not need to match the display name in " +
					"Microsoft Entra ID. Changing it replaces the user.",
				Required:      true,
				Validators:    nameCheck,
				PlanModifiers: replace,
			},
			"type": schema.StringAttribute{
				Description: "`application` (service principal or managed identity), `user` or `group`. " +
					"Changing it replaces the user.",
				Required:      true,
				Validators:    []validator.String{checkString("must be one of: "+strings.Join(azuresql.UserTypes(), ", "), azuresql.ValidateUserType)},
				PlanModifiers: []planmodifier.String{userTypeModifier{}},
			},
			"entra_id": schema.StringAttribute{
				Description: "For `application`, the application (client) ID. For `user` and `group`, the object ID. " +
					"A GUID. Changing it replaces the user.",
				Required: true,
				Validators: []validator.String{checkString("must be a GUID such as 00000000-0000-0000-0000-000000000000", func(s string) error {
					_, err := azuresql.ParseEntraID(s)
					return err
				})},
				PlanModifiers: []planmodifier.String{entraIDModifier{}},
			},
			"sid": schema.StringAttribute{
				Description:   "The user's security identifier as reported by the database, as `0x` followed by hexadecimal digits.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"principal_type": schema.StringAttribute{
				Description: "The principal type as reported by the database, for example `EXTERNAL_USER` or " +
					"`EXTERNAL_GROUP`.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *databaseUserResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.data = req.ProviderData
}

func (r *databaseUserResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan databaseUserModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := requireClient(r.data, &resp.Diagnostics)
	if client == nil {
		return
	}
	database, name := plan.Database.ValueString(), plan.Name.ValueString()
	object := fmt.Sprintf("database user %q in database %q", name, database)
	tflog.Debug(ctx, "creating database user", map[string]any{"database": database, "name": name, "type": plan.Type.ValueString()})

	existing, err := client.Count(ctx, database, azuresql.PrincipalExistsQuery, name)
	if err != nil {
		operationError(&resp.Diagnostics, "check for an existing principal", object, err)
		return
	}
	if existing > 0 {
		resp.Diagnostics.AddError("Database principal already exists", fmt.Sprintf(
			"a database principal named %q already exists in database %q; import it with terraform import <address> %s",
			name, database, azuresql.UserID(database, name)))
		return
	}

	sid, err := azuresql.SIDFromEntraID(plan.EntraID.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("entra_id"), "Invalid value", "entra_id "+err.Error())
		return
	}
	stmt, err := azuresql.CreateUserStmt(name, plan.Type.ValueString(), sid)
	if err != nil {
		operationError(&resp.Diagnostics, "create", object, err)
		return
	}
	if err := client.Exec(ctx, database, stmt); err != nil {
		operationError(&resp.Diagnostics, "create", object, err)
		return
	}

	// The user exists from here on. Whatever happens next, record it in state so
	// Terraform marks the resource tainted and replaces or destroys it next run.
	plan.ID = types.StringValue(azuresql.UserID(database, name))
	user, found, err := readUser(ctx, client, database, name)
	switch {
	case err != nil:
		plan.SID, plan.PrincipalType = types.StringNull(), types.StringNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
		operationError(&resp.Diagnostics, "read back", object, err)
		return
	case !found:
		plan.SID, plan.PrincipalType = types.StringNull(), types.StringNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
		operationError(&resp.Diagnostics, "read back", object, fmt.Errorf("the user was not found after it was created"))
		return
	}
	applyUser(&plan, user)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if user.EntraID == nil || !strings.EqualFold(*user.EntraID, plan.EntraID.ValueString()) {
		operationError(&resp.Diagnostics, "read back", object, fmt.Errorf("the database reports a different identifier than the one created"))
	}
}

func (r *databaseUserResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state databaseUserModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := requireClient(r.data, &resp.Diagnostics)
	if client == nil {
		return
	}
	database, name := state.Database.ValueString(), state.Name.ValueString()
	tflog.Debug(ctx, "reading database user", map[string]any{"database": database, "name": name})

	user, found, err := readUser(ctx, client, database, name)
	if !readOrRemove(ctx, &resp.State, &resp.Diagnostics, "read", fmt.Sprintf("database user %q in database %q", name, database), found, err) {
		return
	}
	applyUser(&state, user)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update runs only to record `type` after an import; nothing changes in the database.
func (r *databaseUserResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan databaseUserModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *databaseUserResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state databaseUserModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := requireClient(r.data, &resp.Diagnostics)
	if client == nil {
		return
	}
	database, name := state.Database.ValueString(), state.Name.ValueString()
	tflog.Debug(ctx, "dropping database user", map[string]any{"database": database, "name": name})

	stmt, err := azuresql.DropUserStmt(name)
	if err == nil {
		err = client.Exec(ctx, database, stmt)
	}
	if err != nil {
		operationError(&resp.Diagnostics, "drop", fmt.Sprintf("database user %q in database %q", name, database), err)
	}
}

func (r *databaseUserResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	database, name, err := azuresql.ParseUserID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), azuresql.UserID(database, name))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("database"), database)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}

// readUser reads one user. found is false only when the query succeeded and the user
// does not exist.
func readUser(ctx context.Context, client *sqlclient.Client, database, name string) (azuresql.User, bool, error) {
	rows, err := client.Users(ctx, database, azuresql.ReadUserQuery, name)
	if err != nil || len(rows) == 0 {
		return azuresql.User{}, false, err
	}
	return azuresql.MapUser(rows[0]), true, nil
}

// applyUser copies what the database reports into the model. The Entra ID configured
// in state is kept when it only differs in letter case.
func applyUser(m *databaseUserModel, u azuresql.User) {
	m.SID = types.StringValue(u.SID)
	m.PrincipalType = types.StringValue(u.PrincipalType)
	switch {
	case u.EntraID == nil:
		m.EntraID = types.StringNull()
	case !m.EntraID.IsNull() && !m.EntraID.IsUnknown() && strings.EqualFold(m.EntraID.ValueString(), *u.EntraID):
		// keep the configured spelling
	default:
		m.EntraID = types.StringValue(*u.EntraID)
	}
}
