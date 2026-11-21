package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"

	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql"
)

// userTypeModifier decides whether a change of `type` replaces the database user.
//
// The catalog cannot tell an application from a user, so `type` is never read back:
// it is kept from state and is empty after an import. A change from a known type
// replaces the user. After an import the first plan only records the type, provided
// the principal type the database reports fits it; otherwise the user is replaced.
type userTypeModifier struct{}

func (userTypeModifier) Description(context.Context) string {
	return "Replaces the user when the type changes. After an import, records the type without " +
		"replacing the user if the database reports a matching principal type."
}

func (m userTypeModifier) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (userTypeModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return // create or destroy
	}
	if req.PlanValue.IsUnknown() || req.PlanValue.IsNull() {
		return
	}

	var prior *string
	if !req.StateValue.IsNull() {
		v := req.StateValue.ValueString()
		prior = &v
	}
	var principalType string
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("principal_type"), &principalType)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if azuresql.TypePlanDecision(prior, req.PlanValue.ValueString(), principalType) == azuresql.TypeReplace {
		resp.RequiresReplace = true
	}
}

// entraIDModifier replaces the user when the Entra ID changes, ignoring letter case:
// GUIDs are case-insensitive, and the ID the database reports is lower case.
type entraIDModifier struct{}

func (entraIDModifier) Description(context.Context) string {
	return "Replaces the user when the Entra ID changes. Letter case is ignored."
}

func (m entraIDModifier) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (entraIDModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	if req.StateValue.IsNull() || !strings.EqualFold(req.StateValue.ValueString(), req.PlanValue.ValueString()) {
		resp.RequiresReplace = true
	}
}
