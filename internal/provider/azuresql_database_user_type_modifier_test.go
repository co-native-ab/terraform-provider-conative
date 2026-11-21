package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func userObjectValue(typeAttr, principalType, entraID tftypes.Value) tftypes.Value {
	str := tftypes.String
	obj := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id": str, "database": str, "name": str, "type": str, "entra_id": str, "sid": str, "principal_type": str,
	}}
	return tftypes.NewValue(obj, map[string]tftypes.Value{
		"id":             tftypes.NewValue(str, "db/u"),
		"database":       tftypes.NewValue(str, "db"),
		"name":           tftypes.NewValue(str, "u"),
		"type":           typeAttr,
		"entra_id":       entraID,
		"sid":            tftypes.NewValue(str, "0x00"),
		"principal_type": principalType,
	})
}

func sv(s string) tftypes.Value { return tftypes.NewValue(tftypes.String, s) }

func nullString() tftypes.Value { return tftypes.NewValue(tftypes.String, nil) }

func modifierRequest(t *testing.T, stateType, statePrincipal, stateEntra, planType, planEntra tftypes.Value, attribute string) planmodifier.StringRequest {
	t.Helper()
	var sch resource.SchemaResponse
	NewDatabaseUserResource().Schema(context.Background(), resource.SchemaRequest{}, &sch)
	state := tfsdk.State{Schema: sch.Schema, Raw: userObjectValue(stateType, statePrincipal, stateEntra)}
	plan := tfsdk.Plan{Schema: sch.Schema, Raw: userObjectValue(planType, statePrincipal, planEntra)}

	req := planmodifier.StringRequest{Path: path.Root(attribute), State: state, Plan: plan}
	switch attribute {
	case "type":
		req.StateValue, req.PlanValue = typesString(stateType), typesString(planType)
	case "entra_id":
		req.StateValue, req.PlanValue = typesString(stateEntra), typesString(planEntra)
	}
	return req
}

func typesString(v tftypes.Value) types.String {
	if v.IsNull() {
		return types.StringNull()
	}
	var s string
	_ = v.As(&s)
	return types.StringValue(s)
}

func TestUserTypeModifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                               string
		stateType, principalType, planType tftypes.Value
		wantReplace                        bool
	}{
		{"unchanged", sv("application"), sv("EXTERNAL_USER"), sv("application"), false},
		{"changed from a known type", sv("application"), sv("EXTERNAL_USER"), sv("user"), true},
		{"imported application", nullString(), sv("EXTERNAL_USER"), sv("application"), false},
		{"imported user", nullString(), sv("EXTERNAL_USER"), sv("user"), false},
		{"imported group", nullString(), sv("EXTERNAL_GROUP"), sv("group"), false},
		{"imported group, reported as user", nullString(), sv("EXTERNAL_USER"), sv("group"), true},
		{"imported application, reported as group", nullString(), sv("EXTERNAL_GROUP"), sv("application"), true},
		{"imported application, reported as SQL user", nullString(), sv("SQL_USER"), sv("application"), true},
	}
	for _, tt := range tests {
		req := modifierRequest(t, tt.stateType, tt.principalType, sv(someEntraID), tt.planType, sv(someEntraID), "type")
		var resp planmodifier.StringResponse
		userTypeModifier{}.PlanModifyString(context.Background(), req, &resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("%s: %v", tt.name, resp.Diagnostics)
		}
		if resp.RequiresReplace != tt.wantReplace {
			t.Errorf("%s: RequiresReplace = %t, want %t", tt.name, resp.RequiresReplace, tt.wantReplace)
		}
	}
}

func TestUserTypeModifierIgnoresCreate(t *testing.T) {
	t.Parallel()

	var sch resource.SchemaResponse
	NewDatabaseUserResource().Schema(context.Background(), resource.SchemaRequest{}, &sch)
	req := planmodifier.StringRequest{
		State:     tfsdk.State{Schema: sch.Schema, Raw: tftypes.NewValue(userObjectValue(nullString(), nullString(), nullString()).Type(), nil)},
		Plan:      tfsdk.Plan{Schema: sch.Schema, Raw: userObjectValue(sv("user"), nullString(), sv(someEntraID))},
		PlanValue: types.StringValue("user"),
	}
	var resp planmodifier.StringResponse
	userTypeModifier{}.PlanModifyString(context.Background(), req, &resp)
	if resp.RequiresReplace || resp.Diagnostics.HasError() {
		t.Errorf("create: RequiresReplace = %t, diagnostics = %v", resp.RequiresReplace, resp.Diagnostics)
	}
}

func TestEntraIDModifier(t *testing.T) {
	t.Parallel()

	upper := "ABCDEF00-0000-0000-0000-000000000001"
	lower := "abcdef00-0000-0000-0000-000000000001"
	other := "abcdef00-0000-0000-0000-000000000002"
	tests := []struct {
		name        string
		state, plan tftypes.Value
		want        bool
	}{
		{"same", sv(lower), sv(lower), false},
		{"only the case differs", sv(lower), sv(upper), false},
		{"different", sv(lower), sv(other), true},
		{"state empty after importing a SQL user", nullString(), sv(lower), true},
	}
	for _, tt := range tests {
		req := modifierRequest(t, sv("application"), sv("EXTERNAL_USER"), tt.state, sv("application"), tt.plan, "entra_id")
		var resp planmodifier.StringResponse
		entraIDModifier{}.PlanModifyString(context.Background(), req, &resp)
		if resp.RequiresReplace != tt.want {
			t.Errorf("%s: RequiresReplace = %t, want %t", tt.name, resp.RequiresReplace, tt.want)
		}
	}
}
