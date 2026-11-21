package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// stringCheck adapts a plain validation function to a string attribute validator, so
// the rules stay in the pure core and the provider only wires them.
type stringCheck struct {
	description string
	check       func(string) error
}

func checkString(description string, check func(string) error) validator.String {
	return stringCheck{description: description, check: check}
}

func (v stringCheck) Description(context.Context) string         { return v.description }
func (v stringCheck) MarkdownDescription(context.Context) string { return v.description }

func (v stringCheck) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if err := v.check(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value", err.Error())
	}
}
