package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
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

// setCheck validates every element of a set of strings with a plain function, and
// optionally requires at least one element.
type setCheck struct {
	description string
	check       func(string) error
	nonEmpty    bool
}

func checkStringSet(description string, nonEmpty bool, check func(string) error) validator.Set {
	return setCheck{description: description, check: check, nonEmpty: nonEmpty}
}

func (v setCheck) Description(context.Context) string         { return v.description }
func (v setCheck) MarkdownDescription(context.Context) string { return v.description }

func (v setCheck) ValidateSet(_ context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	elems := req.ConfigValue.Elements()
	if v.nonEmpty && len(elems) == 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value", "must contain at least one entry")
	}
	for _, e := range elems {
		s, ok := e.(basetypes.StringValue)
		if !ok || s.IsNull() || s.IsUnknown() {
			continue
		}
		if err := v.check(s.ValueString()); err != nil {
			resp.Diagnostics.AddAttributeError(req.Path, "Invalid value", err.Error())
		}
	}
}

// atLeastOne requires an integer of at least one.
type atLeastOne struct{}

func (atLeastOne) Description(context.Context) string         { return "must be at least 1" }
func (atLeastOne) MarkdownDescription(context.Context) string { return "must be at least 1" }

func (atLeastOne) ValidateInt64(_ context.Context, req validator.Int64Request, resp *validator.Int64Response) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if req.ConfigValue.ValueInt64() < 1 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value", "must be at least 1")
	}
}
