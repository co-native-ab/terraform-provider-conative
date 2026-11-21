package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme"
)

// vaultURLType is a string that holds a Key Vault URL. Two values are semantically equal
// when they name the same vault: a trailing slash and the case of the host do not
// matter. The framework then keeps the value already in state, so another spelling of
// the URL never shows as a change, whether it comes from the configuration, from an
// import or from a refresh.
type vaultURLType struct {
	basetypes.StringType
}

var (
	_ basetypes.StringTypable                    = vaultURLType{}
	_ basetypes.StringValuableWithSemanticEquals = vaultURLValue{}
)

func (t vaultURLType) Equal(o attr.Type) bool {
	other, ok := o.(vaultURLType)
	return ok && t.StringType.Equal(other.StringType)
}

func (t vaultURLType) String() string { return "vaultURLType" }

func (t vaultURLType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return vaultURLValue{StringValue: in}, nil
}

func (t vaultURLType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	v, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	s, ok := v.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T", v)
	}
	out, diags := t.ValueFromString(ctx, s)
	if diags.HasError() {
		return nil, fmt.Errorf("converting the value: %v", diags)
	}
	return out, nil
}

func (t vaultURLType) ValueType(context.Context) attr.Value { return vaultURLValue{} }

// vaultURLValue is the value of a vaultURLType.
type vaultURLValue struct {
	basetypes.StringValue
}

func newVaultURL(s string) vaultURLValue {
	return vaultURLValue{StringValue: basetypes.NewStringValue(s)}
}

func (v vaultURLValue) Equal(o attr.Value) bool {
	other, ok := o.(vaultURLValue)
	return ok && v.StringValue.Equal(other.StringValue)
}

func (v vaultURLValue) Type(context.Context) attr.Type { return vaultURLType{} }

// StringSemanticEquals reports whether both values name the same vault.
func (v vaultURLValue) StringSemanticEquals(_ context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	other, ok := newValuable.(vaultURLValue)
	if !ok {
		diags.AddError("Semantic equality check error",
			fmt.Sprintf("Expected a vault URL value, got %T. This is a bug in the provider.", newValuable))
		return false, diags
	}
	return acme.VaultURLEqual(v.ValueString(), other.ValueString()), diags
}
