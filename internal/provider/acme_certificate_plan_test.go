package provider

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func stringSet(vals ...string) types.Set {
	elems := make([]attr.Value, len(vals))
	for i, v := range vals {
		elems[i] = types.StringValue(v)
	}
	return types.SetValueMust(types.StringType, elems)
}

func issuedState(notAfter time.Time) acmeCertificateModel {
	return acmeCertificateModel{
		CommonName: types.StringValue("example.com"), SANs: stringSet("*.example.com"), KeyType: types.StringValue("RSA2048"),
		MinDays: types.Int64Value(30), Version: types.StringValue("v1"), IssuedVersion: types.StringValue("v1"),
		NotAfter: types.StringValue(notAfter.UTC().Format(time.RFC3339)),
	}
}

func TestDecideOrder(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	state := issuedState(now.Add(90 * 24 * time.Hour))

	cases := map[string]struct {
		edit func(*acmeCertificateModel)
		want bool
	}{
		"nothing changed":                {func(*acmeCertificateModel) {}, false},
		"state-only argument changed":    {func(m *acmeCertificateModel) { m.MinDays = types.Int64Value(60) }, false},
		"window reached":                 {func(m *acmeCertificateModel) { m.MinDays = types.Int64Value(90) }, true},
		"a name was added":               {func(m *acmeCertificateModel) { m.SANs = stringSet("*.example.com", "www.example.com") }, true},
		"names reordered":                {func(m *acmeCertificateModel) { m.SANs = stringSet("*.example.com") }, false},
		"key type changed":               {func(m *acmeCertificateModel) { m.KeyType = types.StringValue("P256") }, true},
		"common name changed":            {func(m *acmeCertificateModel) { m.CommonName = types.StringValue("example.net") }, true},
		"a name is not known yet":        {func(m *acmeCertificateModel) { m.SANs = types.SetUnknown(types.StringType) }, true},
		"min_days_remaining not known":   {func(m *acmeCertificateModel) { m.MinDays = types.Int64Unknown() }, true},
		"null equals empty alternatives": {func(m *acmeCertificateModel) { m.SANs = stringSet("*.example.com") }, false},
	}
	for name, c := range cases {
		plan := state
		c.edit(&plan)
		if got, why := decideOrder(now, plan, state); got != c.want || (got && why == "") {
			t.Errorf("%s: order = %t (%q), want %t", name, got, why, c.want)
		}
	}

	external := state
	external.Version = types.StringValue("v2")
	if got, _ := decideOrder(now, state, external); !got {
		t.Error("a version that differs from the issued one must order")
	}
	broken := state
	broken.NotAfter = types.StringValue("not a time")
	if got, _ := decideOrder(now, state, broken); !got {
		t.Error("an unreadable expiry must order")
	}

	none := state
	none.SANs = types.SetNull(types.StringType)
	plan := state
	plan.SANs = types.SetValueMust(types.StringType, nil)
	if got, _ := decideOrder(now, plan, none); got {
		t.Error("null and empty alternative names must be equal")
	}
}

func TestVaultURLReplacesOnlyWhenTheVaultDiffers(t *testing.T) {
	t.Parallel()
	nonNull := tfsdk.State{Raw: tftypes.NewValue(tftypes.String, "x")}
	plan := tfsdk.Plan{Raw: tftypes.NewValue(tftypes.String, "x")}
	for name, c := range map[string]struct {
		state, plan types.String
		replace     bool
	}{
		"same":             {types.StringValue("https://abc.vault.azure.net"), types.StringValue("https://abc.vault.azure.net"), false},
		"trailing slash":   {types.StringValue("https://abc.vault.azure.net"), types.StringValue("https://abc.vault.azure.net/"), false},
		"host case":        {types.StringValue("https://ABC.vault.azure.net/"), types.StringValue("https://abc.vault.azure.net"), false},
		"another vault":    {types.StringValue("https://abc.vault.azure.net"), types.StringValue("https://def.vault.azure.net"), true},
		"not known yet":    {types.StringValue("https://abc.vault.azure.net"), types.StringUnknown(), true},
		"nothing in state": {types.StringNull(), types.StringValue("https://abc.vault.azure.net"), false},
	} {
		var resp planmodifier.StringResponse
		vaultURLReplace{}.PlanModifyString(context.Background(), planmodifier.StringRequest{
			State: nonNull, Plan: plan, StateValue: c.state, PlanValue: c.plan,
		}, &resp)
		if resp.RequiresReplace != c.replace {
			t.Errorf("%s: RequiresReplace = %t, want %t", name, resp.RequiresReplace, c.replace)
		}
		// The same vault in another spelling keeps the value in state, so that no change shows.
		if !c.replace && !c.state.IsNull() && !resp.PlanValue.Equal(c.state) {
			t.Errorf("%s: the planned value %s is not the state value %s", name, resp.PlanValue, c.state)
		}
	}
}

func TestParseDNSBlocks(t *testing.T) {
	t.Parallel()
	md := stringSet("example.com")
	azType := types.ObjectType{AttrTypes: map[string]attr.Type{
		"subscription_id": types.StringType, "resource_group": types.StringType, "zone_name": types.StringType, "match_domains": types.SetType{ElemType: types.StringType},
	}}
	cfType := types.ObjectType{AttrTypes: map[string]attr.Type{
		"zone": types.StringType, "match_domains": types.SetType{ElemType: types.StringType}, "api_token": types.StringType,
	}}
	az := types.ListValueMust(azType, []attr.Value{types.ObjectValueMust(azType.AttrTypes, map[string]attr.Value{
		"subscription_id": types.StringValue("s"), "resource_group": types.StringValue("rg"), "zone_name": types.StringValue("example.com"), "match_domains": md,
	})})
	cf := types.ListValueMust(cfType, []attr.Value{types.ObjectValueMust(cfType.AttrTypes, map[string]attr.Value{
		"zone": types.StringValue("example.net"), "match_domains": stringSet("example.net"), "api_token": types.StringUnknown(),
	})})

	b := parseDNSBlocks(az, cf)
	if !b.Known || b.TokensKnown || len(b.Azure) != 1 || len(b.Cloudflare) != 1 {
		t.Fatalf("%+v", b)
	}
	if got := b.Blocks(); len(got) != 2 || got[0].String() != "azure_dns[0]" || got[1].String() != "cloudflare[0]" {
		t.Errorf("blocks: %v", got)
	}
	if b := parseDNSBlocks(types.ListUnknown(azType), cf); b.Known {
		t.Error("an unknown block list must not count as known")
	}
}
