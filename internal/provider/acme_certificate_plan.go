package provider

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/azuredns"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/cloudflare"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/issuer"
)

type tfConfig = tfsdk.Config

// ---- DNS blocks ---------------------------------------------------------------------

type azureBlock struct {
	Subscription, ResourceGroup, Zone string
	Block                             acme.Block
}

type cloudflareBlock struct {
	Zone  string
	Token string // from the configuration only; empty when unknown
	Block acme.Block
}

// dnsBlocks are the DNS blocks of a certificate as read from the configuration.
type dnsBlocks struct {
	Azure      []azureBlock
	Cloudflare []cloudflareBlock
	// Known is true when every value the routing needs (zones and match_domains) is
	// known; TokensKnown when every Cloudflare token is.
	Known       bool
	TokensKnown bool
}

// Blocks returns the blocks in the form the core routes with.
func (d dnsBlocks) Blocks() []acme.Block {
	var out []acme.Block
	for _, a := range d.Azure {
		out = append(out, a.Block)
	}
	for _, c := range d.Cloudflare {
		out = append(out, c.Block)
	}
	return out
}

func stringOf(v attr.Value) (string, bool) {
	s, ok := v.(types.String)
	if !ok || s.IsNull() || s.IsUnknown() {
		return "", false
	}
	return s.ValueString(), true
}

func objectsOf(l types.List) ([]types.Object, bool) {
	if l.IsUnknown() {
		return nil, false
	}
	var out []types.Object
	for _, e := range l.Elements() {
		o, ok := e.(types.Object)
		if !ok || o.IsUnknown() || o.IsNull() {
			return nil, false
		}
		out = append(out, o)
	}
	return out, true
}

func matchDomainsOf(o types.Object) ([]string, bool) {
	s, ok := o.Attributes()["match_domains"].(types.Set)
	if !ok || s.IsNull() || s.IsUnknown() {
		return nil, false
	}
	var out []string
	for _, e := range s.Elements() {
		v, ok := stringOf(e)
		if !ok {
			return nil, false
		}
		out = append(out, v)
	}
	slices.Sort(out)
	return out, true
}

// readDNSBlocks reads both block lists from the configuration.
func readDNSBlocks(ctx context.Context, cfg tfConfig, diags *diag.Diagnostics) (dnsBlocks, bool) {
	var az, cf types.List
	diags.Append(cfg.GetAttribute(ctx, path.Root("azure_dns"), &az)...)
	diags.Append(cfg.GetAttribute(ctx, path.Root("cloudflare"), &cf)...)
	if diags.HasError() {
		return dnsBlocks{}, false
	}
	return parseDNSBlocks(az, cf), true
}

func parseDNSBlocks(az, cf types.List) dnsBlocks {
	d := dnsBlocks{Known: true, TokensKnown: true}
	azs, ok := objectsOf(az)
	d.Known = d.Known && ok
	for i, o := range azs {
		sub, ok1 := stringOf(o.Attributes()["subscription_id"])
		rg, ok2 := stringOf(o.Attributes()["resource_group"])
		zone, ok3 := stringOf(o.Attributes()["zone_name"])
		md, ok4 := matchDomainsOf(o)
		d.Known = d.Known && ok1 && ok2 && ok3 && ok4
		d.Azure = append(d.Azure, azureBlock{Subscription: sub, ResourceGroup: rg, Zone: zone,
			Block: acme.Block{Kind: acme.KindAzureDNS, Index: i, Zone: zone, MatchDomains: md}})
	}
	cfs, ok := objectsOf(cf)
	d.Known = d.Known && ok
	for i, o := range cfs {
		zone, ok1 := stringOf(o.Attributes()["zone"])
		md, ok2 := matchDomainsOf(o)
		tok, ok3 := stringOf(o.Attributes()["api_token"])
		d.Known = d.Known && ok1 && ok2
		d.TokensKnown = d.TokensKnown && ok3
		d.Cloudflare = append(d.Cloudflare, cloudflareBlock{Zone: zone, Token: tok,
			Block: acme.Block{Kind: acme.KindCloudflare, Index: i, Zone: zone, MatchDomains: md}})
	}
	return d
}

// ---- key_vault_url ------------------------------------------------------------------

// vaultURLReplace requires replacement only when the vault differs: another spelling of
// the same URL (case of the host, a trailing slash) is not a change of vault.
type vaultURLReplace struct{}

func (vaultURLReplace) Description(context.Context) string {
	return "Changing the vault replaces the resource; another spelling of the same URL does not."
}

func (m vaultURLReplace) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (vaultURLReplace) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() || req.StateValue.IsNull() {
		return
	}
	if req.PlanValue.IsUnknown() || !acme.VaultURLEqual(req.StateValue.ValueString(), req.PlanValue.ValueString()) {
		resp.RequiresReplace = true
	}
}

// ---- ValidateConfig -----------------------------------------------------------------

func (r *acmeCertificateResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cn types.String
	var sans types.Set
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("common_name"), &cn)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("subject_alternative_names"), &sans)...)
	blocks, ok := readDNSBlocks(ctx, req.Config, &resp.Diagnostics)
	if !ok || resp.Diagnostics.HasError() {
		return
	}

	var ids []string
	namesKnown := !cn.IsUnknown() && !cn.IsNull() && !sans.IsUnknown()
	if namesKnown {
		for _, e := range sans.Elements() {
			if _, ok := stringOf(e); !ok {
				namesKnown = false
			}
		}
	}
	if namesKnown {
		var err error
		sorted := setStrings(sans)
		slices.Sort(sorted)
		ids, err = acme.Identifiers(cn.ValueString(), sorted)
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("common_name"), "Invalid certificate names", err.Error())
			ids = nil
		}
	}

	var az, cf types.List
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("azure_dns"), &az)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("cloudflare"), &cf)...)
	if az.IsUnknown() || cf.IsUnknown() || !blocks.Known {
		return
	}
	if err := acme.ValidateBlocks(blocks.Blocks()); err != nil {
		resp.Diagnostics.AddError("Invalid DNS blocks", err.Error())
		return
	}
	if ids != nil {
		if _, err := acme.Route(ids, blocks.Blocks()); err != nil {
			resp.Diagnostics.AddError("Names are not covered by the DNS blocks", err.Error())
		}
	}
}

// ---- ModifyPlan ---------------------------------------------------------------------

var orderedComputed = []string{"version", "issued_version", "certificate_pem", "not_after", "thumbprint"}

func (r *acmeCertificateResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return // destroy
	}
	var plan acmeCertificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	creating := req.State.Raw.IsNull()

	order := creating
	if !creating {
		var state acmeCertificateModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		var reason string
		order, reason = decideOrder(time.Now(), plan, state)
		if order {
			tflog.Info(ctx, "a new certificate will be ordered", map[string]any{"reason": reason})
			for _, a := range orderedComputed {
				resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root(a), types.StringUnknown())...)
			}
		} else {
			// Only values the vault cannot report change: keep what is known.
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("version"), state.Version)...)
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("issued_version"), state.IssuedVersion)...)
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("certificate_pem"), state.CertificatePEM)...)
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("not_after"), state.NotAfter)...)
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("thumbprint"), state.Thumbprint)...)
		}
	}
	if !order || resp.Diagnostics.HasError() {
		return
	}
	r.preflight(ctx, plan, req.Config, creating, &resp.Diagnostics)
}

// decideOrder decides whether an update orders a new certificate. A value that is not
// known yet counts as a change, so that nothing is promised that apply might not do.
func decideOrder(now time.Time, plan, state acmeCertificateModel) (bool, string) {
	if plan.CommonName.IsUnknown() || plan.SANs.IsUnknown() || plan.KeyType.IsUnknown() || plan.MinDays.IsUnknown() {
		return true, "a name, the key type or min_days_remaining is not known until apply"
	}
	notAfter, err := time.Parse(time.RFC3339, state.NotAfter.ValueString())
	if err != nil {
		return true, "the expiry of the current certificate is not known"
	}
	changed := acme.NamesChanged(plan.CommonName.ValueString(), setStrings(plan.SANs), state.CommonName.ValueString(), setStrings(state.SANs)) ||
		acme.KeyTypeChanged(plan.KeyType.ValueString(), state.KeyType.ValueString())
	return acme.NeedsOrder(now, notAfter, plan.MinDays.ValueInt64(), state.Version.ValueString(), state.IssuedVersion.ValueString(), changed)
}

// preflight reads, without writing anything, what an order needs: that the Key Vault
// name is free (create) or has no foreign pending operation, and that every DNS zone
// can be reached. Values that are not known yet skip the checks; the order repeats them.
func (r *acmeCertificateResource) preflight(ctx context.Context, plan acmeCertificateModel, cfg tfConfig, creating bool, diags *diag.Diagnostics) {
	pd, _ := r.data.(*providerData)
	if pd == nil || pd.acme == nil || pd.acme.unknown {
		return
	}
	blocks, ok := readDNSBlocks(ctx, cfg, diags)
	if !ok || !blocks.Known {
		return
	}
	if plan.KeyVaultURL.IsUnknown() || plan.CertificateName.IsUnknown() || plan.CommonName.IsUnknown() || plan.SANs.IsUnknown() {
		return
	}
	// Names and routing are validated by ValidateConfig; a configuration that fails
	// there never gets here.
	access := requireACME(pd, diags, false)
	if access == nil {
		return
	}
	vault, err := acme.ParseVaultURL(plan.KeyVaultURL.ValueString())
	if err != nil {
		return
	}
	name := plan.CertificateName.ValueString()
	kv, err := access.keyVault(vault)
	if err != nil {
		operationError(diags, "check", plan.object(), err)
		return
	}
	if _, err := issuer.CheckVault(ctx, kv, name, creating, acme.CertificateID(vault, name)); err != nil {
		diags.AddError("Cannot order the certificate", err.Error())
		return
	}

	if len(blocks.Azure) > 0 {
		switch {
		case access.resourceManagerToken != "":
			c, err := azuredns.New(access.env.resourceManagerURL, access.resourceManagerToken, access.http)
			if err != nil {
				diags.AddError("Cannot reach Azure DNS", err.Error())
				return
			}
			for _, z := range blocks.Azure {
				if err := azuredns.NewZonePublisher(c, z.Subscription, z.ResourceGroup, z.Zone).Check(ctx); err != nil {
					diags.AddError("Cannot use the Azure DNS zone", fmt.Sprintf("azure_dns block %d: %s", z.Block.Index, err))
				}
			}
		case !access.resourceManagerUnknown:
			requireACME(pd, diags, true)
			return
		}
	}
	for _, z := range blocks.Cloudflare {
		if z.Token == "" {
			continue
		}
		c, err := cloudflare.New(access.env.cloudflareURL, z.Token, access.http)
		if err != nil {
			diags.AddError("Cannot reach Cloudflare", err.Error())
			return
		}
		if err := cloudflare.NewZonePublisher(c, z.Zone).Check(ctx); err != nil {
			diags.AddError("Cannot use the Cloudflare zone", fmt.Sprintf("cloudflare block %d: %s", z.Block.Index, err))
		}
	}
}
