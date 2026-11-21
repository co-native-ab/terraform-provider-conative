package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"
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
	Token string // from the configuration only; empty when null or unknown
	// TokenUnknown is true when the token is not known until apply; an empty Token with
	// TokenUnknown false means no token was configured.
	TokenUnknown bool
	Block        acme.Block
}

// dnsBlocks are the DNS blocks of a certificate as read from the configuration.
type dnsBlocks struct {
	Azure      []azureBlock
	Cloudflare []cloudflareBlock
	// Known is true when every value the routing needs (zones and match_domains) is
	// known; TokensKnown when no Cloudflare token is unknown (a token that is not set is
	// known).
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
		unknown := false
		if v, isString := o.Attributes()["api_token"].(types.String); isString {
			unknown = v.IsUnknown()
		}
		d.Known = d.Known && ok1 && ok2
		d.TokensKnown = d.TokensKnown && (ok3 || !unknown)
		d.Cloudflare = append(d.Cloudflare, cloudflareBlock{Zone: zone, Token: tok, TokenUnknown: unknown,
			Block: acme.Block{Kind: acme.KindCloudflare, Index: i, Zone: zone, MatchDomains: md}})
	}
	return d
}

// ---- key_vault_url ------------------------------------------------------------------

// vaultURLReplace keeps the value in state when the configuration names the same vault
// in another spelling (the case of the host, a trailing slash), so that the plan shows no
// change; Terraform accepts a planned value that equals the prior value for that reason.
// It requires replacement only when the vault differs. The attribute's type
// (vaultURLType) does the same after create, update and read.
type vaultURLReplace struct{}

func (vaultURLReplace) Description(context.Context) string {
	return "Changing the vault replaces the resource; another spelling of the same URL does not change anything."
}

func (m vaultURLReplace) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (vaultURLReplace) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() || req.StateValue.IsNull() {
		return
	}
	switch {
	case req.PlanValue.IsUnknown():
		resp.RequiresReplace = true
	case acme.VaultURLEqual(req.StateValue.ValueString(), req.PlanValue.ValueString()):
		resp.PlanValue = req.StateValue
	default:
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

	if !cn.IsUnknown() && !cn.IsNull() {
		if err := acme.ValidateCommonName(cn.ValueString()); err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("common_name"), "Invalid common name", err.Error())
		}
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
			if !strings.Contains(err.Error(), "common_name: ") || acme.ValidateCommonName(cn.ValueString()) == nil {
				resp.Diagnostics.AddAttributeError(path.Root("common_name"), "Invalid certificate names", err.Error())
			}
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
	orderReason := "the certificate does not exist yet"
	if !creating {
		var state acmeCertificateModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		var reason string
		order, reason = decideOrder(time.Now(), plan, state)
		orderReason = reason
		if order {
			if orderUncertain(plan) {
				// Terraform plans the resource again during apply, when the values are known,
				// and this function then makes the real decision; until then a new version is
				// only possible.
				tflog.Info(ctx, "whether a new certificate is ordered is decided at apply", map[string]any{"reason": reason})
			} else {
				tflog.Info(ctx, "a new certificate will be ordered", map[string]any{"reason": reason})
			}
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
	// A new certificate is certain to be ordered; an update orders only when the values
	// that decide it are known.
	certain := creating || !orderUncertain(plan)
	r.checkTokens(ctx, plan, req.Config, orderReason, certain, &resp.Diagnostics)
	if resp.Diagnostics.HasError() || !certain {
		// An update that only may order reads nothing more now: Terraform plans it again
		// during apply with the values known, and that plan runs these checks if it orders.
		return
	}
	r.preflight(ctx, plan, req.Config, creating, &resp.Diagnostics)
}

// orderUncertain is true when the plan has values that decide whether an update orders
// and are not known yet.
func orderUncertain(plan acmeCertificateModel) bool {
	return plan.CommonName.IsUnknown() || plan.SANs.IsUnknown() || plan.KeyType.IsUnknown() || plan.MinDays.IsUnknown() || plan.RegistrationID.IsUnknown()
}

// decideOrder decides whether an update orders a new certificate. A value that is not
// known yet counts as a possible change: the plan shows the attributes of a new version
// as unknown, so that nothing is promised that apply might not do. Terraform plans the
// resource again during apply with every value known (for example the registration_id
// of a registration created in the same run), and that plan decides; any value of the
// current version is then a valid result for the attributes that were unknown.
func decideOrder(now time.Time, plan, state acmeCertificateModel) (bool, string) {
	if orderUncertain(plan) {
		return true, "a name, the key type, min_days_remaining or the registration is not known until apply"
	}
	notAfter, err := time.Parse(time.RFC3339, state.NotAfter.ValueString())
	if err != nil {
		return true, "the expiry of the current certificate is not known"
	}
	var namesChanged bool
	if state.CommonName.IsNull() {
		// A certificate without a subject common name (adopted by an import): all its DNS
		// names are in subject_alternative_names, and the configured common name and
		// alternative names have to make up the same set.
		namesChanged = acme.NamesChangedWithoutCommonName(plan.CommonName.ValueString(), setStrings(plan.SANs), setStrings(state.SANs))
	} else {
		namesChanged = acme.NamesChanged(plan.CommonName.ValueString(), setStrings(plan.SANs), state.CommonName.ValueString(), setStrings(state.SANs))
	}
	changed := namesChanged ||
		acme.KeyTypeChanged(plan.KeyType.ValueString(), state.KeyType.ValueString()) ||
		authorityChanged(plan.RegistrationID, state.RegistrationID)
	return acme.NeedsOrder(now, notAfter, plan.MinDays.ValueInt64(), state.Version.ValueString(), state.IssuedVersion.ValueString(), changed)
}

// authorityChanged reports whether registration_id moved from one certificate authority
// to another: both values are known and their server URLs differ. A registration that
// was not recorded before (null, as after an import) only gets recorded, and another
// account key at the same authority changes nothing about the certificate.
func authorityChanged(plan, state types.String) bool {
	if plan.IsNull() || plan.IsUnknown() || state.IsNull() || state.IsUnknown() {
		return false
	}
	planServer, _, err1 := acme.ParseRegistrationID(plan.ValueString())
	stateServer, _, err2 := acme.ParseRegistrationID(state.ValueString())
	return err1 == nil && err2 == nil && planServer != stateServer
}

// usedBlocks returns the blocks that serve at least one name of the order, with the
// flags of the original. A block that serves no name is never used by the order, so it
// needs no token.
func usedBlocks(ids []string, all dnsBlocks) (dnsBlocks, error) {
	routes, err := acme.Route(ids, all.Blocks())
	if err != nil {
		return dnsBlocks{}, err
	}
	used := map[string]bool{}
	for _, b := range routes {
		used[b.String()] = true
	}
	out := dnsBlocks{Known: all.Known, TokensKnown: all.TokensKnown}
	for _, a := range all.Azure {
		if used[a.Block.String()] {
			out.Azure = append(out.Azure, a)
		}
	}
	for _, c := range all.Cloudflare {
		if used[c.Block.String()] {
			out.Cloudflare = append(out.Cloudflare, c)
		}
	}
	return out, nil
}

// checkTokens runs when an order is planned. It fails the plan when a DNS block that
// will serve a name of the order has no token to use: a Cloudflare block without
// api_token, or an azure_dns block while the provider has no
// acme.resource_manager_access_token. A token that is not known until apply is checked
// at apply instead. Nothing is read or written here.
func (r *acmeCertificateResource) checkTokens(ctx context.Context, plan acmeCertificateModel, cfg tfConfig, reason string, certain bool, diags *diag.Diagnostics) {
	// Whether an order really happens, or which names it has, may depend on values that
	// are not known yet; the check is then repeated at apply.
	if !certain || plan.CommonName.IsUnknown() || plan.SANs.IsUnknown() {
		return
	}
	blocks, ok := readDNSBlocks(ctx, cfg, diags)
	if !ok || !blocks.Known {
		return
	}
	ids, err := identifiersOf(plan)
	if err != nil {
		return // ValidateConfig reports it
	}
	used, err := usedBlocks(ids, blocks)
	if err != nil {
		return // ValidateConfig reports it
	}
	for _, z := range used.Cloudflare {
		if z.Token == "" && !z.TokenUnknown {
			diags.AddAttributeError(path.Root("cloudflare").AtListIndex(z.Block.Index).AtName("api_token"),
				"A Cloudflare API token is required to order the certificate",
				missingCloudflareTokenMessage(z.Block, reason))
		}
	}
	if len(used.Azure) == 0 {
		return
	}
	pd, _ := r.data.(*providerData)
	if pd == nil || pd.acme == nil || pd.acme.unknown || pd.acme.resourceManagerUnknown || pd.acme.resourceManagerToken != "" {
		return
	}
	diags.AddError("An Azure Resource Manager access token is required to order the certificate",
		missingResourceManagerTokenMessage(used.Azure[0].Block, reason))
}

func missingCloudflareTokenMessage(b acme.Block, reason string) string {
	return fmt.Sprintf("A new certificate has to be ordered (%s), and the %s block serves names of the order, but its api_token is not set. "+
		"Set api_token (typically from an ephemeral Key Vault secret) in the configuration. "+
		"It is needed only when an order runs; plans in which nothing is ordered do not need it.", reason, b)
}

func missingResourceManagerTokenMessage(b acme.Block, reason string) string {
	return fmt.Sprintf("A new certificate has to be ordered (%s), and the %s block serves names of the order, but the provider's "+
		"acme.resource_manager_access_token is not set. Set it (typically from an azidentity ephemeral resource for "+
		"https://management.azure.com). It is needed only when an order runs; plans in which nothing is ordered do not need it.", reason, b)
}

// preflight reads, without writing anything, what an order needs: that the Key Vault
// name is free (create) and that every DNS zone can be reached. It only lists the
// certificate's versions (certificates/read); it never reads the pending operation,
// which Key Vault authorises as certificates/create/action. Pending operations are
// handled when the order runs. Values that are not known yet skip the checks; the order
// repeats them.
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
	// there never gets here. Only the blocks that serve a name of the order are checked.
	ids, err := identifiersOf(plan)
	if err != nil {
		return
	}
	blocks, err = usedBlocks(ids, blocks)
	if err != nil {
		return
	}
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
	if err := issuer.CheckVersions(ctx, kv, name, creating, acme.CertificateID(vault, name)); err != nil {
		diags.AddError("Cannot order the certificate", err.Error())
		return
	}

	// A token that is missing or not known yet skips its zone check; checkTokens and the
	// order itself report a missing token.
	if len(blocks.Azure) > 0 && access.resourceManagerToken != "" {
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
