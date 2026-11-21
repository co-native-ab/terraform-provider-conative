package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/azuredns"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/cloudflare"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/issuer"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/keyvault"
)

var (
	_ resource.Resource                   = (*acmeCertificateResource)(nil)
	_ resource.ResourceWithConfigure      = (*acmeCertificateResource)(nil)
	_ resource.ResourceWithImportState    = (*acmeCertificateResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*acmeCertificateResource)(nil)
	_ resource.ResourceWithValidateConfig = (*acmeCertificateResource)(nil)
)

// importedVersionKey is the private state key that records the version that was
// current when an existing certificate was imported.
const importedVersionKey = "imported_version"

// issuedByKey is the private state key that records the registration (its
// registration_id) whose account ordered the certificate in issued_version. Only that
// account, or one that holds valid authorizations for every name, may revoke it
// (RFC 8555 section 7.6), so destroy revokes with that account's key even when
// registration_id has since moved to another account at the same authority.
const issuedByKey = "issued_by"

const defaultMinDaysRemaining = 30

// NewACMECertificateResource returns the conative_acme_certificate resource.
func NewACMECertificateResource() resource.Resource { return &acmeCertificateResource{} }

type acmeCertificateResource struct {
	data any
}

type acmeCertificateModel struct {
	ID              types.String  `tfsdk:"id"`
	SecretID        types.String  `tfsdk:"secret_id"`
	RegistrationID  types.String  `tfsdk:"registration_id"`
	KeyVaultURL     vaultURLValue `tfsdk:"key_vault_url"`
	CertificateName types.String  `tfsdk:"certificate_name"`
	CommonName      types.String  `tfsdk:"common_name"`
	SANs            types.Set     `tfsdk:"subject_alternative_names"`
	KeyType         types.String  `tfsdk:"key_type"`
	MinDays         types.Int64   `tfsdk:"min_days_remaining"`
	RevokeOnDestroy types.Bool    `tfsdk:"revoke_on_destroy"`
	AzureDNS        types.List    `tfsdk:"azure_dns"`
	Cloudflare      types.List    `tfsdk:"cloudflare"`
	Version         types.String  `tfsdk:"version"`
	IssuedVersion   types.String  `tfsdk:"issued_version"`
	CertificatePEM  types.String  `tfsdk:"certificate_pem"`
	NotAfter        types.String  `tfsdk:"not_after"`
	Thumbprint      types.String  `tfsdk:"thumbprint"`
}

func (m acmeCertificateModel) object() string {
	return fmt.Sprintf("certificate %q in %s", m.CertificateName.ValueString(), m.KeyVaultURL.ValueString())
}

func (r *acmeCertificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acme_certificate"
}

func (r *acmeCertificateResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.data = req.ProviderData
}

func (r *acmeCertificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A certificate in Azure Key Vault issued by an ACME certificate authority through DNS-01 " +
			"challenges. Key Vault generates the private key (exportable, a new key for every version) and the " +
			"signing request; the provider only passes the signing request to the authority and merges the issued " +
			"certificate back. Neither the private key nor any password is ever in Terraform state. Renewal adds a " +
			"new version to the same Key Vault certificate, so services that reference the versionless ID pick it up. " +
			"Refreshing and planning only read certificate metadata and the public certificate from Key Vault: they never " +
			"read a secret, sign, call the certificate authority or write anywhere, and they need neither the Cloudflare " +
			"token nor the Resource Manager token. Those are needed only when an order runs.",
		Attributes: map[string]schema.Attribute{
			"registration_id": schema.StringAttribute{
				MarkdownDescription: "The `id` of a `conative_acme_registration`. Changing it to a registration at " +
					"another certificate authority (a different `server_url`, for example from a staging to a production " +
					"directory) orders a new certificate in place; changing it to another account at the same authority, " +
					"or setting it after an import, only updates the state. When the registration is created or replaced " +
					"in the same run, so that this value is not known until the apply, the plan shows an in-place update " +
					"with the attributes of a new version unknown, and the apply decides with the known value by the same " +
					"rules as any other update: a change of authority, of the names or of the key type orders, as does a " +
					"certificate that is due or whose current version was added outside Terraform.",
				Required:   true,
				Validators: []validator.String{checkString("must be <server_url>|<account_key_id>", validateRegistrationID)},
			},
			"key_vault_url": schema.StringAttribute{
				MarkdownDescription: "The vault URL, for example `https://example.vault.azure.net/`. The host must end in " +
					"`.vault.azure.net`; access tokens are sent to no other host. Changing it to " +
					"another vault replaces the resource; a different spelling of the same URL (a trailing slash, the case " +
					"of the host) is no change at all.",
				CustomType:    vaultURLType{},
				Required:      true,
				Validators:    []validator.String{checkString("must be a Key Vault URL such as https://example.vault.azure.net/", validateVaultURL)},
				PlanModifiers: []planmodifier.String{vaultURLReplace{}},
			},
			"certificate_name": schema.StringAttribute{
				MarkdownDescription: "The Key Vault certificate name. The resource owns this certificate; creating it " +
					"fails if the name already holds an issued certificate (import it instead). Changing it replaces " +
					"the resource.",
				Required:      true,
				Validators:    []validator.String{checkString("must be 1 to 127 letters, digits or hyphens", acme.ValidateCertificateName)},
				PlanModifiers: replace,
			},
			"common_name": schema.StringAttribute{
				MarkdownDescription: "The certificate's common name, at most 64 characters; always also a subject alternative name. " +
					"Changing it issues a new version. Some certificate authorities leave the common name out of the " +
					"certificate they issue; the provider then keeps the configured value. It is null after importing a " +
					"certificate that has no subject common name; the names are then all in " +
					"`subject_alternative_names` until the configuration is applied.",
				Required: true,
			},
			"subject_alternative_names": schema.SetAttribute{
				MarkdownDescription: "Further DNS names. Wildcards are written `*.example.com`. Do not repeat " +
					"`common_name`. Changing them issues a new version.",
				ElementType: types.StringType,
				Optional:    true,
			},
			"key_type": schema.StringAttribute{
				MarkdownDescription: "`" + strings.Join(acme.KeyTypes(), "`, `") + "`. The certificate authority " +
					"decides which it accepts (Let's Encrypt does not accept `P521`). Changing it issues a new version.",
				Required:   true,
				Validators: []validator.String{checkString("must be one of "+strings.Join(acme.KeyTypes(), ", "), acme.ValidateKeyType)},
			},
			"min_days_remaining": schema.Int64Attribute{
				MarkdownDescription: "Renew when the certificate expires within this many days. A plan then shows an " +
					"in-place update that orders a new version.",
				Optional:   true,
				Computed:   true,
				Default:    int64default.StaticInt64(defaultMinDaysRemaining),
				Validators: []validator.Int64{atLeastOne{}},
			},
			"revoke_on_destroy": schema.BoolAttribute{
				MarkdownDescription: "Whether destroying the resource revokes the certificate at the authority before " +
					"deleting it from Key Vault. The version revoked is the one this resource issued last " +
					"(`issued_version`), not necessarily the current version. It is skipped when that version has " +
					"expired or is gone, and for a certificate that was imported and not yet renewed by this resource " +
					"(it was issued elsewhere): destroy then warns and only deletes it. It is revoked with the account " +
					"that ordered it, also when `registration_id` has moved to another account at the same authority " +
					"since; if that account's key no longer exists, destroy warns and does not revoke. Revoking signs a " +
					"request with the account key.",
				Required: true,
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "The versionless Key Vault certificate ID, `https://<vault>/certificates/<name>`.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"secret_id": schema.StringAttribute{
				MarkdownDescription: "The versionless Key Vault secret ID, `https://<vault>/secrets/<name>`, which " +
					"services such as Azure Front Door and Azure Container Apps use to load the certificate.",
				Computed:      true,
				PlanModifiers: keep,
			},
			"version": schema.StringAttribute{
				MarkdownDescription: "The certificate's current version in Key Vault.",
				Computed:            true,
			},
			"issued_version": schema.StringAttribute{
				MarkdownDescription: "The version this resource issued last, or after import the version that was " +
					"current then. When `version` differs, the certificate changed outside Terraform and the next plan " +
					"renews it.",
				Computed: true,
			},
			"certificate_pem": schema.StringAttribute{
				MarkdownDescription: "The current certificate (public), PEM.",
				Computed:            true,
			},
			"not_after": schema.StringAttribute{
				MarkdownDescription: "Expiry of the current certificate, RFC 3339.",
				Computed:            true,
			},
			"thumbprint": schema.StringAttribute{
				MarkdownDescription: "SHA-1 thumbprint of the current certificate, upper-case hexadecimal.",
				Computed:            true,
			},
		},
		Blocks: map[string]schema.Block{
			"azure_dns": schema.ListNestedBlock{
				MarkdownDescription: "An Azure DNS zone that answers challenges. At least one `azure_dns` or `cloudflare` " +
					"block is required, and every name of the certificate must be covered by one of them.",
				NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
					"subscription_id": schema.StringAttribute{
						MarkdownDescription: "The subscription of the zone.",
						Required:            true,
						Validators:          []validator.String{checkString("must be a GUID", acme.ValidateSubscriptionID)},
					},
					"resource_group": schema.StringAttribute{
						MarkdownDescription: "The resource group of the zone.",
						Required:            true,
						Validators:          []validator.String{checkString("must be a resource group name", acme.ValidateResourceGroup)},
					},
					"zone_name": schema.StringAttribute{
						MarkdownDescription: "The zone name, for example `example.net`.",
						Required:            true,
						Validators:          []validator.String{checkString("must be a lower-case DNS name", acme.ValidateMatchDomain)},
					},
					"match_domains": matchDomainsAttribute(),
				}},
			},
			"cloudflare": schema.ListNestedBlock{
				MarkdownDescription: "A Cloudflare zone that answers challenges.",
				NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
					"zone": schema.StringAttribute{
						MarkdownDescription: "The zone name, for example `example.com`.",
						Required:            true,
						Validators:          []validator.String{checkString("must be a lower-case DNS name", acme.ValidateMatchDomain)},
					},
					"match_domains": matchDomainsAttribute(),
					"api_token": schema.StringAttribute{
						MarkdownDescription: "A Cloudflare API token with Zone Read and DNS Edit on the zone. Write-only: " +
							"never stored in the plan or the state. Needs Terraform 1.11 or later. Supply it from an " +
							"ephemeral value. Optional because it is needed only when an order runs (a new " +
							"certificate, a renewal or a change that orders): plans in which nothing is ordered succeed " +
							"without it. When an order is planned and a name of the order is served by this block, a " +
							"missing token is an error. A read-only token can plan but not apply, except that an apply " +
							"writes no record, and so succeeds, for a name whose authorization the certificate " +
							"authority still holds as valid.",
						Optional:  true,
						WriteOnly: true,
						Sensitive: true,
					},
				}},
			},
		},
	}
}

func matchDomainsAttribute() schema.Attribute {
	return schema.SetAttribute{
		MarkdownDescription: "Names this zone answers for: a name is covered when it equals an entry or ends in " +
			"`.<entry>` (ignoring a leading `*.`). When entries of several blocks match, the longest wins.",
		ElementType: types.StringType,
		Required:    true,
		Validators:  []validator.Set{checkStringSet("must be lower-case DNS names without a wildcard", true, acme.ValidateMatchDomain)},
	}
}

func validateRegistrationID(s string) error {
	_, _, err := acme.ParseRegistrationID(s)
	return err
}

func validateVaultURL(s string) error {
	_, err := acme.ParseVaultURL(s)
	return err
}

// access returns the ACME access, adding an error when it is unusable.
func (r *acmeCertificateResource) access(diags *diag.Diagnostics, needResourceManager bool) *acmeAccess {
	return requireACME(r.data, diags, needResourceManager)
}

// ---- reading what Key Vault holds -------------------------------------------------

// currentBundle returns the current issued version of a certificate: the latest, or when
// the latest has no certificate (a pending version) the newest issued one.
func currentBundle(ctx context.Context, kv *keyvault.Client, name string) (keyvault.Bundle, error) {
	b, err := kv.GetCertificate(ctx, name)
	if err != nil {
		return keyvault.Bundle{}, err
	}
	if len(b.Cer) > 0 {
		return b, nil
	}
	versions, err := kv.ListVersions(ctx, name)
	if err != nil {
		return keyvault.Bundle{}, err
	}
	var newest *keyvault.Bundle
	for i := range versions {
		v := versions[i]
		if v.Issued && v.Enabled && (newest == nil || v.Created.After(newest.Created)) {
			newest = &v
		}
	}
	if newest == nil {
		return keyvault.Bundle{}, errNoIssuedVersion
	}
	return kv.GetCertificateVersion(ctx, name, newest.Version)
}

var errNoIssuedVersion = errors.New("the certificate has no issued version")

func (r *acmeCertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state acmeCertificateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	access := r.access(&resp.Diagnostics, false)
	if access == nil {
		return
	}
	vault, err := acme.ParseVaultURL(state.KeyVaultURL.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid key_vault_url", err.Error())
		return
	}
	name := state.CertificateName.ValueString()
	kv, err := access.keyVault(vault)
	if err != nil {
		operationError(&resp.Diagnostics, "read", state.object(), err)
		return
	}
	tflog.Debug(ctx, "reading acme certificate")
	bundle, err := currentBundle(ctx, kv, name)
	imported := state.IssuedVersion.IsNull()
	if errors.Is(err, keyvault.ErrNotFound) {
		if imported {
			resp.Diagnostics.AddError("Cannot import the certificate",
				fmt.Sprintf("%s was not found in Key Vault", acme.CertificateID(vault, name)))
			return
		}
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		if imported {
			resp.Diagnostics.AddError("Cannot import the certificate", fmt.Sprintf("%s: %s", acme.CertificateID(vault, name), err))
			return
		}
		operationError(&resp.Diagnostics, "read", state.object(), err)
		return
	}

	var info acme.Info
	if imported {
		info, err = acme.InspectForImport(bundle.Cer)
		if err != nil {
			resp.Diagnostics.AddError("Cannot import the certificate", fmt.Sprintf(
				"%s (version %s): %s. This resource cannot adopt the certificate.", acme.CertificateID(vault, name), bundle.Version, err))
			return
		}
		state.IssuedVersion = types.StringValue(bundle.Version)
		state.MinDays = types.Int64Value(defaultMinDaysRemaining)
		resp.Diagnostics.Append(resp.Private.SetKey(ctx, importedVersionKey, mustJSON(bundle.Version))...)
		state.SANs = namesSet(info.SANs, types.SetNull(types.StringType))
	} else {
		info, err = acme.Inspect(bundle.Cer)
		if err != nil {
			operationError(&resp.Diagnostics, "read", state.object(), err)
			return
		}
		// A certificate authority may leave the common name out of the certificate (it
		// does when the name is longer than 64 characters, or when its profile has no
		// subject). When the configured name is among the certificate's names, nothing
		// changed: keep it.
		if info.CommonName == "" {
			cn := strings.ToLower(state.CommonName.ValueString())
			if cn != "" && slices.Contains(info.SANs, cn) {
				info.CommonName = cn
				info.SANs = slices.DeleteFunc(slices.Clone(info.SANs), func(n string) bool { return n == cn })
			}
		}
		state.SANs = namesSet(info.SANs, state.SANs)
	}
	state.ID = types.StringValue(acme.CertificateID(vault, name))
	state.SecretID = types.StringValue(acme.SecretID(vault, name))
	state.Version = types.StringValue(bundle.Version)
	state.CertificatePEM = types.StringValue(info.PEM)
	state.NotAfter = types.StringValue(info.NotAfterString())
	state.Thumbprint = types.StringValue(info.Thumbprint)
	state.CommonName = types.StringValue(info.CommonName)
	if info.CommonName == "" {
		// The certificate has no subject common name (and the configuration, if any, does
		// not name one that the certificate carries): record none.
		state.CommonName = types.StringNull()
	}
	state.KeyType = types.StringValue(info.KeyType)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// namesSet turns read-back alternative names into a set. When the certificate has none,
// the form already held (null or empty) is kept.
func namesSet(names []string, current types.Set) types.Set {
	if len(names) == 0 {
		if current.IsNull() || current.IsUnknown() || len(current.Elements()) == 0 {
			return current
		}
		return types.SetValueMust(types.StringType, nil)
	}
	elems := make([]attr.Value, len(names))
	for i, n := range names {
		elems[i] = types.StringValue(n)
	}
	return types.SetValueMust(types.StringType, elems)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ---- ordering -----------------------------------------------------------------------

// buildOrder assembles an order from the planned values and the configuration, which
// alone holds the write-only Cloudflare tokens.
func (r *acmeCertificateResource) buildOrder(ctx context.Context, access *acmeAccess, m acmeCertificateModel, blocks dnsBlocks, creating bool) (issuer.Order, error) {
	vault, err := acme.ParseVaultURL(m.KeyVaultURL.ValueString())
	if err != nil {
		return issuer.Order{}, err
	}
	name := m.CertificateName.ValueString()
	kv, err := access.keyVault(vault)
	if err != nil {
		return issuer.Order{}, err
	}
	server, key, err := acme.ParseRegistrationID(m.RegistrationID.ValueString())
	if err != nil {
		return issuer.Order{}, fmt.Errorf("registration_id: %w", err)
	}
	reg, err := access.registration(ctx, server, key)
	if err != nil {
		return issuer.Order{}, err
	}
	ids, err := identifiersOf(m)
	if err != nil {
		return issuer.Order{}, err
	}
	routes, err := acme.Route(ids, blocks.Blocks())
	if err != nil {
		return issuer.Order{}, err
	}
	publishers, err := access.publishers(blocks)
	if err != nil {
		return issuer.Order{}, err
	}
	return issuer.Order{
		Registration: reg, Vault: kv, Certificate: name, CommonName: m.CommonName.ValueString(), Identifiers: ids,
		KeyType: m.KeyType.ValueString(), Creating: creating, ImportID: acme.CertificateID(vault, name),
		Routes: routes, Publishers: publishers, Checker: access.propagation(), WaitTimeout: access.env.waitTimeout,
	}, nil
}

// identifiersOf returns the names of the certificate: the common name, then the
// alternative names in sorted order.
func identifiersOf(m acmeCertificateModel) ([]string, error) {
	sans := setStrings(m.SANs)
	slices.Sort(sans)
	return acme.Identifiers(m.CommonName.ValueString(), sans)
}

func setStrings(s types.Set) []string {
	var out []string
	for _, e := range s.Elements() {
		if v, ok := e.(types.String); ok && !v.IsNull() && !v.IsUnknown() {
			out = append(out, v.ValueString())
		}
	}
	return out
}

// publishers builds one DNS publisher per block, keyed by the block's name.
func (a *acmeAccess) publishers(b dnsBlocks) (map[string]issuer.DNSPublisher, error) {
	out := map[string]issuer.DNSPublisher{}
	if len(b.Azure) > 0 {
		c, err := azuredns.New(a.env.resourceManagerURL, a.resourceManagerToken, a.http)
		if err != nil {
			return nil, err
		}
		c.SetRetryBase(a.env.retryBase)
		for _, z := range b.Azure {
			out[z.Block.String()] = azuredns.NewZonePublisher(c, z.Subscription, z.ResourceGroup, z.Zone)
		}
	}
	for _, z := range b.Cloudflare {
		c, err := cloudflare.New(a.env.cloudflareURL, z.Token, a.http)
		if err != nil {
			return nil, err
		}
		out[z.Block.String()] = cloudflare.NewZonePublisher(c, z.Zone)
	}
	return out, nil
}

// applyIssued writes the result of an order into the model.
func applyIssued(m *acmeCertificateModel, vault string, res issuer.Result) {
	name := m.CertificateName.ValueString()
	m.ID = types.StringValue(acme.CertificateID(vault, name))
	m.SecretID = types.StringValue(acme.SecretID(vault, name))
	m.Version = types.StringValue(res.Bundle.Version)
	m.IssuedVersion = types.StringValue(res.Bundle.Version)
	m.CertificatePEM = types.StringValue(res.Info.PEM)
	m.NotAfter = types.StringValue(res.Info.NotAfterString())
	m.Thumbprint = types.StringValue(res.Info.Thumbprint)
}

// warnLifetime adds a warning when a certificate that was just issued is already inside
// its renewal window, which would make every plan order again.
func warnLifetime(ctx context.Context, diags *diag.Diagnostics, m acmeCertificateModel, res issuer.Result) {
	if acme.InsideWindow(time.Now(), res.Info.NotAfter, m.MinDays.ValueInt64()) {
		msg := fmt.Sprintf("The issued certificate expires at %s, which is within min_days_remaining (%d days). "+
			"The next plan will order another certificate. Lower min_days_remaining or ask the certificate authority for "+
			"longer-lived certificates.", res.Info.NotAfterString(), m.MinDays.ValueInt64())
		tflog.Warn(ctx, msg)
		diags.AddWarning("The certificate is already due for renewal", msg)
	}
}

func (r *acmeCertificateResource) order(ctx context.Context, plan *acmeCertificateModel, config tfConfig, creating bool, diags *diag.Diagnostics) (issuer.Result, bool) {
	blocks, ok := readDNSBlocks(ctx, config, diags)
	if !ok {
		return issuer.Result{}, false
	}
	ids, err := identifiersOf(*plan)
	if err != nil {
		operationError(diags, "prepare the order for", plan.object(), err)
		return issuer.Result{}, false
	}
	// Only the blocks that serve a name of the order are used, and only they need a token.
	blocks, err = usedBlocks(ids, blocks)
	if err != nil {
		operationError(diags, "prepare the order for", plan.object(), err)
		return issuer.Result{}, false
	}
	for _, z := range blocks.Cloudflare {
		if z.Token == "" {
			diags.AddAttributeError(path.Root("cloudflare").AtListIndex(z.Block.Index).AtName("api_token"),
				"A Cloudflare API token is required to order the certificate",
				missingCloudflareTokenMessage(z.Block, "the order is running now"))
		}
	}
	if diags.HasError() {
		return issuer.Result{}, false
	}
	if len(blocks.Azure) > 0 {
		if pd, _ := r.data.(*providerData); pd != nil && pd.acme != nil && pd.acme.keyVaultToken != "" && pd.acme.resourceManagerToken == "" {
			diags.AddError("An Azure Resource Manager access token is required to order the certificate",
				missingResourceManagerTokenMessage(blocks.Azure[0].Block, "the order is running now"))
			return issuer.Result{}, false
		}
	}
	access := r.access(diags, len(blocks.Azure) > 0)
	if access == nil {
		return issuer.Result{}, false
	}
	o, err := r.buildOrder(ctx, access, *plan, blocks, creating)
	if err != nil {
		operationError(diags, "prepare the order for", plan.object(), err)
		return issuer.Result{}, false
	}
	verb := "renew"
	if creating {
		verb = "issue"
	}
	res, err := issuer.Issue(ctx, o)
	if err != nil {
		var left *issuer.LeftoverError
		if errors.As(err, &left) {
			diags.AddError("Cannot "+verb, plan.object()+": "+err.Error()+"\n\n"+leftoverNote(plan.CertificateName.ValueString()))
			return issuer.Result{}, false
		}
		operationError(diags, verb, plan.object(), err)
		return issuer.Result{}, false
	}
	return res, true
}

// leftoverNote explains the certificate that a failed first order leaves in Key Vault.
func leftoverNote(name string) string {
	return fmt.Sprintf("Key Vault now holds a certificate named %q that has no issued version: the order failed after "+
		"the certificate was created there. It is kept on purpose, so the next apply of this configuration reuses it and "+
		"issues the first version. If you abandon this configuration instead, remove it: delete the certificate in Key Vault "+
		"and, where the vault allows it, purge it (a deleted certificate keeps its name reserved until it is purged or its "+
		"retention period ends; recover it to use the name again).", name)
}

func (r *acmeCertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan acmeCertificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	res, ok := r.order(ctx, &plan, req.Config, true, &resp.Diagnostics)
	if !ok {
		return
	}
	vault, _ := acme.ParseVaultURL(plan.KeyVaultURL.ValueString())
	applyIssued(&plan, vault, res)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	resp.Diagnostics.Append(resp.Private.SetKey(ctx, issuedByKey, mustJSON(plan.RegistrationID.ValueString()))...)
	warnLifetime(ctx, &resp.Diagnostics, plan, res)
}

func (r *acmeCertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan acmeCertificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.IssuedVersion.IsUnknown() {
		// Only values the vault cannot report changed: record them, request nothing.
		resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
		return
	}
	res, ok := r.order(ctx, &plan, req.Config, false, &resp.Diagnostics)
	if !ok {
		return
	}
	vault, _ := acme.ParseVaultURL(plan.KeyVaultURL.ValueString())
	applyIssued(&plan, vault, res)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	resp.Diagnostics.Append(resp.Private.SetKey(ctx, importedVersionKey, nil)...)
	resp.Diagnostics.Append(resp.Private.SetKey(ctx, issuedByKey, mustJSON(plan.RegistrationID.ValueString()))...)
	warnLifetime(ctx, &resp.Diagnostics, plan, res)
}

// ---- destroy and import -------------------------------------------------------------

func (r *acmeCertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state acmeCertificateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	access := r.access(&resp.Diagnostics, false)
	if access == nil {
		return
	}
	vault, err := acme.ParseVaultURL(state.KeyVaultURL.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid key_vault_url", err.Error())
		return
	}
	name := state.CertificateName.ValueString()
	kv, err := access.keyVault(vault)
	if err != nil {
		operationError(&resp.Diagnostics, "delete", state.object(), err)
		return
	}

	if state.RevokeOnDestroy.ValueBool() {
		if !r.revoke(ctx, access, kv, state, req.Private, &resp.Diagnostics) {
			return
		}
	} else {
		tflog.Debug(ctx, "revocation skipped", map[string]any{"reason": "revoke_on_destroy is false"})
	}
	if err := kv.DeleteCertificate(ctx, name); err != nil {
		operationError(&resp.Diagnostics, "delete", state.object(), err)
	}
}

// revoke revokes the certificate of issued_version at the authority, unless it was
// issued elsewhere, has expired or is gone. It reports whether destroy may continue.
func (r *acmeCertificateResource) revoke(ctx context.Context, access *acmeAccess, kv *keyvault.Client, state acmeCertificateModel, private interface {
	GetKey(context.Context, string) ([]byte, diag.Diagnostics)
}, diags *diag.Diagnostics) bool {
	issued := state.IssuedVersion.ValueString()
	raw, d := private.GetKey(ctx, importedVersionKey)
	diags.Append(d...)
	var imported string
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &imported)
	}
	if imported != "" && imported == issued {
		msg := fmt.Sprintf("Version %s of the certificate was issued elsewhere and imported, and this resource has not renewed it, "+
			"so it is not revoked. It is deleted from Key Vault.", issued)
		tflog.Debug(ctx, "revocation skipped", map[string]any{"reason": "the version was issued elsewhere and imported"})
		tflog.Warn(ctx, msg)
		diags.AddWarning("The imported certificate is not revoked", msg)
		return !diags.HasError()
	}
	// The account that ordered the certificate revokes it; registration_id may have moved
	// to another account at the same authority since.
	regID := state.RegistrationID.ValueString()
	rawBy, d := private.GetKey(ctx, issuedByKey)
	diags.Append(d...)
	if len(rawBy) > 0 {
		var by string
		if json.Unmarshal(rawBy, &by) == nil && by != "" {
			regID = by
		}
	}
	if regID == "" {
		diags.AddError("Cannot revoke the certificate", state.object()+": registration_id is not recorded; apply the configuration once before destroying")
		return false
	}
	b, err := kv.GetCertificateVersion(ctx, state.CertificateName.ValueString(), issued)
	if errors.Is(err, keyvault.ErrNotFound) {
		tflog.Debug(ctx, "revocation skipped", map[string]any{"reason": "the issued version is gone from Key Vault"})
		return true
	}
	if err != nil {
		operationError(diags, "read the certificate before revoking", state.object(), err)
		return false
	}
	info, err := acme.Inspect(b.Cer)
	if err != nil {
		operationError(diags, "read the certificate before revoking", state.object(), err)
		return false
	}
	if info.NotAfter.Before(time.Now()) {
		tflog.Debug(ctx, "revocation skipped", map[string]any{"reason": "the certificate has expired"})
		tflog.Info(ctx, "the certificate has expired; it is not revoked")
		return true
	}
	server, key, err := acme.ParseRegistrationID(regID)
	if err != nil {
		diags.AddError("Invalid registration_id", err.Error())
		return false
	}
	reg, err := access.registration(ctx, server, key)
	if errors.Is(err, keyvault.ErrNotFound) {
		msg := fmt.Sprintf("The account key %s, whose account ordered version %s, no longer exists in Key Vault, so the certificate cannot be revoked "+
			"(only that account, or one that holds valid authorizations for all its names, may revoke it). It is deleted from Key Vault without being revoked.", key.Name, issued)
		tflog.Debug(ctx, "revocation skipped", map[string]any{"reason": "the account key that ordered the certificate is gone from Key Vault"})
		tflog.Warn(ctx, msg)
		diags.AddWarning("The certificate is not revoked", msg)
		return true
	}
	if err != nil {
		operationError(diags, "revoke", state.object(), err)
		return false
	}
	if err := issuer.Revoke(ctx, reg, b.Cer); err != nil {
		operationError(diags, "revoke", state.object(), err)
		return false
	}
	tflog.Debug(ctx, "the certificate was revoked at the authority", map[string]any{"version": issued})
	return true
}

func (r *acmeCertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	vault, name, err := acme.ParseCertificateImportID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), acme.CertificateID(vault, name))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key_vault_url"), vault)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("certificate_name"), name)...)
}
