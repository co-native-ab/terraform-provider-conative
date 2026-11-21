package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/issuer"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/keyvault"
)

var (
	_ resource.Resource                = (*acmeRegistrationResource)(nil)
	_ resource.ResourceWithConfigure   = (*acmeRegistrationResource)(nil)
	_ resource.ResourceWithImportState = (*acmeRegistrationResource)(nil)
)

// NewACMERegistrationResource returns the conative_acme_registration resource.
func NewACMERegistrationResource() resource.Resource { return &acmeRegistrationResource{} }

type acmeRegistrationResource struct {
	data any
}

type acmeRegistrationModel struct {
	ID           types.String `tfsdk:"id"`
	ServerURL    types.String `tfsdk:"server_url"`
	AccountKeyID types.String `tfsdk:"account_key_id"`
	Email        types.String `tfsdk:"email"`
	AccountURL   types.String `tfsdk:"account_url"`
}

func (r *acmeRegistrationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acme_registration"
}

func (r *acmeRegistrationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "An account with an ACME certificate authority whose key is a Key Vault key. " +
			"Every request to the authority is signed by Key Vault; the private key never leaves it. " +
			"If the authority already has an account for the key, that account is used. " +
			"Refreshing and planning never sign anything and never contact the authority: they only read the " +
			"key's metadata from Key Vault. Creating, updating the email and importing sign. " +
			"Creating an account agrees to the authority's terms of service. " +
			"Destroying the resource does not deactivate the account.",
		Attributes: map[string]schema.Attribute{
			"server_url": schema.StringAttribute{
				MarkdownDescription: "The ACME directory URL, for example Let's Encrypt's " +
					"`https://acme-v02.api.letsencrypt.org/directory` (or its staging directory for testing). " +
					"Changing it replaces the registration.",
				Required:      true,
				Validators:    []validator.String{checkString("must be an https URL", acme.ValidateServerURL)},
				PlanModifiers: replace,
			},
			"account_key_id": schema.StringAttribute{
				MarkdownDescription: "The versioned ID of an existing Key Vault key (`https://<name>.vault.azure.net/keys/<key>/<version>`), " +
					"RSA (2048 bits or more) or EC (P-256, P-384 or P-521), with the `sign` operation permitted. " +
					"Whether the key is exportable does not matter. Some authorities do not accept every key: " +
					"Let's Encrypt, for example, does not accept P-521 account keys. Changing it replaces the " +
					"registration.",
				Required:      true,
				Validators:    []validator.String{checkString("must be a versioned Key Vault key ID", validateKeyID)},
				PlanModifiers: replace,
			},
			"email": schema.StringAttribute{
				MarkdownDescription: "A contact address for the account. Setting or changing it updates the account (which signs " +
					"a request with the account key). Removing it stops managing the contact; the authority keeps the " +
					"last address. Some certificate authorities, Let's Encrypt among them, do not report or store an " +
					"account's contact address, so it cannot be read back: Terraform keeps the configured value.",
				Optional:   true,
				Validators: []validator.String{checkString("must be an e-mail address", acme.ValidateEmail)},
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "`<server_url>|<account_key_id>`. Use it as a certificate's `registration_id`.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"account_url": schema.StringAttribute{
				MarkdownDescription: "The account's URL at the certificate authority.",
				Computed:            true,
				PlanModifiers:       keep,
			},
		},
	}
}

func validateKeyID(s string) error {
	_, err := acme.ParseKeyID(s)
	return err
}

func (r *acmeRegistrationResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.data = req.ProviderData
}

func (m acmeRegistrationModel) object() string {
	return fmt.Sprintf("ACME registration at %s", m.ServerURL.ValueString())
}

// registration builds the account access for a model: the signer comes from Key Vault.
func (r *acmeRegistrationResource) registration(ctx context.Context, m acmeRegistrationModel, diags *diag.Diagnostics) (issuer.Registration, bool) {
	access := requireACME(r.data, diags, false)
	if access == nil {
		return issuer.Registration{}, false
	}
	key, err := acme.ParseKeyID(m.AccountKeyID.ValueString())
	if err != nil {
		diags.AddError("Invalid account_key_id", err.Error())
		return issuer.Registration{}, false
	}
	reg, err := access.registration(ctx, m.ServerURL.ValueString(), key)
	if err != nil {
		diags.AddError("Cannot use the account key", m.object()+": "+err.Error())
		return issuer.Registration{}, false
	}
	return reg, true
}

func (r *acmeRegistrationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan acmeRegistrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	reg, ok := r.registration(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	email := plan.Email.ValueString()
	tflog.Debug(ctx, "creating acme registration")

	acct, err := issuer.Lookup(ctx, reg)
	switch {
	case err == nil:
		// Some authorities (Let's Encrypt among them) do not report an account's contacts.
		// Without a list nothing says the address differs, so nothing is sent.
		if email != "" && len(acct.Contact) > 0 && !hasContact(acct.Contact, email) {
			acct, err = issuer.UpdateContact(ctx, reg, acct.URL, email)
		}
	case errors.Is(err, issuer.ErrNoAccount):
		acct, err = issuer.Register(ctx, reg, email)
	}
	if err != nil {
		operationError(&resp.Diagnostics, "create", plan.object(), err)
		return
	}
	plan.ID = types.StringValue(acme.RegistrationID(plan.ServerURL.ValueString(), plan.AccountKeyID.ValueString()))
	plan.AccountURL = types.StringValue(acct.URL)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func hasContact(contacts []string, email string) bool {
	for _, c := range contacts {
		if c == "mailto:"+email {
			return true
		}
	}
	return false
}

// Read refreshes the registration without signing anything: the account URL is kept from
// state, and Key Vault is asked only for the key's metadata, to confirm the key still
// exists. Only a key that Key Vault answers with "not found" removes the registration
// from state; any other failure is an error and the state is kept. The one exception is
// the first read after an import, which has to ask the certificate authority for the
// account and therefore signs.
func (r *acmeRegistrationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state acmeRegistrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	access := requireACME(r.data, &resp.Diagnostics, false)
	if access == nil {
		return
	}
	key, err := acme.ParseKeyID(state.AccountKeyID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid account_key_id", err.Error())
		return
	}
	kv, err := access.keyVault(key.Vault)
	if err != nil {
		operationError(&resp.Diagnostics, "read", state.object(), err)
		return
	}
	tflog.Debug(ctx, "reading acme registration")
	if _, err := kv.GetKey(ctx, key.Name, key.Version); err != nil {
		if errors.Is(err, keyvault.ErrNotFound) {
			resp.State.RemoveResource(ctx)
			return
		}
		operationError(&resp.Diagnostics, "read the account key of", state.object(), err)
		return
	}

	if state.AccountURL.IsNull() || state.AccountURL.IsUnknown() {
		// Import: the account is looked up once, which needs the key to sign.
		reg, ok := r.registration(ctx, state, &resp.Diagnostics)
		if !ok {
			return
		}
		acct, err := issuer.Lookup(ctx, reg)
		if errors.Is(err, issuer.ErrNoAccount) {
			resp.State.RemoveResource(ctx)
			return
		}
		if err != nil {
			operationError(&resp.Diagnostics, "read", state.object(), err)
			return
		}
		// The contact address is not read back: many authorities do not report it. After an
		// import an email in the configuration is set by the first apply.
		state.AccountURL = types.StringValue(acct.URL)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *acmeRegistrationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan acmeRegistrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Removing the email only stops managing the contact: no request.
	if !plan.Email.IsNull() {
		reg, ok := r.registration(ctx, plan, &resp.Diagnostics)
		if !ok {
			return
		}
		acct, err := issuer.UpdateContact(ctx, reg, plan.AccountURL.ValueString(), plan.Email.ValueString())
		if err != nil {
			operationError(&resp.Diagnostics, "update", plan.object(), err)
			return
		}
		plan.AccountURL = types.StringValue(acct.URL)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete removes the registration from state. The account is not deactivated: it may be
// shared with other configurations.
func (r *acmeRegistrationResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
}

func (r *acmeRegistrationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	server, keyID, ok := strings.Cut(req.ID, "|")
	if _, _, err := acme.ParseRegistrationID(req.ID); err != nil || !ok {
		msg := "must be <server_url>|<account_key_id>"
		if err != nil {
			msg = err.Error()
		}
		resp.Diagnostics.AddError("Invalid import ID", msg)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("server_url"), server)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("account_key_id"), keyID)...)
}
