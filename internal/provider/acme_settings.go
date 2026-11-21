package provider

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/dnscheck"
)

const (
	resourceManagerBaseURL = "https://management.azure.com"
	cloudflareBaseURL      = "https://api.cloudflare.com/client/v4"
)

// acmeEnv holds what the ACME resources need besides the settings: the endpoints that
// are fixed in the provider, the propagation check and the HTTP client. New fills the
// production values. Tests in this package set others (loopback fakes); nothing outside
// a test file can, and every client refuses a base URL that is not https.
type acmeEnv struct {
	resourceManagerURL string
	cloudflareURL      string
	// propagationFor builds the propagation check from the settings; nil means the
	// production check (dnscheck.Authoritative, or dnscheck.DelayOnly when it is off).
	propagationFor func(check bool, timeout time.Duration) dnscheck.Checker
	httpClient     *http.Client
	// retryBase and waitTimeout shorten the pauses and waits of an order in tests; zero
	// means the production values.
	retryBase   time.Duration
	waitTimeout time.Duration
}

func productionACMEEnv() acmeEnv {
	return acmeEnv{
		resourceManagerURL: resourceManagerBaseURL,
		cloudflareURL:      cloudflareBaseURL,
	}
}

// acmeAccess is the ACME area of the provider data: the tokens, or the reason there are
// none, plus the shared HTTP client and the endpoints.
type acmeAccess struct {
	keyVaultToken        string
	resourceManagerToken string
	// reason says why the settings are unusable; unknown is true when that is only
	// because a value is not known until apply.
	reason  string
	unknown bool
	// resourceManagerUnknown is true when the Resource Manager token is not known until
	// apply.
	resourceManagerUnknown bool

	// propagationCheck says whether the provider waits until the challenge records are
	// visible on the zone's name servers; propagationTimeout bounds that wait.
	propagationCheck   bool
	propagationTimeout time.Duration

	http *http.Client
	env  acmeEnv
}

// propagation returns the check an order runs after it has written its records.
func (a *acmeAccess) propagation() dnscheck.Checker {
	if a.env.propagationFor != nil {
		return a.env.propagationFor(a.propagationCheck, a.propagationTimeout)
	}
	if !a.propagationCheck {
		return dnscheck.DelayOnly{Delay: dnscheck.DefaultInitialDelay}
	}
	c := dnscheck.Default()
	c.Timeout = a.propagationTimeout
	return c
}

type acmeModel struct {
	KeyVaultAccessToken        types.String `tfsdk:"key_vault_access_token"`
	ResourceManagerAccessToken types.String `tfsdk:"resource_manager_access_token"`
	DNSPropagationCheck        types.Bool   `tfsdk:"dns_propagation_check"`
	DNSPropagationTimeout      types.String `tfsdk:"dns_propagation_timeout"`
}

func acmeSettingsSchema() schema.Attribute {
	return schema.SingleNestedAttribute{
		Description: "Settings for the ACME resources. Required only when one of them is used.",
		Optional:    true,
		Attributes: map[string]schema.Attribute{
			"key_vault_access_token": schema.StringAttribute{
				Description: "A Microsoft Entra access token for `https://vault.azure.net/.default`. " +
					"Used to sign ACME requests with the account key and to create, read, merge and delete " +
					"certificates in Key Vault. The provider never signs in by itself, never stores the token " +
					"and never writes it to logs. Supply it from an ephemeral resource or ephemeral variable.",
				Required:  true,
				Sensitive: true,
			},
			"resource_manager_access_token": schema.StringAttribute{
				Description: "A Microsoft Entra access token for `https://management.azure.com/.default`, " +
					"used to write DNS-01 challenge records in Azure DNS. Optional: it is needed only when an order " +
					"runs (a new certificate or a renewal) for names served by an `azure_dns` block. Refreshing and " +
					"planning, and plans in which nothing is ordered, do not need it. When an order is planned and " +
					"the token is missing, the plan fails and names the block.",
				Optional:  true,
				Sensitive: true,
			},
			"dns_propagation_check": schema.BoolAttribute{
				Description: "Whether to wait until the challenge records are visible on the zone's authoritative " +
					"name servers before the certificate authority is asked to validate them. Default `true`. " +
					"The check waits five seconds, then queries every name server of the zone directly (UDP, with " +
					"a fall back to TCP, port 53) every five seconds and trusts only answers that carry the " +
					"authoritative-answer flag. It needs direct access to port 53 of those name servers and does not " +
					"work behind a DNS-intercepting proxy or secure web gateway, which answers on their behalf; " +
					"set this to `false` there. When it is `false` the provider still waits five seconds after " +
					"writing the records and then lets the certificate authority validate them.",
				Optional: true,
			},
			"dns_propagation_timeout": schema.StringAttribute{
				Description: "How long the propagation check keeps polling, as a Go duration such as `90s` or `5m`, " +
					"between `10s` and `30m`. Default `2m`. Ignored when `dns_propagation_check` is `false`.",
				Optional:   true,
				Validators: []validator.String{checkString("must be a duration between 10s and 30m", validatePropagationTimeout)},
			},
		},
	}
}

func validatePropagationTimeout(s string) error {
	_, err := acme.ParsePropagationTimeout(s)
	return err
}

// defaultHTTPClient is shared by every ACME request: TLS 1.2 or later, a 30 second limit
// per request and the standard proxy environment.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}
}

// configureACME turns the acme settings into access, or records why they are unusable.
func (p *conativeProvider) configureACME(ctx context.Context, obj types.Object, resp *provider.ConfigureResponse) *acmeAccess {
	access := &acmeAccess{
		env: p.acmeEnv, http: p.acmeEnv.httpClient,
		propagationCheck: true, propagationTimeout: acme.DefaultPropagationTimeout,
	}
	if access.http == nil {
		access.http = defaultHTTPClient()
	}
	switch {
	case obj.IsNull():
		access.reason = "the acme block is not set"
		return access
	case obj.IsUnknown():
		access.reason, access.unknown = "the acme block is not known until apply", true
		return access
	}
	var s acmeModel
	resp.Diagnostics.Append(obj.As(ctx, &s, basetypes.ObjectAsOptions{})...)
	if resp.Diagnostics.HasError() {
		return access
	}
	switch {
	case s.KeyVaultAccessToken.IsUnknown():
		access.reason, access.unknown = "acme.key_vault_access_token is not known until apply", true
	case s.KeyVaultAccessToken.IsNull() || s.KeyVaultAccessToken.ValueString() == "":
		access.reason = "acme.key_vault_access_token is not set"
	default:
		access.keyVaultToken = s.KeyVaultAccessToken.ValueString()
	}
	access.propagationCheck = s.DNSPropagationCheck.IsNull() || s.DNSPropagationCheck.IsUnknown() || s.DNSPropagationCheck.ValueBool()
	access.propagationTimeout = acme.DefaultPropagationTimeout
	if !s.DNSPropagationTimeout.IsNull() && !s.DNSPropagationTimeout.IsUnknown() {
		if d, err := acme.ParsePropagationTimeout(s.DNSPropagationTimeout.ValueString()); err == nil {
			access.propagationTimeout = d
		}
	}
	switch {
	case s.ResourceManagerAccessToken.IsUnknown():
		access.resourceManagerUnknown = true
	case !s.ResourceManagerAccessToken.IsNull():
		access.resourceManagerToken = s.ResourceManagerAccessToken.ValueString()
	}
	return access
}

// requireACME returns the ACME access, or adds an error naming the missing setting. It
// is for create, read, update and delete, which only run once values are known. When
// needResourceManager is true the Resource Manager token is required too.
func requireACME(data any, diags *diag.Diagnostics, needResourceManager bool) *acmeAccess {
	pd, _ := data.(*providerData)
	if pd == nil || pd.acme == nil {
		diags.AddError("ACME settings are required", "the provider was not configured for this operation")
		return nil
	}
	a := pd.acme
	if a.keyVaultToken == "" {
		diags.AddError("ACME settings are required",
			"the provider's acme settings (key_vault_access_token) are required for this resource: "+a.reason)
		return nil
	}
	if needResourceManager && a.resourceManagerToken == "" {
		reason := "it is not set"
		if a.resourceManagerUnknown {
			reason = "it is not known until apply"
		}
		diags.AddError("ACME settings are required",
			"the provider's acme setting resource_manager_access_token is required for a certificate with an azure_dns block, but "+reason)
		return nil
	}
	return a
}
