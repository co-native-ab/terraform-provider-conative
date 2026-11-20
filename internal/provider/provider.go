// Package provider implements the conative Terraform provider.
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ provider.Provider = (*conativeProvider)(nil)

type conativeProvider struct {
	version string
}

// New returns a provider factory for the given provider version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &conativeProvider{version: version}
	}
}

func (p *conativeProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "conative"
	resp.Version = p.version
}

func (p *conativeProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

func (p *conativeProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
}

func (p *conativeProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

func (p *conativeProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
