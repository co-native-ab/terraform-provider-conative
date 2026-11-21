package provider

import (
	"context"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"

	"github.com/co-native-ab/terraform-provider-conative/internal/azuresql/sqlclient"
)

// errMissingSettings is the message of every resource and data source that needs a
// connection when the provider has none.
const errMissingSettings = "the provider's azuresql settings (server, access_token) are required for this resource"

// azureSQL is what Configure hands to resources and data sources: a client, or the
// reason there is none.
type azureSQL struct {
	client *sqlclient.Client
	reason string
}

// requireClient returns the client, or adds an error naming the missing settings.
// It is for create, read, update, delete and data source reads, which only run after
// the provider is configured; a missing client there is an error, never a silent skip.
func requireClient(data any, diags *diag.Diagnostics) *sqlclient.Client {
	a, ok := data.(*azureSQL)
	if !ok || a == nil {
		diags.AddError("Azure SQL settings are required", "the provider was not configured for this operation")
		return nil
	}
	if a.client == nil {
		diags.AddError("Azure SQL settings are required", errMissingSettings+": "+a.reason)
		return nil
	}
	return a.client
}

// operationError adds an error diagnostic for a failed operation. The message names
// the operation and the object; the underlying error never carries parameters or the
// access token.
func operationError(diags *diag.Diagnostics, operation, object string, err error) {
	diags.AddError("Cannot "+operation, object+": "+err.Error())
}

// readOrRemove decides what a Read does after querying the database. A query error
// is reported and the state is kept: a failure to connect, sign in or read is never
// taken to mean the object is gone. Only a successful query that found nothing
// removes the resource from state. It reports whether the resource still exists and
// should be refreshed.
func readOrRemove(ctx context.Context, state *tfsdk.State, diags *diag.Diagnostics, operation, object string, found bool, err error) bool {
	if err != nil {
		operationError(diags, operation, object, err)
		return false
	}
	if !found {
		state.RemoveResource(ctx)
		return false
	}
	return true
}
