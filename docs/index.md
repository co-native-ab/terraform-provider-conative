---
page_title: "conative Provider"
subcategory: ""
description: |-
    Manages resources that the major cloud providers do not cover, or do not cover well. The first area is Azure SQL Database: Microsoft Entra principals as contained database users, their role memberships and their permissions. The second is ACME: certificates from an ACME certificate authority such as Let's Encrypt, issued into Azure Key Vault with DNS-01 challenges in Azure DNS or Cloudflare.
---

# conative Provider

Manages resources that the major cloud providers do not cover, or do not cover well. The first area is Azure SQL Database: Microsoft Entra principals as contained database users, their role memberships and their permissions. The second is ACME: certificates from an ACME certificate authority such as Let's Encrypt, issued into Azure Key Vault with DNS-01 challenges in Azure DNS or Cloudflare.

See the [Azure SQL guide](guides/azure-sql-entra-principals) for how the access token, user creation,
import and retries work, and the [ACME guide](guides/acme-certificates-in-key-vault) for certificates issued
into Azure Key Vault.

## Authentication

The provider contains no sign-in code. For Azure SQL Database it takes a Microsoft Entra access token for
`https://database.windows.net/.default` in `azuresql.access_token`, and any source of such a token works.

The recommended way to obtain one is the [`co-native-ab/azidentity`](https://registry.terraform.io/providers/co-native-ab/azidentity)
provider, whose ephemeral resources acquire a token at the start of each run without storing it in the plan
or the state (Terraform 1.10 or later). The example below uses `azidentity_default_credential`, which picks a
suitable method on its own, such as environment variables, a managed identity or an Azure CLI session. The
other credential types work the same way: `azidentity_azure_cli_credential`, `azidentity_client_secret_credential`
and `azidentity_client_assertion_credential` (for example workload identity federation in a CI pipeline) all
take `scopes` and return `access_token`. Leave their `continue_on_error` at its default, `false`, so that a
failure to obtain the token stops the run where it happens.

## Example Usage

```terraform
terraform {
  # Ephemeral resources need Terraform 1.10 or later.
  required_version = ">= 1.10.0"

  required_providers {
    azidentity = {
      source  = "co-native-ab/azidentity"
      version = "~> 0.1"
    }
    conative = {
      source = "co-native-ab/conative"
    }
  }
}

provider "azidentity" {}

# Obtain a Microsoft Entra access token for Azure SQL Database at the start of each run.
# The token is an ephemeral value, so it never reaches the plan or the state.
ephemeral "azidentity_default_credential" "sql" {
  scopes = ["https://database.windows.net/.default"]
}

provider "conative" {
  azuresql = {
    server        = "example-server.database.windows.net"
    access_token  = ephemeral.azidentity_default_credential.sql.access_token
    retry_timeout = "2m" # optional
  }
}

# To manage a second server, add a provider alias. The same token works for every
# server the identity has access to.
provider "conative" {
  alias = "reporting"

  azuresql = {
    server       = "reporting-server.database.windows.net"
    access_token = ephemeral.azidentity_default_credential.sql.access_token
  }
}
```

### ACME

The `conative_acme_registration` and `conative_acme_certificate` resources take two access tokens in the
`acme` settings, and neither is needed unless you use them:

- `key_vault_access_token`, for `https://vault.azure.net/.default`. It signs the requests to the certificate
  authority with the account key and creates, reads, merges and deletes certificates in Key Vault.
- `resource_manager_access_token`, for `https://management.azure.com/.default`. It writes the challenge records
  in Azure DNS, so it is needed only when a certificate has an `azure_dns` block.

Both tokens are sensitive and are never stored or logged. Obtain them from the same `azidentity` provider, one
ephemeral resource per scope. The Cloudflare API token of a certificate is not a provider setting: it is a
write-only argument on the certificate itself. Using write-only arguments needs Terraform 1.11 or later.

```terraform
terraform {
  # Ephemeral resources need Terraform 1.10 or later. The write-only Cloudflare API token
  # of conative_acme_certificate needs 1.11 or later.
  required_version = ">= 1.11.0"

  required_providers {
    azidentity = {
      source  = "co-native-ab/azidentity"
      version = "~> 0.1"
    }
    conative = {
      source = "co-native-ab/conative"
    }
  }
}

provider "azidentity" {}

# One token for Key Vault: it signs the requests to the certificate authority with the
# account key and manages the certificate.
ephemeral "azidentity_default_credential" "key_vault" {
  scopes = ["https://vault.azure.net/.default"]
}

# One token for Azure Resource Manager: it writes the challenge records in Azure DNS.
# Needed only when an order runs for names that an azure_dns block serves; plans in which
# nothing is ordered do not need it.
ephemeral "azidentity_default_credential" "resource_manager" {
  scopes = ["https://management.azure.com/.default"]
}

provider "conative" {
  acme = {
    key_vault_access_token        = ephemeral.azidentity_default_credential.key_vault.access_token
    resource_manager_access_token = ephemeral.azidentity_default_credential.resource_manager.access_token
  }
}
```

### Supplying the token from a variable

A token obtained outside Terraform, for example with `az account get-access-token` or from a pipeline
variable, works just as well. Declare the variable `ephemeral` so that Terraform does not keep it.

```terraform
terraform {
  required_providers {
    conative = {
      source = "co-native-ab/conative"
    }
  }
}

# A Microsoft Entra access token for https://database.windows.net/.default,
# obtained outside Terraform, for example with
#
#   export TF_VAR_sql_token="$(az account get-access-token \
#     --resource https://database.windows.net/ --query accessToken --output tsv)"
#
# Marking the variable ephemeral keeps the token out of the plan and the state
# (Terraform 1.10 or later).
variable "sql_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

provider "conative" {
  azuresql = {
    server       = "example-server.database.windows.net"
    access_token = var.sql_token
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `acme` (Attributes) Settings for the ACME resources. Required only when one of them is used. (see [below for nested schema](#nestedatt--acme))
- `azuresql` (Attributes) Settings for Azure SQL Database resources and data sources. Required only when one of them is used. (see [below for nested schema](#nestedatt--azuresql))

<a id="nestedatt--acme"></a>
### Nested Schema for `acme`

Required:

- `key_vault_access_token` (String, Sensitive) A Microsoft Entra access token for `https://vault.azure.net/.default`. Used to sign ACME requests with the account key and to create, read, merge and delete certificates in Key Vault. The provider never signs in by itself, never stores the token and never writes it to logs. Supply it from an ephemeral resource or ephemeral variable.

Optional:

- `resource_manager_access_token` (String, Sensitive) A Microsoft Entra access token for `https://management.azure.com/.default`, used to write DNS-01 challenge records in Azure DNS. Optional: it is needed only when an order runs (a new certificate or a renewal) for names served by an `azure_dns` block. Refreshing and planning, and plans in which nothing is ordered, do not need it. When an order is planned and the token is missing, the plan fails and names the block.


<a id="nestedatt--azuresql"></a>
### Nested Schema for `azuresql`

Required:

- `access_token` (String, Sensitive) A Microsoft Entra access token for `https://database.windows.net/.default`. The provider never signs in by itself, never stores the token and never writes it to logs. Supply it from an ephemeral resource or ephemeral variable.
- `server` (String) Fully qualified name of the logical server, optionally with `:port` (default 1433). One provider configuration manages one server; use provider aliases for more.

Optional:

- `retry_timeout` (String) Maximum total time to keep retrying a connection that fails with an error Microsoft documents as transient. A duration such as `"2m"` (the default) or `"0s"` to disable. Other errors are never retried.
