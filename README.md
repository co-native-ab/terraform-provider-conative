# Terraform Provider: conative

[![Terraform Registry](https://img.shields.io/badge/Terraform-Registry-blue.svg)](https://registry.terraform.io/providers/co-native-ab/conative)
[![License](https://img.shields.io/github/license/co-native-ab/terraform-provider-conative)](LICENSE)

A Terraform provider for managing resources that the major cloud providers do not cover, or do not cover
well.

The first area is **Azure SQL Database**: managing Microsoft Entra principals (managed identities,
applications, users and groups) as contained database users, their fixed database role memberships, and
their database- and schema-level permissions. The provider authenticates with a Microsoft Entra access
token that you supply, so it works with whatever identity your Terraform run already uses. It never signs
in by itself and never stores or logs the token.

The second area is **ACME certificates in Azure Key Vault**: an account with an ACME certificate authority
such as Let's Encrypt whose key lives in Key Vault, and certificates issued through DNS-01 challenges in
Azure DNS and Cloudflare. Key Vault generates the certificate's private key, so it never reaches Terraform
or the state, and renewal adds a new version to the same Key Vault certificate. Existing Key Vault
certificates can be imported. See the [ACME guide](docs/guides/acme-certificates-in-key-vault.md).

| Type | Name |
| --- | --- |
| Resource | `conative_azuresql_database_user` |
| Resource | `conative_azuresql_database_role_member` |
| Resource | `conative_azuresql_database_permission` |
| Resource | `conative_acme_registration` |
| Resource | `conative_acme_certificate` |
| Data source | `conative_azuresql_database_user` |
| Data source | `conative_azuresql_database_users` |

## Authentication

The provider has no sign-in code of its own. For Azure SQL Database it takes a Microsoft Entra access token
for `https://database.windows.net/.default`, and any source of such a token works: an ephemeral resource,
`az account get-access-token`, or a variable set by your pipeline.

The recommended source is the [`co-native-ab/azidentity`](https://registry.terraform.io/providers/co-native-ab/azidentity)
provider. Its ephemeral resources obtain a fresh token on every run and keep it out of the plan and the state
(Terraform 1.10 or later). The example below uses `azidentity_default_credential`; the Azure CLI, client
secret and client assertion (workload identity) credentials work the same way. See the
[provider documentation](docs/index.md) for the alternative of passing the token in an ephemeral variable.

## Example

```hcl
terraform {
  required_version = ">= 1.10.0"

  required_providers {
    azidentity = {
      source  = "co-native-ab/azidentity"
      version = "~> 0.1"
    }
    conative = {
      source  = "co-native-ab/conative"
      version = "~> 0.1"
    }
  }
}

provider "azidentity" {}

ephemeral "azidentity_default_credential" "sql" {
  scopes = ["https://database.windows.net/.default"]
}

provider "conative" {
  azuresql = {
    server       = "example-server.database.windows.net"
    access_token = ephemeral.azidentity_default_credential.sql.access_token
  }
}

resource "conative_azuresql_database_user" "orders_app" {
  database = "orders"
  name     = "orders-app"
  type     = "application"
  entra_id = "00000000-0000-0000-0000-000000000000"
}

resource "conative_azuresql_database_role_member" "orders_app_owner" {
  database = "orders"
  role     = "db_owner"
  member   = conative_azuresql_database_user.orders_app.name
}
```

## Example: an ACME certificate

The ACME resources take two more tokens, for `https://vault.azure.net/.default` and
`https://management.azure.com/.default`, from the same provider. The Cloudflare token is a write-only
argument (Terraform 1.11 or later).

```hcl
provider "conative" {
  acme = {
    key_vault_access_token        = ephemeral.azidentity_default_credential.key_vault.access_token
    resource_manager_access_token = ephemeral.azidentity_default_credential.resource_manager.access_token
  }
}

resource "conative_acme_certificate" "example" {
  registration_id   = conative_acme_registration.letsencrypt.id
  key_vault_url     = azurerm_key_vault.example.vault_uri
  certificate_name  = "example-com"
  common_name       = "example.com"
  subject_alternative_names = ["*.example.com"]
  key_type          = "RSA4096"
  revoke_on_destroy = true

  cloudflare {
    zone          = "example.com"
    match_domains = ["example.com"]
    api_token     = ephemeral.azurerm_key_vault_secret.cloudflare_token.value
  }
}
```

## Documentation

See [`docs/`](docs/index.md) for the provider, every resource and data source, and a
guide to [Azure SQL](docs/guides/azure-sql-entra-principals.md) (sign-in, user creation, import and retries)
and to [ACME certificates](docs/guides/acme-certificates-in-key-vault.md).

## Requirements

- Terraform 1.0 or later; 1.10 or later to supply the token from an ephemeral resource or an ephemeral
  variable.
- A Microsoft Entra access token for `https://database.windows.net/.default`, with the permissions needed
  for what you manage.
- For the ACME resources: Terraform 1.11 or later (write-only arguments), and access tokens for
  `https://vault.azure.net/.default` and, for Azure DNS, `https://management.azure.com/.default`. The
  DNS propagation check needs direct UDP and TCP access to port 53 of the zone's name servers; behind a
  DNS-intercepting proxy set `dns_propagation_check = false` in the `acme` settings.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

> **Status:** early development. Nothing is released yet, and the interface may change without notice.

## License

[MIT](LICENSE)
