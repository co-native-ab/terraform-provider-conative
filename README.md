# Terraform Provider: conative

A Terraform provider for managing resources that the major cloud providers do not cover, or do not cover
well.

The first area is **Azure SQL Database**: managing Microsoft Entra principals (managed identities,
applications, users and groups) as contained database users, their fixed database role memberships, and
their database- and schema-level permissions. The provider authenticates with a Microsoft Entra access
token that you supply, so it works with whatever identity your Terraform run already uses. It never signs
in by itself and never stores or logs the token.

| Type | Name |
| --- | --- |
| Resource | `conative_azuresql_database_user` |
| Resource | `conative_azuresql_database_role_member` |
| Resource | `conative_azuresql_database_permission` |
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
      source = "co-native-ab/conative"
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

## Documentation

See [`docs/`](docs/index.md) for the provider, every resource and data source, and a
[guide](docs/guides/azure-sql-entra-principals.md) to how sign-in, user creation, import and retries work.

## Requirements

- Terraform 1.0 or later; 1.10 or later to supply the token from an ephemeral resource or an ephemeral
  variable.
- A Microsoft Entra access token for `https://database.windows.net/.default`, with the permissions needed
  for what you manage.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

> **Status:** early development. Nothing is released yet, and the interface may change without notice.

## License

[MIT](LICENSE)
