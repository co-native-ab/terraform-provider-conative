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

## Example

```hcl
terraform {
  required_providers {
    conative = {
      source = "co-native-ab/conative"
    }
  }
}

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

- Terraform 1.0 or later; 1.10 or later to supply the token from an ephemeral variable.
- A Microsoft Entra access token for `https://database.windows.net/.default`, with the permissions needed
  for what you manage.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

> **Status:** early development. Nothing is released yet, and the interface may change without notice.

## License

[MIT](LICENSE)
