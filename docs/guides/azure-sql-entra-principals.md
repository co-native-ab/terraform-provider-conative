---
page_title: "Managing Microsoft Entra principals in Azure SQL Database"
subcategory: ""
description: |-
  How the Azure SQL Database resources sign in, create users, handle imports and retry.
---

# Managing Microsoft Entra principals in Azure SQL Database

This guide explains how the `conative_azuresql_*` resources and data sources behave, and why.

## Supplying the access token

The provider contains no sign-in code. It never calls Microsoft Entra ID and never asks for a
credential of its own: you give it an access token for `https://database.windows.net/.default`, and it
uses that token to open connections for the length of the run.

- The token is a sensitive attribute and is never written to state, a plan, a log line or an error
  message, at any log level.
- Obtain the token outside the provider, for example with the Azure CLI:

  ```shell
  export TF_VAR_sql_token="$(az account get-access-token \
    --resource https://database.windows.net/ --query accessToken --output tsv)"
  ```

- Declare the variable as `ephemeral = true` (Terraform 1.10 or later), so that Terraform does not
  persist it either. Older Terraform versions work too, but then Terraform itself may keep the value
  in a saved plan.
- Tokens are short-lived. Obtain a fresh one for each run.
- Connections always use encryption and always validate the server certificate against the host name
  in `server`. There is no setting to turn either off.

The provider settings are required only when a resource or data source of this area is used. A
configuration that does not use one needs no `azuresql` block.

One provider configuration manages one logical server. Use provider aliases for more servers.

## The identity that runs Terraform

The token belongs to a principal in the database, and that principal needs the permissions for what
you manage. The provider checks nothing and grants nothing itself.

| You manage | The principal needs |
| --- | --- |
| `conative_azuresql_database_user` | `ALTER ANY USER` in the database |
| `conative_azuresql_database_role_member` | `ALTER ANY ROLE`, or ownership of the role |
| `conative_azuresql_database_permission` | `CONTROL` on the database or schema, or the permission with grant option |

A principal that is a member of `db_owner` has all of these.

## Users are created from an ID, without a directory lookup

A database user is created from the Entra ID you configure, with a statement of the form

```sql
CREATE USER [name] WITH SID = 0x..., TYPE = E;
```

The security identifier is derived from the ID itself: the GUID's bytes in the order SQL Server stores a
`uniqueidentifier`. Because nothing is looked up in the directory, the server does not need permission to
read the directory, and the resource cannot pick the wrong principal because of a display name.

Which ID to use depends on `type`:

| `type` | `entra_id` | Created as |
| --- | --- | --- |
| `application` | the application (client) ID of a service principal or managed identity | external user (`E`) |
| `user` | the object ID of the user | external user (`E`) |
| `group` | the object ID of the group | external group (`X`) |

The `name` is only the name of the user in the database. It does not have to match anything in Entra ID.

## Import, and what `type` means after an import

Every resource can be imported. Import IDs are `/`-separated:

| Resource | Import ID |
| --- | --- |
| `conative_azuresql_database_user` | `database/name` |
| `conative_azuresql_database_role_member` | `database/role/member` |
| `conative_azuresql_database_permission` | `database/principal/STATE/PERMISSION`, or `database/principal/STATE/PERMISSION/schema` for a schema |

Names can contain `/` and `%`. Inside an ID, write `%` as `%25` and `/` as `%2F`, and nothing else is
escaped. For example, the user `x%y` in the database `a/b` is imported as `a%2Fb/x%25y`.

A database cannot tell an application from a user: both are external users. The provider therefore
keeps `type` from your configuration instead of reading it back. After an import, `type` is empty in
state. The next plan records it without touching the database, provided the type the database reports
fits the configuration (`EXTERNAL_USER` for `application` and `user`, `EXTERNAL_GROUP` for `group`);
otherwise the plan replaces the user, just as it does for a different `entra_id`.

Creating a user, a role membership or a permission fails if it already exists, and the error shows
the import command. The provider never adopts something it was not told about.

## Role memberships and permissions

- Only the fixed database roles are supported: `db_accessadmin`, `db_backupoperator`, `db_datareader`,
  `db_datawriter`, `db_ddladmin`, `db_denydatareader`, `db_denydatawriter`, `db_owner` and
  `db_securityadmin`.
- A membership resource adds and removes exactly that membership. A permission resource grants or denies
  exactly that permission and revokes exactly that permission on destroy, without cascading.
- Permissions are never granted with grant option. A permission held with grant option, set outside
  Terraform, shows as `GRANT_WITH_GRANT_OPTION`, which differs from the configuration and plans a
  replacement. The revoke then fails until the grant option is removed.
- Every new database user already holds `CONNECT`. To manage it, import it.
- Permission names are validated before any statement is built, against the list of permissions the
  database engine reports for databases and for schemas.

## Retries and failures

The provider retries only the act of connecting, and only when the engine answers with an error that
Microsoft documents as transient: 615, 926, 4060, 4221, 40197, 40501, 40613, 49918, 49919 and 49920.
Delays start at five seconds and double up to one minute, for at most `retry_timeout` in total (two
minutes by default; `"0s"` turns retries off). Then the run fails with the last error.

Everything else fails at once: a rejected token, an unreachable server, a failed certificate check, any
error from a statement. Statements are never retried.

A failure to connect, sign in or read is never taken to mean that something is gone. A resource leaves
state only after a successful read that shows it does not exist.
