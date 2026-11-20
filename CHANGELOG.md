# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, an incompatible change
bumps the minor version.

## Unreleased

### Added

- Provider settings `azuresql` with `server`, `access_token` (sensitive; never stored or logged) and
  `retry_timeout`. The settings are required only when an Azure SQL resource or data source is used.
- Resource `conative_azuresql_database_user`: a contained database user for a Microsoft Entra
  application, user or group, created from its ID without a directory lookup. Importable as
  `database/name`.
- Resource `conative_azuresql_database_role_member`: membership of a user in one fixed database
  role. Importable as `database/role/member`.
- Resource `conative_azuresql_database_permission`: one `GRANT` or `DENY` of a permission on a database
  or a schema. Importable as `database/principal/STATE/PERMISSION[/schema]`.
- Data sources `conative_azuresql_database_user` and `conative_azuresql_database_users` to look up
  database users.
- Documentation, including a guide to the Azure SQL resources.
