# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, an incompatible change
bumps the minor version.

## Unreleased

### Added

- Provider settings `acme` with `key_vault_access_token` and `resource_manager_access_token` (both
  sensitive; never stored or logged). The settings are required only when an ACME resource is used, and
  the second only for certificates with an `azure_dns` block.
- Resource `conative_acme_registration`: an account with an ACME certificate authority whose key is a
  Key Vault key; every request is signed by Key Vault. Importable as `server_url|account_key_id`.
- Resource `conative_acme_certificate`: a certificate in Key Vault issued through DNS-01 challenges in
  Azure DNS and Cloudflare, in one order if needed. The private key is generated in Key Vault and never
  stored in the state. Renewal updates the resource in place and adds a new version to the same Key Vault
  certificate. `cloudflare.api_token` is a write-only argument and needs Terraform 1.11 or later. Plans
  only read. Importable by the versionless Key Vault certificate ID, including a certificate issued
  elsewhere; the first renewal moves it to a key generated in Key Vault.
- A guide to the ACME resources, and documentation of the `acme` settings with the
  [`co-native-ab/azidentity`](https://registry.terraform.io/providers/co-native-ab/azidentity) provider as
  the token source.

## 0.1.1 (2026-11-21)

### Security

- Updated dependencies to address vulnerabilities reported by `govulncheck`:
  - `google.golang.org/grpc` 1.83.2, which fixes GO-2026-6443.
  - `golang.org/x/net` v0.63.0, which fixes GO-2026-6603, GO-2026-6611, GO-2026-6612 and GO-2026-6617.
  - Go 1.27.4, which fixes GO-2026-6859 in `net/http`.

## 0.1.0 (2026-11-21)

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
- Documentation of how to supply the access token with the ephemeral resources of the
  [`co-native-ab/azidentity`](https://registry.terraform.io/providers/co-native-ab/azidentity) provider,
  the recommended source, or from an ephemeral variable.
