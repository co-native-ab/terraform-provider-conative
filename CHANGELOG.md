# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, an incompatible change
bumps the minor version.

## Unreleased

### Added

- Provider settings `acme` with `key_vault_access_token` and `resource_manager_access_token` (both
  sensitive; never stored or logged), `dns_propagation_check` (default `true`) and
  `dns_propagation_timeout` (a duration from `10s` to `30m`, default `2m`). The settings are required
  only when an ACME resource is used, and the Resource Manager token only when an order runs for names
  that an `azure_dns` block serves.
- Resource `conative_acme_registration`: an account with an ACME certificate authority whose key is a
  Key Vault key; every request is signed by Key Vault. Importable as `server_url|account_key_id`.
  Refreshing and planning never sign.
- Resource `conative_acme_certificate`: a certificate in Key Vault issued through DNS-01 challenges in
  Azure DNS and Cloudflare, in one order if needed. The private key is generated in Key Vault and never
  stored in the state. Renewal updates the resource in place and adds a new version to the same Key
  Vault certificate.
  - `cloudflare.api_token` is a write-only argument and needs Terraform 1.11 or later. It is optional:
    it is needed only when an order runs, and a plan in which an order is due without it fails with an
    error that names the block. A read-only token can plan but not apply.
  - Refresh and plan only read, with read-only rights in Key Vault, and never sign. A plan in which an
    order is due also reads the DNS zones.
  - A changed `registration_id` that points at another certificate authority URL orders a new
    certificate; another account at the same URL only updates the state.
  - Importable by the versionless Key Vault certificate ID, including a certificate issued elsewhere
    and one without a subject common name. The first apply after an import records the arguments that
    Key Vault cannot report and sends no request; the plan after that is empty. The first renewal moves
    the certificate to a key generated in Key Vault.
  - A different spelling of `key_vault_url` (a trailing `/`, the case of the host) is never a change.
  - The propagation check waits five seconds, then queries the zone's authoritative name servers
    directly over UDP (TCP when truncated) without recursion, trusts only answers with the
    authoritative-answer flag, and polls until `dns_propagation_timeout`. It needs direct access to
    port 53 and does not work behind a DNS-intercepting proxy; turn it off with
    `dns_propagation_check = false`, which still waits five seconds before the authority validates.
  - Only a pending operation that is in progress blocks an order. The record Key Vault keeps after an
    operation has finished (for example from the `Self` issuer) is ignored or deleted, so such a
    certificate can be renewed in place.
  - Certificates whose names share a challenge record name can be ordered at the same time.
  - Destroy with `revoke_on_destroy = true` revokes with the account that ordered the certificate, also
    when `registration_id` has moved to another account at the authority since.
  - A failed first order keeps the Key Vault certificate, without an issued version, so that the next
    apply reuses it; the error explains how to remove it if you abandon the configuration.
  - DEBUG logs of each step of an order (name servers, authorizations, finalization, revocation), never
    with a secret or a TXT record value.
- The Key Vault URL, key IDs and import IDs of the ACME resources must name a vault under
  `vault.azure.net` with a vault name of 3 to 24 letters, digits or hyphens; access tokens are sent to no
  other host.
- A guide to the ACME resources, with the minimum Azure RBAC per operation, and documentation of the
  `acme` settings with the [`co-native-ab/azidentity`](https://registry.terraform.io/providers/co-native-ab/azidentity)
  provider as the token source.

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
