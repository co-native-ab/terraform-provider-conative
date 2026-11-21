---
page_title: "Issuing ACME certificates into Azure Key Vault"
subcategory: ""
description: |-
  How the ACME resources create certificates in Key Vault with DNS-01 challenges, renew them, handle failures and import existing certificates.
---

# Issuing ACME certificates into Azure Key Vault

This guide explains how `conative_acme_registration` and `conative_acme_certificate` behave, and why. The
resources talk to any certificate authority that implements ACME (RFC 8555), such as Let's Encrypt, prove
control of the names with DNS-01 challenges in Azure DNS or Cloudflare, and keep the issued certificate in
Azure Key Vault.

## What it does

1. **The account key lives in Key Vault.** You create an RSA or EC key in Key Vault, for example with
   `azurerm_key_vault_key`. `conative_acme_registration` uses it as the ACME account key. Every request to
   the certificate authority is signed by Key Vault's sign operation, so the private key never leaves Key
   Vault. Whether the key is exportable is your choice; the provider does not need it either way. If the
   authority already has an account for the key, that account is used; otherwise one is created, which
   agrees to the authority's terms of service.
2. **The certificate's key is generated in Key Vault.** For an order, the provider asks Key Vault to create a
   certificate with the issuer `Unknown`. Key Vault generates a new, exportable private key and a signing
   request, and waits for a certificate. The provider passes the request to the certificate authority,
   answers the DNS-01 challenges, finalizes the order with the signing request, and merges the issued chain
   back into the same Key Vault certificate. The private key is never in Terraform state, in the plan or in
   a log.
3. **State holds only public values:** the certificate IDs, the current version, the certificate in PEM,
   its expiry and its thumbprint.

The resource owns the Key Vault certificate. You do not also declare it with `azurerm_key_vault_certificate`.

## Supplying the tokens

The provider contains no sign-in code. It takes two Microsoft Entra access tokens in the `acme` settings:

- `key_vault_access_token` for `https://vault.azure.net/.default`
- `resource_manager_access_token` for `https://management.azure.com/.default`, optional: needed only when an
  order runs for names that an `azure_dns` block serves

The recommended source is the [`co-native-ab/azidentity`](https://registry.terraform.io/providers/co-native-ab/azidentity)
provider with one ephemeral resource per scope:

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

The `acme` settings are required only when an ACME resource is used. A configuration that uses only other
resources of this provider needs no `acme` block.

### The DNS propagation check

After it has written the challenge records and before it asks the certificate authority to validate them,
the provider waits until the records are visible. Two more `acme` settings control this:

- `dns_propagation_check` (default `true`)
- `dns_propagation_timeout`, a Go duration from `10s` to `30m` (default `2m`)

The check waits five seconds before the first poll, because a record written a moment ago is rarely served
yet. It then looks up the name servers of the zone and sends each of them a TXT query directly, over UDP
(and over TCP when the answer is truncated) on port 53, without asking for recursion, every five seconds
until the timeout. It trusts only answers that carry the authoritative-answer flag.

**The check needs direct UDP and TCP access to port 53 of the zone's name servers.** It does not work behind
a DNS-intercepting proxy or a secure web gateway that answers DNS queries itself, because such a proxy
answers for the name servers, often from a cache, and the answer does not carry the flag. The provider
recognises this: it logs a warning, ignores the answer (a missing record in it proves nothing, and a record
in it is not proof either) and keeps polling until the timeout, and the error then names the setting. A
proxy may also refuse the query instead of answering it: an answer of SERVFAIL or REFUSED without the flag
counts as an answer that is not trusted. When, in the first round of polling, every name server of a zone
answers SERVFAIL or REFUSED without the flag, the check fails at once, without waiting for the timeout, and
the error names the setting. (A SERVFAIL that does carry the flag is a failure of the name server itself and
is retried until the timeout, like a network error.) On such a network, and wherever port 53 is blocked, turn
the check off:

```terraform
provider "conative" {
  acme = {
    # ...
    dns_propagation_check = false
  }
}
```

With the check off the provider still waits five seconds after it has written the records and then lets the
certificate authority validate them, which is where the validation happens anyway. A record that is not
served yet then fails the validation and therefore the apply, which can be repeated.

## A registration and a certificate

The following creates an account, and one certificate with a wildcard and the apex name answered through
Cloudflare and another wildcard answered through Azure DNS, all in one order:

```terraform
resource "azurerm_key_vault_key" "acme_account" {
  name         = "acme-account"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "EC"
  curve        = "P-256"
  key_opts     = ["sign", "verify"]
}

resource "conative_acme_registration" "letsencrypt" {
  server_url     = "https://acme-v02.api.letsencrypt.org/directory"
  account_key_id = azurerm_key_vault_key.acme_account.id
  email          = "certificates@example.com"
}

ephemeral "azurerm_key_vault_secret" "cloudflare_token" {
  name         = "cloudflare-dns-token"
  key_vault_id = azurerm_key_vault.example.id
}

resource "conative_acme_certificate" "example" {
  registration_id  = conative_acme_registration.letsencrypt.id
  key_vault_url    = azurerm_key_vault.example.vault_uri
  certificate_name = "example-com"

  common_name = "example.com"
  subject_alternative_names = [
    "*.example.com",
    "*.apps.example.net",
  ]

  key_type           = "RSA4096"
  min_days_remaining = 30
  revoke_on_destroy  = true

  cloudflare {
    zone          = "example.com"
    match_domains = ["example.com"]
    api_token     = ephemeral.azurerm_key_vault_secret.cloudflare_token.value
  }

  azure_dns {
    subscription_id = "00000000-0000-0000-0000-000000000000"
    resource_group  = "dns"
    zone_name       = "example.net"
    match_domains   = ["apps.example.net"]
  }
}
```

### The Cloudflare token

`cloudflare.api_token` is a write-only argument. Terraform passes it to the provider for the run and never
stores it in the plan or the state, so it needs Terraform 1.11 or later, and using a different token in
another run causes no difference in the plan. Feed it from an ephemeral value, as above from an ephemeral
`azurerm_key_vault_secret`, or from an ephemeral variable.

The attribute is optional because it is needed only when an order actually runs:

- A plan or refresh in which no order is due succeeds with the token unset (null). Nothing in such a run
  calls Cloudflare.
- When an order is planned (a new certificate, a renewal, a change of names, key type or certificate
  authority, or a version added outside Terraform) and a block that serves a name of the order has no token,
  the plan fails with an error that names the block and `api_token`. If the token is not known until apply,
  the same check runs again at apply.
- During a plan the provider uses the token only to look up the zone, which is a read. A token that can read
  but not edit therefore works for plans, including a plan that shows a renewal.

The same applies to `acme.resource_manager_access_token` and `azure_dns` blocks: without the token, plans in
which nothing is ordered succeed, and a planned order fails with an error that names the setting and the
block.

### Read-only tokens for plans, write tokens for apply

You can run plans with credentials that cannot change anything and keep the write credentials for apply
runs. For Cloudflare, pass a read-only token (*Zone: Zone: Read* and *Zone: DNS: Read*) as `api_token` in
plan runs and the token that can edit DNS in apply runs. Because `api_token` is write-only, switching tokens
between the plan and the apply causes no diff. For example, keep both tokens as ephemeral secrets (or as
ephemeral variables supplied by the pipeline) and select one per run:

```terraform
variable "dns_write" {
  type    = bool
  default = false # true only in apply runs
}

ephemeral "azurerm_key_vault_secret" "cloudflare_read" {
  name         = "cloudflare-dns-read-token"
  key_vault_id = azurerm_key_vault.example.id
}

ephemeral "azurerm_key_vault_secret" "cloudflare_write" {
  name         = "cloudflare-dns-token"
  key_vault_id = azurerm_key_vault.example.id
}

# In the certificate's cloudflare block:
#   api_token = var.dns_write ? ephemeral.azurerm_key_vault_secret.cloudflare_write.value : ephemeral.azurerm_key_vault_secret.cloudflare_read.value
```

The same works for the Azure side (use identities with read-only and with write rights to produce the two
tokens) and for Key Vault, see [Permissions](#permissions). If an apply runs with a token that cannot write,
it fails at the first write with an error naming the block and zone (for Cloudflare it adds that the token
needs DNS Edit permission on the zone and that a read-only token can plan but not apply), removes what it
created in Key Vault and in DNS, and leaves the state unchanged. The order stays pending at the certificate
authority, which expires it.

An apply with a read-only token is not guaranteed to fail. The provider writes a challenge record only for a
name whose authorization is not valid yet. A certificate authority such as Let's Encrypt reuses a valid
authorization for a while, so a renewal soon after an issue needs no record at all and succeeds with a token
that cannot write. Do not rely on a read-only token to make an apply a no-op.

### Which DNS zone answers which name

Every name of the certificate (the common name and each subject alternative name) must be answered by exactly
one `azure_dns` or `cloudflare` block. A name belongs to a block when it equals one of the block's
`match_domains` entries or ends in `.` followed by an entry; a leading `*.` is ignored. If entries of several
blocks match, the longest entry wins. In the example, `example.com` and `*.example.com` go to Cloudflare, and
`*.apps.example.net` goes to Azure DNS. A name that no block covers is rejected at plan time.

Challenge records are removed again after validation, also when the order fails.

Several certificates may share a challenge record name, for example `example.com` and `*.example.com`
(`_acme-challenge.example.com`), and Terraform then orders them at the same time. This works: writes to one
Azure DNS record set that lose a race are repeated after a short, growing pause (up to ten times), a record
in Cloudflare that an order running at the same time has created identically is used as it is and left to
the order that created it, and an authorization that another order has validated meanwhile is not validated
again.

## Renewal and consumers

Set `min_days_remaining` (default `30`). When the current time passes the expiry minus that many days, the
plan shows an **in-place update**. Applying it runs a new order and adds a **new version** to the same Key
Vault certificate, with a new key generated in Key Vault. A new version is also planned when the current
version in Key Vault was changed outside Terraform.

Services that reference the versionless identifiers pick up the new version without any change of their own:

- `id`: `https://<vault>/certificates/<name>`
- `secret_id`: `https://<vault>/secrets/<name>`, the form that services such as Azure Front Door and Azure
  Container Apps use to load a certificate

Do not use the versioned form (`version`) for consumers that should follow renewals.

### Forcing a renewal

- Set `min_days_remaining` higher than the days the certificate has left. The next plan shows an in-place
  update that orders a new version. The new certificate may again be inside the window, in which case every
  plan orders again, so set the value back afterwards.
- Change `common_name`, `subject_alternative_names` or `key_type`: a different set of names or another key
  type orders a new version in place.
- Change `registration_id` to a registration at another certificate authority URL.
- `terraform apply -replace=conative_acme_certificate.example` destroys and creates the resource. The destroy
  revokes the certificate when `revoke_on_destroy` is `true` and soft-deletes the Key Vault certificate, and
  creating a certificate under a soft-deleted name fails until it is purged or recovered (see
  [Destroying](#destroying)). Prefer the in-place ways above unless you want a new Key Vault certificate.

Renewal needs a plan and apply to happen, for example in a scheduled pipeline run; the provider has no
background process.

### How consumers pick up a new version

A new version in Key Vault does not reach every consumer at once; the delay is the consumer's, not the
provider's, and it is set by each service. Two examples:

- Azure Container Apps environments that reference the certificate through its versionless Key Vault ID
  picked up a new version within minutes in practice. Microsoft documents that it
  [can take up to 12 hours](https://learn.microsoft.com/azure/container-apps/key-vault-certificates-manage#rotate-certificates).
- Azure Front Door with the certificate version set to "Latest" rotates on its own schedule, which can take
  hours or longer. Microsoft documents that a customer certificate
  [rotates within 3-4 days](https://learn.microsoft.com/azure/frontdoor/end-to-end-tls#certificate-autorotation)
  of a new version.

Other services differ again, so check how yours follows a Key Vault certificate. Renewing with enough margin,
that is, a `min_days_remaining` well above the slowest consumer's delay, covers it: the old version stays
valid while the new one propagates.

## A plan never writes

Plan and refresh only read, and they need only read rights:

- `conative_acme_registration` keeps the account URL from state. Refresh makes **no signed request** to the
  certificate authority and no Key Vault sign call; it reads the key's metadata from Key Vault to confirm that
  the key still exists. Only a Key Vault answer of "not found" for the key removes the registration from the
  state; any other failure is an error and the state is kept.
- `conative_acme_certificate` refresh, import and plan read the certificate's public data from Key Vault
  (the certificate and its versions). They never read a secret, never sign, never call the certificate
  authority, never touch a pending operation, and never write to Key Vault, DNS or the authority. Key Vault
  authorises even a read of the pending-operation endpoint (`/certificates/<name>/pending`) as the write
  action `certificates/create/action`, so the provider uses that endpoint only when an order runs.
- A plan in which nothing is ordered needs neither the Cloudflare token nor the Resource Manager token.

Importing a registration is an explicit action that looks up the account and therefore signs once. Creating
a registration, changing its `email`, ordering, renewing and destroying a certificate sign and write; they
happen in apply.

## Authority changes

`registration_id` of a certificate normally refers to the registration you already use. When it changes from
a registration at one certificate authority URL to a registration at a different `server_url` (for example
from a staging directory to the production directory), the plan shows an in-place update that orders a new
certificate, because a certificate from one authority is not valid for the other. Changing it to another
account at the same `server_url`, or setting it for the first time after an import, only updates the state
and orders nothing.

If the registration is created or replaced in the same run (for example its `account_key_id` changes, so that
`registration_id` is not known until apply), the plan cannot tell yet whether the authority changes. It shows
an in-place update with the attributes of a new version (`version`, `issued_version`, `thumbprint`,
`not_after` and `certificate_pem`) as "known after apply". During apply, once the registration exists,
Terraform plans the certificate again with the known `registration_id`, and the provider decides then by the
same rules as for any other update: it orders if the new registration's `server_url` differs from that of
the registration in the state, if the names or the key type changed, or if a renewal is due (see
[Renewal and consumers](#renewal-and-consumers)). Otherwise nothing is sent to Key Vault, DNS or the
authority: the apply records the new `registration_id` and the attributes keep the values of the current
version. A certificate that was imported and has had no registration recorded yet is never ordered because of
the registration alone. A plan that leaves the decision to apply reads neither the certificate's versions nor
the DNS zones; the plan during apply does, if it orders.

## Some authorities do not report or keep what you send

- Some authorities, Let's Encrypt among them, do not store or report an account's contact address. The
  provider therefore never reads `email` back: Terraform keeps the configured value, an unchanged `email`
  causes no request, and only a change of `email` sends an update.
- Some authorities leave the common name out of the certificate they issue (Let's Encrypt does for names of
  65 characters or more, and some profiles never include one). `common_name` can be at most 64 characters.
  When the issued certificate has no common name but contains the configured one among its DNS names, the
  provider keeps the configured common name and the plan stays empty.

## Failures and retries

An apply that fails part way leaves nothing half-done:

- The challenge records the apply wrote are removed again, and the pending request in Key Vault is cancelled.
  If the removal of a record fails, the error names the records that remain.
- A failed create does not save the resource, and a failed update leaves the state unchanged, so running
  apply again is the retry.
- A certificate that has been issued by the authority but whose merge into Key Vault failed is not revoked;
  its key is gone with the cancelled request, and the next apply orders a new one.
- At apply, before ordering, the provider looks at the pending operation that Key Vault keeps for the
  certificate. A plan never reads it, so a plan does not fail because of it. Key Vault keeps the record after
  an operation has finished, so only an operation that is **in progress** matters: one with the issuer
  `Unknown` left by an earlier failed run is cancelled, and one in progress for another issuer makes the
  apply fail, naming the issuer and writing nothing, until it finishes or you cancel it in Key Vault; then
  apply again. A completed, failed or cancelled operation of any issuer, for example the record
  `az keyvault certificate create` leaves for the issuer `Self`, never blocks an apply (the apply deletes
  the finished record first). A version that was created that way is just a version added outside
  Terraform: the next plan renews it in place.
- **A failed first order keeps the Key Vault certificate.** The provider creates the certificate in Key
  Vault before the order starts. When the order of a new resource fails, the pending request is cancelled
  but the certificate itself stays, without an issued version, and the error says so. This is deliberate:
  deleting it would put the name into Key Vault's soft-delete state, which blocks creating the name again
  until it is purged or the retention period ends, and purging is often forbidden. The next apply of the
  same configuration reuses the certificate and issues the first version. If you abandon the
  configuration, remove the certificate yourself: delete it in Key Vault and, where the vault allows it,
  purge it (or recover it if you want to use the name again).
- When the certificate authority no longer has an account for the registration's key (it was deleted or
  deactivated there), an order fails with an error that says so before anything is created in Key Vault.
  Recreate the account with `terraform apply -replace=conative_acme_registration.example` (use the address
  of your registration), then apply again.
- Creating a certificate under the name of a soft-deleted Key Vault certificate fails, and the error
  suggests recovering or purging the deleted certificate.

The provider waits, by default for at most two minutes, until the challenge records are visible on the zone's
authoritative name servers before it asks the authority to validate. Apply fails with a clear error if they
do not appear in time. See [The DNS propagation check](#the-dns-propagation-check) for the settings and for
networks where the check cannot work.

At the DEBUG log level the provider logs each step of an order: which name servers were queried and
whether they answered authoritatively, when the records became visible and how long that took, the status
of each authorization (reused, pending, valid), the finalization of the order and the merge, and whether a
revocation was done or skipped and why. It never logs a token, a key or the value of a TXT record.

Authorization errors are errors: if a token lacks a permission, the apply fails and says which service
refused.

## Destroying

With `revoke_on_destroy = true`, destroy first revokes the certificate at the authority with the account key
of the registration, and then deletes the certificate from Key Vault. With `false`, it only deletes.

Exactly which certificate is revoked: the version this resource **issued last** (`issued_version`), which is
not necessarily the current version in Key Vault, for example when another version was added outside
Terraform. It is revoked with the account that ordered it. The provider remembers that account (in private
state), so a later change of `registration_id` to another account at the same authority does not matter: an
authority lets only the account that issued a certificate, or one with valid authorizations for all of its
names, revoke it. Revocation is skipped (and destroy continues with the deletion) when

- that version has expired or no longer exists in Key Vault,
- the key of the account that ordered it no longer exists in Key Vault, so nobody can sign the request;
  destroy then warns,
- the authority reports that the certificate is already revoked, which counts as revoked, or
- the certificate was imported and this resource has not renewed it since, because it was issued elsewhere;
  destroy then warns.

Revoking signs a request with the account key, so the identity behind the Key Vault token needs the sign
permission at destroy. If revocation fails, destroy fails before anything is deleted.

Key Vault soft-deletes the certificate: its name stays reserved until it is purged or the soft-delete
retention period has passed, and creating a certificate with that name fails in the meantime. Recover or
purge the deleted certificate first. Destroying `conative_acme_registration` removes it from state only; the
account stays registered with the authority.

## Permissions

The identities behind the tokens need the permissions below. The provider neither checks nor grants them, and
it never reads a secret: no operation needs a secrets permission. The built-in roles named are examples; any
role or access policy that grants the data actions will do. Check the current role definitions in the Azure
documentation.

Key Vault data actions (Azure RBAC) for each operation:

| Operation | Key Vault data actions | Other services |
| --- | --- | --- |
| Refresh and plan of a registration | `Microsoft.KeyVault/vaults/keys/read` on the account key | none |
| Refresh, import and plan of a certificate | `Microsoft.KeyVault/vaults/certificates/read` (get, list versions) | none |
| Plan when an order is due | `certificates/read` only, as above | Azure DNS: `Microsoft.Network/dnsZones/read` with the Resource Manager token, for each `azure_dns` block that serves a name of the order; Cloudflare: *Zone: Zone: Read* for each `cloudflare` block that serves one. The plan only reads, and fails with a clear error if it cannot read the zone. |
| Create a registration, change its `email`, import a registration | `keys/read` and `Microsoft.KeyVault/vaults/keys/sign/action` on the account key | the certificate authority |
| Order or renew a certificate | `certificates/read`, `certificates/create/action` (creating the pending version, reading the pending operation and merging the issued chain), `certificates/update/action` and `certificates/delete` (deleting a pending operation: a finished record or a cancelled leftover; see below), and `keys/read` and `keys/sign/action` on the account key | Azure DNS: `Microsoft.Network/dnsZones/read`, `Microsoft.Network/dnsZones/TXT/read`, `.../TXT/write`, `.../TXT/delete`; Cloudflare: *Zone: Zone: Read* and *Zone: DNS: Edit* |
| Destroy with `revoke_on_destroy = true` | `certificates/read`, `certificates/delete`, `keys/sign/action` | the certificate authority |
| Destroy with `revoke_on_destroy = false` | `certificates/delete` | none |

The pending-operation endpoint (`/certificates/<name>/pending`) needs `certificates/create/action` even to
read it, although Microsoft's REST reference names the get permission for
[reading a pending operation](https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificate-operation/get-certificate-operation),
so the provider uses it only at apply; plan and refresh never call it. For
[deleting a pending operation](https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/delete-certificate-operation/delete-certificate-operation)
the REST reference names the update permission, but which data action Key Vault checks is not documented. An
order therefore lists every candidate, `certificates/create/action`, `certificates/update/action` and
`certificates/delete`, so that it works whichever Key Vault asks for. An order never deletes the Key Vault
certificate itself. *Key Vault Certificates Officer* grants all of them.

For example, *Key Vault Reader* (metadata only) for plans, or for apply *Key Vault Certificates Officer*,
which covers every certificate data action above, and *Key Vault Crypto User* for `keys/read` and
`keys/sign/action` on the account key. Rights for refresh and plan are a strict subset of those for apply, so
a pipeline can run plans with a read-only identity and applies with a writing one. The merge needs only
`certificates/create/action`; it does not need the `import` data action. The certificate's own key needs no
key permission. With access policies instead of RBAC, the equivalent are the certificate permissions `get`,
`list`, `create`, `update` and `delete`, and the key permissions `get` and `sign`. A plan in which an order is
due also needs, for the DNS side, only read access to the zones, as the table shows.

Azure DNS: for each `azure_dns` block, read the zone and read, write and delete TXT record sets, for example
with the built-in *DNS Zone Contributor* role (broader than needed) or a custom role limited to the actions
above. Needed only when an order runs. The token for `https://management.azure.com/.default` is used. Only the
Azure public cloud is supported.

Cloudflare: for each `cloudflare` block an API token with *Zone: Zone: Read* and *Zone: DNS: Edit* on the
zone for orders. A plan only reads the zone, so a token with read rights suffices there.

## Account key types

The account key of a registration can be RSA with 2048 bits or more (Key Vault offers 2048, 3072 and 4096)
or EC on P-256, P-384 or P-521; the provider signs with RS256, ES256, ES384 and ES512 respectively. The key
must permit the `sign` operation. It does not matter whether the key is exportable or not. Some authorities
accept fewer key types: Let's Encrypt, for example, does not accept P-521 account keys. EC curves other than
those named (for example P-256K) and RSA keys below 2048 bits are refused.

## Importing an existing certificate

Import IDs:

- `conative_acme_registration`: `<server_url>|<account_key_id>`, quoted because of the pipe, for example
  `'https://acme-v02.api.letsencrypt.org/directory|https://example.vault.azure.net/keys/acme-account/0123456789abcdef'`.
  Importing looks up the account for the key at the authority, which signs a request. The email is not read
  back (many authorities do not report it); an `email` in the configuration is set by the first apply,
  which sends one account update.
- `conative_acme_certificate`: the versionless Key Vault ID, `https://<vault>.vault.azure.net/certificates/<name>`.

```shell
terraform import conative_acme_certificate.example https://example.vault.azure.net/certificates/example-com
```

Any Key Vault certificate can be imported, including one issued by another authority or imported from a PFX
file. Import reads only the current version and changes nothing.

An `import` block works in the same run that creates the registration the certificate references: one plan
and one apply are enough. The plan shows the import and an in-place update whose version attributes are
"known after apply", because `registration_id` is not known yet. During apply the provider decides with the
known value, as described in [Authority changes](#authority-changes): unless the certificate is due or its
names or key type differ from the configuration, it writes nothing to Key Vault and only records the
arguments in the state, and the next plan is empty. If it is due or differs, the apply orders a new version.

1. Import records the names, key type, expiry and thumbprint from the certificate itself, and sets
   `min_days_remaining` to `30`.
2. Key Vault cannot report the registration, `revoke_on_destroy`, the DNS blocks or a `min_days_remaining`
   other than `30`. Terraform plans a change from "not set" to the configured value for such an argument,
   and a provider cannot turn that into an empty plan, so the first plan after the import shows **one
   in-place update**. **The first apply after an import records these arguments in state and sends no
   request:** it contacts neither the authority, nor Key Vault, nor any DNS zone. The plan after that is
   empty. How the vault URL is written (a trailing `/`, the case of the host) never causes a change.
3. The plan after that is empty, until the certificate is within `min_days_remaining` days of expiry or you
   change the names or the key type.
4. The first order replaces the certificate policy with the resource's own (issuer `Unknown`, exportable key,
   your key type and names, no automatic actions) and adds a new version with a key generated in Key Vault.
   The versionless IDs stay the same. The policy's content type becomes `application/x-pkcs12`: a
   certificate that was imported with a PEM secret becomes a PKCS #12 secret from the first order on, which
   consumers that read the secret must be able to handle. Services such as Azure Front Door and Azure
   Container Apps do.
5. A certificate that was imported and not yet renewed by this resource is never revoked on destroy: it was
   not issued by this resource.
6. A certificate without a subject common name can be imported. `common_name` is then recorded as null and
   every DNS name of the certificate as an alternative name. If the configured `common_name` and
   `subject_alternative_names` together make up exactly those names, the first apply is the state-only
   update of step 2; the plan after that is empty.

See "Importing an existing certificate" on the [certificate resource page](../resources/acme_certificate)
for the exact rules, including the certificates that cannot be imported.

## Let's Encrypt notes

- Use the staging directory `https://acme-staging-v02.api.letsencrypt.org/directory` while you try a
  configuration; the production directory has rate limits.
- Let's Encrypt does not accept the `P521` key type for certificates or for account keys, and does not report
  an account's contact address or include a long common name in a certificate.
- Wildcard names need DNS-01, which is the only challenge this provider supports.

## Limitations

- Only DNS-01 validation, through Azure DNS (public cloud) and Cloudflare.
- No account deactivation, key rollover or external account binding.
- The certificate's key is always generated in Key Vault, exportable, and new for every version; an existing
  key cannot be reused.
- Certificate profiles and preferred chains are not supported.
- A saved plan (`terraform plan -out`) that orders nothing fails at apply if the certificate has entered its
  renewal window in the meantime: Terraform reports that the provider produced an inconsistent final plan, and
  nothing is changed. Plan again; the new plan shows the renewal.
