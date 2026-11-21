# Contributing

Thank you for helping. This document explains how to build, test and change the provider.

## Prerequisites

- Go, at the version in `go.mod` (the `toolchain` line downloads it if needed).
- Terraform 1.10 or later on your `PATH`. The tests that supply the access token through an
  ephemeral variable need it.
- Docker, for the acceptance tests.

## Building and checking

```shell
make build     # go build ./...
make fmt       # gofmt
make lint      # golangci-lint run
make test      # unit tests; no Docker needed
```

Unit tests run on any platform.

## Acceptance tests

```shell
make testacc   # TF_ACC=1 go test ./internal/provider/... -run TestAcc -timeout 30m -v
```

The acceptance tests run the provider as users run it, configured with an access token, against SQL
Server in a container. They need Docker, Terraform and a Linux environment (Linux, WSL or a dev
container). They need no cloud account and no secret, so they also run for pull requests from forks.

How they work:

- The test run starts `mcr.microsoft.com/mssql/server:2022-latest` (set `ACC_MSSQL_IMAGE` to use another
  image), waits until it accepts connections, and removes the container when the run ends.
- SQL Server in a container does not accept a Microsoft Entra access token, so a small sign-in proxy in
  `internal/acctest/tdsproxy` stands in front of it. It accepts the driver's token login, compares the
  token with the one generated for the run, signs in to the container with SQL authentication, and then
  passes all traffic through unchanged. It knows nothing about Entra users and emulates nothing else.
- The proxy presents a certificate from a certificate authority generated for the run. The tests make Go
  trust it by pointing `SSL_CERT_FILE` at the authority before anything uses TLS. Go honours that variable
  on Linux but not on macOS or Windows, which is why the acceptance tests need Linux. The provider itself
  has no setting that weakens certificate validation.
- A container cannot hold users created from an Entra ID, so tests use users created `WITHOUT LOGIN`
  as stand-ins for reads, imports, role memberships and permissions. The exact statement that creates an
  Entra user is covered by unit tests.

### ACME tests

The ACME acceptance tests need no Docker, no network and no account. They run the provider against fakes
that live in the repository under `internal/acctest`:

- `acmefake`: an ACME certificate authority (RFC 8555) with accounts (including lookup by key), orders,
  authorizations, DNS-01 validation, finalize with a signing request, issuance from a test authority and
  revocation. It validates a challenge by reading the TXT records from the shared DNS store.
- `keyvaultfake`: Key Vault keys (sign for RSA and EC) and certificates (create with the issuer `Unknown`,
  pending request with a signing request, merge, versions, delete).
- `azurednsfake` and `cloudflarefake`: the TXT record parts of the Azure DNS Resource Manager API and the
  Cloudflare API. Both write to the same `dnsstore` that the certificate authority reads.

SQL Server is started only when an Azure SQL acceptance test first needs it, so running only the ACME
tests (`-run 'TestAccACME|TestAccProvider_acme'`) never starts a container. The provider accepts only Key
Vault names under `vault.azure.net`, so the fake vault is addressed as `fake.vault.azure.net` and the
tests' HTTP client maps that name to the loopback listener.

Every fake serves HTTPS on a loopback port with a certificate from a certificate authority generated for the
run, trusted through `SSL_CERT_FILE` like the SQL proxy above, so they also need Linux. The provider has no
setting that weakens certificate validation; the tests inject the base URLs and the DNS propagation check
instead. Each fake keeps a journal of the requests it received, which the tests use to show that a plan or a
state-only update wrote nothing, and the tests search the state, saved plans and trace logs for every token
and private key the fakes hold.

If a run is killed, a container named `conative-acc-*` can be left behind; remove it with
`docker rm -f`.

## Documentation

The files under `docs/` are generated from the schema descriptions, `examples/` and `templates/`.
After changing any of them, run

```shell
make docs
```

and commit the result. CI fails if the committed documentation differs from what the generator
produces.

## Changes

- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages and pull request
  titles, for example `feat(azuresql): add ...` or `fix: ...`.
- Add an entry under `Unreleased` in `CHANGELOG.md` for every user-visible change. Mark an incompatible
  change as breaking.
- The public interface is the provider configuration, the names, attributes and semantics of resources
  and data sources, import ID formats and the state schema. Changing any of them is a breaking change.
- Keep decisions that a reader needs in the repository: in the code, in `docs/`, or in the pull request
  description.

## Releases

Maintainers cut a release by pushing a signed, annotated tag `vX.Y.Z` on `main`. The tag is the only place
the version is written. The release workflow builds the archives for every platform the Terraform Registry
supports with GoReleaser, signs the checksums file and publishes a GitHub release. Merging a pull request
releases nothing. To check the release configuration locally:

```shell
goreleaser check
goreleaser release --snapshot --clean --skip=sign,publish
```

## Dependencies

The provider depends on the Terraform plugin framework, the Microsoft SQL Server driver for Go,
`golang.org/x/crypto` and the standard library. `golang.org/x/crypto/acme` is the RFC 8555 client,
maintained by the Go project and BSD-licensed; only the `internal/acme/issuer` package imports it, and
`acme/autocert` must not be used. The Key Vault, Azure DNS and Cloudflare clients are plain HTTP on purpose,
to avoid pulling in the Azure and Cloudflare SDKs. Justify every new dependency in the pull request. Nothing that signs in to Microsoft Entra
ID may be added: the caller supplies the access token, and CI fails if such a package appears in the build.

## Code guidelines

- Decisions are pure functions in `internal/azuresql`: building statements, deriving security identifiers,
  parsing import IDs, validating names, roles and permissions, and mapping catalog rows. They do no
  network, database, file-system or clock access. Lint rules enforce it.
- Decisions for the ACME resources (name routing, record names, IDs, key types, the renewal decision,
  inspecting certificates) are pure functions in `internal/acme`, the second pure core; the clients for
  Key Vault, Azure DNS, Cloudflare and the DNS check live in subpackages and make no decisions.
- Talking to the database lives in `internal/azuresql/sqlclient` and makes no decisions.
- Identifiers in T-SQL are always bracket-quoted with `]` doubled, values are always passed as parameters,
  and role and permission names are checked against allowlists before a statement is built. Add a test
  with hostile names for every new statement.
- Report every failure as an error. A failure to connect, sign in or read must never be treated as "not
  found".
