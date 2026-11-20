# Terraform Provider: conative

A Terraform provider for managing resources that the major cloud providers do
not cover, or do not cover well.

The first area is **Azure SQL Database**: managing Microsoft Entra principals
(managed identities, applications and groups) as contained database users, their
database role memberships, and their database- and schema-level permissions. The
provider authenticates with a Microsoft Entra access token that you supply, so it
works with whatever identity your Terraform run already uses.

> **Status:** early development. Nothing is released yet, and the interface may
> change without notice.

## License

[MIT](LICENSE)
