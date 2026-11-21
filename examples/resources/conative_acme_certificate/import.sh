# Import by the versionless Key Vault certificate ID. This also adopts a certificate that
# was issued elsewhere or imported into Key Vault from a PFX file.
terraform import conative_acme_certificate.example https://example.vault.azure.net/certificates/example-com
