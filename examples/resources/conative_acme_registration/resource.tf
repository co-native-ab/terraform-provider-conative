# The account key is an existing Key Vault key. Every request to the certificate
# authority is signed by Key Vault, so the private key never leaves it.
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
