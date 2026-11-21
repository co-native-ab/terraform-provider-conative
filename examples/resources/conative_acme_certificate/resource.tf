# The Cloudflare API token is write-only: it is never stored in the plan or the state.
# Read it from an ephemeral resource.
ephemeral "azurerm_key_vault_secret" "cloudflare_token" {
  name         = "cloudflare-dns-token"
  key_vault_id = azurerm_key_vault.example.id
}

# One order for names in two DNS providers. Each name is answered by the block whose
# match_domains entry it matches.
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
