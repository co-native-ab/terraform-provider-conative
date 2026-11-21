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
