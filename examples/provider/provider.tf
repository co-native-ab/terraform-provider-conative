terraform {
  # Ephemeral resources need Terraform 1.10 or later.
  required_version = ">= 1.10.0"

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

# Obtain a Microsoft Entra access token for Azure SQL Database at the start of each run.
# The token is an ephemeral value, so it never reaches the plan or the state.
ephemeral "azidentity_default_credential" "sql" {
  scopes = ["https://database.windows.net/.default"]
}

provider "conative" {
  azuresql = {
    server        = "example-server.database.windows.net"
    access_token  = ephemeral.azidentity_default_credential.sql.access_token
    retry_timeout = "2m" # optional
  }
}

# To manage a second server, add a provider alias. The same token works for every
# server the identity has access to.
provider "conative" {
  alias = "reporting"

  azuresql = {
    server       = "reporting-server.database.windows.net"
    access_token = ephemeral.azidentity_default_credential.sql.access_token
  }
}
