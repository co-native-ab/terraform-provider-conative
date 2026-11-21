terraform {
  required_providers {
    conative = {
      source = "co-native-ab/conative"
    }
  }
}

# A Microsoft Entra access token for https://database.windows.net/.default,
# obtained outside the provider. Marking the variable ephemeral keeps the token out
# of the plan and the state (Terraform 1.10 or later).
variable "sql_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

provider "conative" {
  azuresql = {
    server        = "example-server.database.windows.net"
    access_token  = var.sql_token
    retry_timeout = "2m" # optional
  }
}

# To manage a second server, add a provider alias.
provider "conative" {
  alias = "reporting"

  azuresql = {
    server       = "reporting-server.database.windows.net"
    access_token = var.sql_token
  }
}
