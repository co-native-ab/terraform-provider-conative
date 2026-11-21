terraform {
  required_providers {
    conative = {
      source = "co-native-ab/conative"
    }
  }
}

# A Microsoft Entra access token for https://database.windows.net/.default,
# obtained outside Terraform, for example with
#
#   export TF_VAR_sql_token="$(az account get-access-token \
#     --resource https://database.windows.net/ --query accessToken --output tsv)"
#
# Marking the variable ephemeral keeps the token out of the plan and the state
# (Terraform 1.10 or later).
variable "sql_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

provider "conative" {
  azuresql = {
    server       = "example-server.database.windows.net"
    access_token = var.sql_token
  }
}
