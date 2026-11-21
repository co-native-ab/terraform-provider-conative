# List the external users of a database. An empty list is not an error, so this
# can be used to check whether something exists.
data "conative_azuresql_database_users" "external" {
  database       = "orders"
  principal_type = "EXTERNAL_USER" # optional
  # name         = "orders-app"    # optional, exact match
}

output "has_app" {
  value = length(data.conative_azuresql_database_users.external.users) > 0
}
