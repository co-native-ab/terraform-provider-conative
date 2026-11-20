# An Entra application (a service principal or a managed identity), by its
# application (client) ID.
resource "conative_azuresql_database_user" "orders_app" {
  database = "orders"
  name     = "orders-app"
  type     = "application"
  entra_id = "00000000-0000-0000-0000-000000000000"
}

# An Entra group, by its object ID.
resource "conative_azuresql_database_user" "operators" {
  database = "orders"
  name     = "orders-operators"
  type     = "group"
  entra_id = "00000000-0000-0000-0000-000000000000"
}
