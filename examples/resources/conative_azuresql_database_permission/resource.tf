# Let an identity read the definitions of every object in the database.
resource "conative_azuresql_database_permission" "reader_view_definition" {
  database   = "orders"
  principal  = "plan-reader"
  state      = "GRANT"
  permission = "VIEW DEFINITION"
}

# Deny reading the data in one schema.
resource "conative_azuresql_database_permission" "deny_sales_select" {
  database   = "orders"
  principal  = "plan-reader"
  state      = "DENY"
  permission = "SELECT"
  schema     = "sales"
}
