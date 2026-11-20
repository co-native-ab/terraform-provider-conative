# Make a database user the owner of the database, for example an identity that
# runs schema migrations.
resource "conative_azuresql_database_role_member" "orders_app_owner" {
  database = "orders"
  role     = "db_owner"
  member   = conative_azuresql_database_user.orders_app.name
}
