data "conative_azuresql_database_user" "app" {
  database = "orders"
  name     = "orders-app"
}

output "app_sid" {
  value = data.conative_azuresql_database_user.app.sid
}
