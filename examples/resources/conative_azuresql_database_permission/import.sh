# The import ID is database/principal/STATE/PERMISSION for a database-level
# permission, and database/principal/STATE/PERMISSION/schema for a schema-level one.
terraform import conative_azuresql_database_permission.reader_view_definition 'orders/plan-reader/GRANT/VIEW DEFINITION'
terraform import conative_azuresql_database_permission.deny_sales_select 'orders/plan-reader/DENY/SELECT/sales'
