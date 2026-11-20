// Package azuresql is the pure core of the Azure SQL Database area: it builds
// T-SQL statements, derives security identifiers, formats and parses import IDs,
// validates names, roles and permissions, and maps catalog rows to resource state.
//
// Nothing in this package talks to a database, the network, the file system or the
// clock. Database access lives in the sqlclient subpackage.
package azuresql
