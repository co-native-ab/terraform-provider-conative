package azuresql

import "time"

// transientErrors are the SQL Server error numbers Microsoft documents as transient
// connection faults for Azure SQL Database ("Troubleshoot common connection issues",
// "List of transient fault error codes").
var transientErrors = map[int32]bool{
	615:   true, // could not find database ID (database being reconfigured)
	926:   true, // database cannot be opened, marked SUSPECT or recovering
	4060:  true, // cannot open database requested by the login
	4221:  true, // login to read-secondary failed, secondary not yet in sync
	40197: true, // service error while processing the request
	40501: true, // service is busy
	40613: true, // database not currently available
	49918: true, // not enough resources to process the request
	49919: true, // too many create or update operations in progress
	49920: true, // service is busy processing multiple requests
}

// IsTransient reports whether a SQL Server error number is on the documented list of
// transient connection errors.
func IsTransient(number int32) bool { return transientErrors[number] }

const (
	firstRetryDelay = 5 * time.Second
	maxRetryDelay   = 60 * time.Second
)

// NextDelay returns how long to wait before retry number attempt (0 for the first
// retry) and whether to retry at all. Delays start at five seconds and double up to a
// cap of one minute. It reports false when waiting would exceed budget given the
// time already elapsed, so the total time spent never passes the budget by a wait.
func NextDelay(attempt int, elapsed, budget time.Duration) (time.Duration, bool) {
	delay := firstRetryDelay
	for i := 0; i < attempt && delay < maxRetryDelay; i++ {
		delay *= 2
	}
	delay = min(delay, maxRetryDelay)
	if elapsed+delay > budget {
		return 0, false
	}
	return delay, true
}
