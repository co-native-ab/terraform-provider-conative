package acme

import (
	"fmt"
	"time"
)

// Bounds of the propagation timeout setting.
const (
	MinPropagationTimeout = 10 * time.Second
	MaxPropagationTimeout = 30 * time.Minute
	// DefaultPropagationTimeout is used when the setting is not set.
	DefaultPropagationTimeout = 2 * time.Minute
)

// ParsePropagationTimeout parses a Go duration such as "90s" or "5m" and checks it
// against the allowed range.
func ParsePropagationTimeout(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q must be a duration such as 90s or 5m", s)
	}
	if d < MinPropagationTimeout || d > MaxPropagationTimeout {
		return 0, fmt.Errorf("%q must be between %s and %s", s, MinPropagationTimeout, MaxPropagationTimeout)
	}
	return d, nil
}
