package azuresql

import (
	"testing"
	"time"
)

func TestIsTransient(t *testing.T) {
	t.Parallel()

	for _, n := range []int32{615, 926, 4060, 4221, 40197, 40501, 40613, 49918, 49919, 49920} {
		if !IsTransient(n) {
			t.Errorf("IsTransient(%d) = false, want true", n)
		}
	}
	for _, n := range []int32{0, 18456, 18487, 4064, 53, 10060, 208, 2714, 15023, -1} {
		if IsTransient(n) {
			t.Errorf("IsTransient(%d) = true, want false", n)
		}
	}
}

// collect follows the retry loop the way a caller does: every failed attempt is
// assumed to take no time, so only the waits count towards the budget.
func collect(budget time.Duration) []time.Duration {
	var delays []time.Duration
	var elapsed time.Duration
	for attempt := 0; attempt < 100; attempt++ {
		d, ok := NextDelay(attempt, elapsed, budget)
		if !ok {
			break
		}
		delays = append(delays, d)
		elapsed += d
	}
	return delays
}

func TestNextDelaySchedule(t *testing.T) {
	t.Parallel()

	s := time.Second
	got := collect(2 * time.Minute)
	want := []time.Duration{5 * s, 10 * s, 20 * s, 40 * s}
	if len(got) != len(want) {
		t.Fatalf("2m budget gives delays %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("delay %d = %v, want %v", i, got[i], want[i])
		}
	}

	long := collect(10 * time.Minute)
	if len(long) < 7 {
		t.Fatalf("10m budget gives only %v", long)
	}
	for i, d := range long[4:] {
		if d != 60*s {
			t.Errorf("delay %d = %v, want the 60s cap", i+4, d)
		}
	}
	var total time.Duration
	for _, d := range long {
		total += d
	}
	if total > 10*time.Minute {
		t.Errorf("total waits %v exceed the budget", total)
	}
}

func TestNextDelayBudget(t *testing.T) {
	t.Parallel()

	if _, ok := NextDelay(0, 0, 0); ok {
		t.Error("zero budget must not retry")
	}
	if _, ok := NextDelay(0, 0, 4*time.Second); ok {
		t.Error("budget below the first delay must not retry")
	}
	if d, ok := NextDelay(0, 0, 5*time.Second); !ok || d != 5*time.Second {
		t.Errorf("budget equal to the first delay: %v, %v", d, ok)
	}
	// Time spent in the attempts themselves counts.
	if _, ok := NextDelay(0, 118*time.Second, 2*time.Minute); ok {
		t.Error("elapsed time must count against the budget")
	}
	// Huge attempt numbers stay at the cap without overflowing.
	if d, ok := NextDelay(1_000_000, 0, time.Hour); !ok || d != 60*time.Second {
		t.Errorf("large attempt: %v, %v", d, ok)
	}
}
