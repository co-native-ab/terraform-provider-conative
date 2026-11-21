package azuredns

import (
	"testing"
	"time"
)

func TestRetryPauseGrowsAndIsJittered(t *testing.T) {
	t.Parallel()
	c := &Client{retryBase: 100 * time.Millisecond}
	for n := 1; n <= 12; n++ {
		full := min(100*time.Millisecond<<(n-1), maxRetryPause)
		distinct := map[time.Duration]bool{}
		for range 50 {
			d := c.retryPause(n)
			if d < full/2 || d > full {
				t.Fatalf("attempt %d: pause %s is outside [%s, %s]", n, d, full/2, full)
			}
			distinct[d] = true
		}
		if len(distinct) < 2 {
			t.Errorf("attempt %d: the pause is not jittered", n)
		}
	}
	if (&Client{}).retryPause(1) < defaultRetryBase/2 {
		t.Error("the default base is not used")
	}
}
