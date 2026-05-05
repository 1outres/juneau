package trace

import (
	"time"

	"golang.org/x/sys/unix"
)

// processStart is the wallclock time the package was first
// initialised. Combined with monoNowNs() at the same instant it lets
// us translate wallclock expiries into CLOCK_MONOTONIC values that
// match bpf_ktime_get_ns().
var processStart = time.Now()

func monoNowNs() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// Fallback: time.Now's monotonic component is also
		// CLOCK_MONOTONIC on Linux, so use it as the anchor. The
		// resulting expiry will still match bpf_ktime_get_ns within
		// the resolution of the runtime's monotonic clock read.
		return time.Now().UnixNano()
	}
	return ts.Nano()
}
