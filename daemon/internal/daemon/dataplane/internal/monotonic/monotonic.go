// Package monotonic reads the clock the eBPF data plane stamps its
// map entries with.
package monotonic

import (
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// Ns returns nanoseconds since boot on CLOCK_MONOTONIC, the same clock
// bpf_ktime_get_ns reads. Comparing a map entry against time.Now()
// instead would break every TTL the moment NTP steps the wall clock,
// and it would break quietly: entries would either never expire or all
// expire at once.
func Ns() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		zap.S().Warnf("monotonic: clock_gettime: %v", err)
		return 0
	}
	return uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec)
}
