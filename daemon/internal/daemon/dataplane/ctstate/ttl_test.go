package ctstate

import (
	"testing"
	"time"
)

const (
	protoICMP uint8 = 1
	protoTCP  uint8 = 6
	protoUDP  uint8 = 17
	protoGRE  uint8 = 47
	protoESP  uint8 = 50
	protoRaw  uint8 = 253
)

func TestShouldEvict(t *testing.T) {
	const now uint64 = 24 * 60 * 60 * 1_000_000_000 // 1 day in ns; bigger than the longest TTL

	cases := []struct {
		name         string
		state        uint8
		proto        uint8
		ageBeforeNow time.Duration
		want         bool
	}{
		{"NEW within TTL stays", StateNew, protoTCP, 29 * time.Second, false},
		{"NEW at TTL stays", StateNew, protoTCP, TTLNew, false},
		{"NEW past TTL evicts", StateNew, protoTCP, TTLNew + time.Second, true},

		{"ESTABLISHED within TTL stays", StateEstablished, protoTCP, 4 * time.Minute, false},
		{"ESTABLISHED at TTL stays", StateEstablished, protoTCP, TTLEstablished, false},
		{"ESTABLISHED past TTL evicts", StateEstablished, protoTCP, TTLEstablished + time.Second, true},

		{"FIN_WAIT within TTL stays", StateFinWait, protoTCP, 30 * time.Second, false},
		{"FIN_WAIT at TTL stays", StateFinWait, protoTCP, TTLFinWait, false},
		{"FIN_WAIT past TTL evicts", StateFinWait, protoTCP, TTLFinWait + time.Second, true},

		{"CLOSED is always evicted regardless of age", StateClosed, protoTCP, 0, true},
		{"CLOSED with stale timestamp evicts", StateClosed, protoTCP, time.Hour, true},

		{"UDP under TTL stays even if state ESTABLISHED", StateEstablished, protoUDP, 29 * time.Second, false},
		{"UDP at TTL stays", StateEstablished, protoUDP, TTLUDP, false},
		{"UDP past TTL evicts", StateEstablished, protoUDP, TTLUDP + time.Second, true},
		{"UDP NEW past UDP TTL evicts (state is irrelevant for UDP)", StateNew, protoUDP, TTLUDP + time.Second, true},

		{"ICMP under TTL stays even if state ESTABLISHED", StateEstablished, protoICMP, 29 * time.Second, false},
		{"ICMP at TTL stays", StateEstablished, protoICMP, TTLICMP, false},
		{"ICMP past TTL evicts", StateEstablished, protoICMP, TTLICMP + time.Second, true},

		{"GRE under TTL stays", StateEstablished, protoGRE, 60 * time.Second, false},
		{"GRE at TTL stays", StateEstablished, protoGRE, TTLOther, false},
		{"GRE past TTL evicts", StateEstablished, protoGRE, TTLOther + time.Second, true},
		{"GRE never gets the TCP ESTABLISHED hour", StateEstablished, protoGRE, 30 * time.Minute, true},
		{"GRE NEW past TTL evicts (state is irrelevant for GRE)", StateNew, protoGRE, TTLOther + time.Second, true},

		{"ESP past TTL evicts", StateEstablished, protoESP, TTLOther + time.Second, true},
		{"a protocol number with no keyword still gets a TTL", StateEstablished, protoRaw, TTLOther + time.Second, true},

		{"future last_seen treated as now (not evicted)", StateEstablished, protoTCP, -time.Second, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lastSeen := now - uint64(tc.ageBeforeNow.Nanoseconds())
			got := ShouldEvict(tc.state, tc.proto, lastSeen, now)
			if got != tc.want {
				t.Fatalf("ShouldEvict(state=%d proto=%d age=%s) = %v; want %v",
					tc.state, tc.proto, tc.ageBeforeNow, got, tc.want)
			}
		})
	}
}
