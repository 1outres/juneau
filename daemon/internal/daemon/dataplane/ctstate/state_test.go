package ctstate

import "testing"

func TestDeriveNextState(t *testing.T) {
	cases := []struct {
		name string
		cur  uint8
		flag uint8
		want uint8
	}{
		{"NEW + ACK becomes ESTABLISHED", StateNew, FlagAck, StateEstablished},
		{"NEW + SYN+ACK stays NEW until pure ACK arrives is wrong; SYN+ACK has ACK so promote", StateNew, FlagSyn | FlagAck, StateEstablished},
		{"NEW + SYN only stays NEW", StateNew, FlagSyn, StateNew},
		{"NEW + RST goes CLOSED", StateNew, FlagRst, StateClosed},
		{"NEW + FIN goes FIN_WAIT", StateNew, FlagFin, StateFinWait},

		{"ESTABLISHED + ACK stays ESTABLISHED", StateEstablished, FlagAck, StateEstablished},
		{"ESTABLISHED + FIN goes FIN_WAIT", StateEstablished, FlagFin, StateFinWait},
		{"ESTABLISHED + FIN+ACK goes FIN_WAIT", StateEstablished, FlagFin | FlagAck, StateFinWait},
		{"ESTABLISHED + RST goes CLOSED", StateEstablished, FlagRst, StateClosed},

		{"FIN_WAIT + ACK stays FIN_WAIT", StateFinWait, FlagAck, StateFinWait},
		{"FIN_WAIT + FIN goes CLOSED (both sides closed)", StateFinWait, FlagFin, StateClosed},
		{"FIN_WAIT + FIN+ACK goes CLOSED", StateFinWait, FlagFin | FlagAck, StateClosed},
		{"FIN_WAIT + RST goes CLOSED", StateFinWait, FlagRst, StateClosed},

		{"CLOSED stays CLOSED on any flag", StateClosed, FlagAck, StateClosed},
		{"CLOSED stays CLOSED on RST", StateClosed, FlagRst, StateClosed},

		{"RST trumps FIN", StateEstablished, FlagFin | FlagRst, StateClosed},
		{"RST trumps SYN+ACK from NEW", StateNew, FlagSyn | FlagAck | FlagRst, StateClosed},

		{"empty flags keep state in NEW", StateNew, 0, StateNew},
		{"empty flags keep state in ESTABLISHED", StateEstablished, 0, StateEstablished},
		{"empty flags keep state in FIN_WAIT", StateFinWait, 0, StateFinWait},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveNextState(tc.cur, tc.flag)
			if got != tc.want {
				t.Fatalf("DeriveNextState(%d, 0x%02x) = %d; want %d", tc.cur, tc.flag, got, tc.want)
			}
		})
	}
}

func TestInitialStateForSYN(t *testing.T) {
	cases := []struct {
		name  string
		flags uint8
		want  uint8
	}{
		{"SYN only initializes NEW", FlagSyn, StateNew},
		{"SYN+ACK initializes NEW (active opener side)", FlagSyn | FlagAck, StateNew},
		{"no SYN initializes ESTABLISHED (mid-flow)", FlagAck, StateEstablished},
		{"no flags initializes ESTABLISHED", 0, StateEstablished},
		{"FIN without SYN initializes ESTABLISHED", FlagFin, StateEstablished},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := InitialStateForSYN(tc.flags)
			if got != tc.want {
				t.Fatalf("InitialStateForSYN(0x%02x) = %d; want %d", tc.flags, got, tc.want)
			}
		})
	}
}
