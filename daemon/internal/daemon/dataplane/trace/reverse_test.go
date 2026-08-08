package trace

import (
	"net"
	"testing"
)

func ip(s string) net.IP { return net.ParseIP(s).To4() }

func TestReverseMirrorFromEvent(t *testing.T) {
	base := Event{
		TraceID:  7,
		Scope:    ScopeVPC,
		VPCID:    42,
		Protocol: 6,
		SrcIP:    ip("10.0.1.5"),
		DstIP:    ip("10.96.0.10"),
		SrcPort:  33333,
		DstPort:  443,
	}

	tests := []struct {
		name    string
		mutate  func(Event) Event
		wantOK  bool
		wantKey TupleKey
		wantDir Direction
	}{
		{
			name: "request enter seeds reply mirror",
			mutate: func(e Event) Event {
				e.Reason = ReasonEnterPodEgress
				e.Direction = DirRequest
				return e
			},
			wantOK: true,
			// src/dst swapped, ports wildcarded, tagged Reply.
			wantKey: TupleKey{Scope: ScopeVPC, Protocol: 6, VPCID: 42,
				SrcIP: [4]byte{10, 96, 0, 10}, DstIP: [4]byte{10, 0, 1, 5}},
			wantDir: DirReply,
		},
		{
			name: "reply enter seeds nothing (request mirror already present)",
			mutate: func(e Event) Event {
				e.Reason = ReasonEnterPodIngress
				e.Direction = DirReply
				return e
			},
			wantOK: false,
		},
		{
			name: "enter with unspecified leg seeds nothing",
			mutate: func(e Event) Event {
				e.Reason = ReasonEnterNodeIngress
				e.Direction = DirUnspecified
				return e
			},
			wantOK: false,
		},
		{
			name: "request NAT mirrors the aux (after) tuple, tagged Reply",
			mutate: func(e Event) Event {
				e.Reason = ReasonDNATApplied
				e.Direction = DirRequest
				e.HasAux = true
				e.AuxSrc = ip("10.0.1.5")
				e.AuxDst = ip("10.0.2.8") // post-DNAT backend
				return e
			},
			wantOK: true,
			// aux src/dst swapped -> (AuxDst, AuxSrc), Reply.
			wantKey: TupleKey{Scope: ScopeVPC, Protocol: 6, VPCID: 42,
				SrcIP: [4]byte{10, 0, 2, 8}, DstIP: [4]byte{10, 0, 1, 5}},
			wantDir: DirReply,
		},
		{
			name: "reply NAT mirrors the aux tuple, tagged Request",
			mutate: func(e Event) Event {
				e.Reason = ReasonReverseNATApplied
				e.Direction = DirReply
				e.HasAux = true
				e.AuxSrc = ip("10.0.2.8")
				e.AuxDst = ip("10.0.1.5")
				return e
			},
			wantOK: true,
			wantKey: TupleKey{Scope: ScopeVPC, Protocol: 6, VPCID: 42,
				SrcIP: [4]byte{10, 0, 1, 5}, DstIP: [4]byte{10, 0, 2, 8}},
			wantDir: DirRequest,
		},
		{
			// An ICMP error message reports on a flow. Its aux tuple is
			// the post-translation outer tuple, so it seeds a mirror the
			// same way every other NAT event does.
			name: "icmp error translation mirrors the aux tuple",
			mutate: func(e Event) Event {
				e.Reason = ReasonICMPErrorTranslated
				e.Direction = DirReply
				e.HasAux = true
				e.AuxSrc = ip("198.51.100.9")
				e.AuxDst = ip("10.0.1.5")
				return e
			},
			wantOK: true,
			wantKey: TupleKey{Scope: ScopeVPC, Protocol: 6, VPCID: 42,
				SrcIP: [4]byte{10, 0, 1, 5}, DstIP: [4]byte{198, 51, 100, 9}},
			wantDir: DirRequest,
		},
		{
			name: "policy event seeds nothing",
			mutate: func(e Event) Event {
				e.Reason = ReasonPolicyACLPass
				e.Direction = DirRequest
				return e
			},
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, dir, ok := reverseMirrorFromEvent(tc.mutate(base))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if key != tc.wantKey {
				t.Errorf("key = %+v, want %+v", key, tc.wantKey)
			}
			if dir != tc.wantDir {
				t.Errorf("dir = %d, want %d", dir, tc.wantDir)
			}
			if key.SrcPort != 0 || key.DstPort != 0 {
				t.Errorf("ports not wildcarded: src=%d dst=%d", key.SrcPort, key.DstPort)
			}
		})
	}
}
