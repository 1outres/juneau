package grpc

import (
	"testing"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/trace"
	"github.com/1outres/juneau/daemon/pkg/debugpb"
)

// reasonToProto is a plain numeric cast, so the two lists of constants
// only agree as long as somebody keeps them in step. This pins the pairs
// so a renumbered or missing enum entry fails here instead of showing up
// as a mislabelled event in kubectl juneau trace.
func TestReasonToProtoMatchesEnum(t *testing.T) {
	cases := map[trace.Reason]debugpb.TraceEventReason{
		trace.ReasonEnterPodEgress:      debugpb.TraceEventReason_TRACE_EVENT_REASON_ENTER_POD_EGRESS,
		trace.ReasonEnterNodeIngress:    debugpb.TraceEventReason_TRACE_EVENT_REASON_ENTER_NODE_INGRESS,
		trace.ReasonMissConntrack:       debugpb.TraceEventReason_TRACE_EVENT_REASON_MISS_CONNTRACK,
		trace.ReasonPolicySGDrop:        debugpb.TraceEventReason_TRACE_EVENT_REASON_POLICY_SG_DROP,
		trace.ReasonDNATApplied:         debugpb.TraceEventReason_TRACE_EVENT_REASON_DNAT_APPLIED,
		trace.ReasonSNATApplied:         debugpb.TraceEventReason_TRACE_EVENT_REASON_SNAT_APPLIED,
		trace.ReasonNAPTAllocated:       debugpb.TraceEventReason_TRACE_EVENT_REASON_NAPT_ALLOCATED,
		trace.ReasonReverseNATApplied:   debugpb.TraceEventReason_TRACE_EVENT_REASON_REVERSE_NAT_APPLIED,
		trace.ReasonICMPErrorTranslated: debugpb.TraceEventReason_TRACE_EVENT_REASON_ICMP_ERROR_TRANSLATED,
		trace.ReasonDropBlackhole:       debugpb.TraceEventReason_TRACE_EVENT_REASON_DROP_BLACKHOLE,
	}
	for reason, want := range cases {
		if got := reasonToProto(reason); got != want {
			t.Errorf("reasonToProto(%d) = %v, want %v", reason, got, want)
		}
	}
}
