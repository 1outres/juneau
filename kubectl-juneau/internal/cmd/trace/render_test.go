package trace

import (
	"strings"
	"testing"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
)

func TestRenderEvent(t *testing.T) {
	ev := &debugpb.TraceEvent{
		TraceId:     0xdeadbeef,
		Reason:      debugpb.TraceEventReason_TRACE_EVENT_REASON_DNAT_APPLIED,
		Hook:        debugpb.TraceHook_TRACE_HOOK_POD_EGRESS,
		NodeName:    "worker-1",
		MonotonicNs: 1_500_000,
		SrcIp:       []byte{10, 0, 1, 5},
		DstIp:       []byte{10, 96, 0, 10},
		SrcPort:     50000,
		DstPort:     443,
		HasAuxTuple: true,
		AuxSrcIp:    []byte{10, 0, 1, 5},
		AuxDstIp:    []byte{10, 0, 2, 8},
		AuxSrcPort:  50000,
		AuxDstPort:  8443,
		Verdict:     debugpb.TraceVerdict_TRACE_VERDICT_OK,
	}
	out := renderEvent(ev)
	for _, want := range []string{
		"worker-1",
		"pod_egress",
		"dnat applied",
		"10.0.1.5:50000->10.96.0.10:443",
		"10.0.1.5:50000->10.0.2.8:8443",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("renderEvent missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderEventDropSuffix(t *testing.T) {
	ev := &debugpb.TraceEvent{
		Reason:  debugpb.TraceEventReason_TRACE_EVENT_REASON_POLICY_ACL_DROP,
		Hook:    debugpb.TraceHook_TRACE_HOOK_POD_EGRESS,
		Verdict: debugpb.TraceVerdict_TRACE_VERDICT_DROP,
		SrcIp:   []byte{1, 2, 3, 4},
		DstIp:   []byte{5, 6, 7, 8},
	}
	out := renderEvent(ev)
	if !strings.Contains(out, "[DROP]") {
		t.Fatalf("missing drop marker: %s", out)
	}
	if !strings.Contains(out, "acl drop") {
		t.Fatalf("missing acl drop reason: %s", out)
	}
}

func TestReasonStringFallback(t *testing.T) {
	out := reasonString(debugpb.TraceEventReason_TRACE_EVENT_REASON_UNSPECIFIED)
	if out == "" {
		t.Fatalf("expected non-empty fallback")
	}
}
