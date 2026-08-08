package trace

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
	sigsyaml "sigs.k8s.io/yaml"
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

func TestRenderEventDirectionMarker(t *testing.T) {
	ev := &debugpb.TraceEvent{
		Reason: debugpb.TraceEventReason_TRACE_EVENT_REASON_ENTER_POD_EGRESS,
		Hook:   debugpb.TraceHook_TRACE_HOOK_POD_EGRESS,
		SrcIp:  []byte{10, 0, 1, 5},
		DstIp:  []byte{10, 0, 2, 8},
	}
	ev.Direction = debugpb.TraceDirection_TRACE_DIRECTION_REQUEST
	req := renderEvent(ev)
	if !strings.Contains(req, "[->]") || strings.Contains(req, "[<-]") {
		t.Fatalf("request leg should carry [->] marker only: %q", req)
	}
	ev.Direction = debugpb.TraceDirection_TRACE_DIRECTION_REPLY
	rep := renderEvent(ev)
	if !strings.Contains(rep, "[<-]") || strings.Contains(rep, "[->]") {
		t.Fatalf("reply leg should carry [<-] marker only: %q", rep)
	}
	ev.Direction = debugpb.TraceDirection_TRACE_DIRECTION_UNSPECIFIED
	unk := renderEvent(ev)
	if strings.Contains(unk, "[->]") || strings.Contains(unk, "[<-]") {
		t.Fatalf("unspecified leg should carry no direction marker: %q", unk)
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

// A reason with no case in reasonString falls back to the raw enum name,
// which reads badly in a timeline. Adding a reason to the proto without
// a label here should fail this test rather than ship.
func TestReasonStringLabelsEveryReason(t *testing.T) {
	for value, name := range debugpb.TraceEventReason_name {
		reason := debugpb.TraceEventReason(value)
		if reason == debugpb.TraceEventReason_TRACE_EVENT_REASON_UNSPECIFIED {
			continue
		}
		if got := reasonString(reason); got == name {
			t.Errorf("reason %s has no human label", name)
		}
	}
}

func TestReasonStringICMPErrorTranslated(t *testing.T) {
	got := reasonString(debugpb.TraceEventReason_TRACE_EVENT_REASON_ICMP_ERROR_TRANSLATED)
	if got != "icmp error translated" {
		t.Fatalf("reasonString = %q", got)
	}
}

func sampleEvent() *debugpb.TraceEvent {
	return &debugpb.TraceEvent{
		TraceId:  0xdeadbeef,
		NodeName: "worker-1",
		Reason:   debugpb.TraceEventReason_TRACE_EVENT_REASON_DNAT_APPLIED,
		Hook:     debugpb.TraceHook_TRACE_HOOK_POD_EGRESS,
		SrcIp:    []byte{10, 0, 1, 5},
		DstIp:    []byte{10, 96, 0, 10},
		SrcPort:  50000,
		DstPort:  443,
	}
}

func TestWriteEventJSONIsParseable(t *testing.T) {
	var buf bytes.Buffer
	if err := writeEvent(&buf, "json", sampleEvent()); err != nil {
		t.Fatalf("writeEvent: %v", err)
	}
	line := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(line, "{") {
		t.Fatalf("expected JSON object, got: %q", line)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, line)
	}
	if got, _ := decoded["nodeName"].(string); got != "worker-1" {
		t.Fatalf("nodeName = %q, want worker-1", got)
	}
}

func TestWriteEventYAMLIsParseable(t *testing.T) {
	var buf bytes.Buffer
	if err := writeEvent(&buf, "yaml", sampleEvent()); err != nil {
		t.Fatalf("writeEvent: %v", err)
	}
	body := buf.String()
	if !strings.HasPrefix(body, "---\n") {
		t.Fatalf("expected YAML doc separator prefix, got: %q", body)
	}
	var decoded map[string]any
	if err := sigsyaml.Unmarshal([]byte(strings.TrimPrefix(body, "---\n")), &decoded); err != nil {
		t.Fatalf("not valid YAML: %v\n%s", err, body)
	}
	if got, _ := decoded["nodeName"].(string); got != "worker-1" {
		t.Fatalf("nodeName = %q, want worker-1", got)
	}
}

func TestWriteEventTreeFallbackUsesRenderEvent(t *testing.T) {
	var buf bytes.Buffer
	if err := writeEvent(&buf, "tree", sampleEvent()); err != nil {
		t.Fatalf("writeEvent: %v", err)
	}
	if !strings.Contains(buf.String(), "pod_egress") {
		t.Fatalf("tree output missing hook marker: %q", buf.String())
	}
	// JSON / YAML should not leak into tree mode.
	if strings.Contains(buf.String(), "\"nodeName\"") {
		t.Fatalf("tree output should not be JSON: %q", buf.String())
	}
}

func TestWriteHeaderFooterSkipsForMachineFormats(t *testing.T) {
	r := &resolved{traceID: 0xdeadbeef}
	o := &Options{Protocol: "tcp"}
	for _, fmtName := range []string{"json", "yaml"} {
		var hdr bytes.Buffer
		writeHeader(&hdr, fmtName, r, o)
		if hdr.Len() != 0 {
			t.Fatalf("%s: header should be empty, got %q", fmtName, hdr.String())
		}
		var ftr bytes.Buffer
		writeFooter(&ftr, fmtName, &eventCollector{}, r)
		if ftr.Len() != 0 {
			t.Fatalf("%s: footer should be empty, got %q", fmtName, ftr.String())
		}
	}
}
