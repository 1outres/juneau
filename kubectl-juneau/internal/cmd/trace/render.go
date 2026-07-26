package trace

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
	"google.golang.org/protobuf/encoding/protojson"
	sigsyaml "sigs.k8s.io/yaml"
)

// Output formats accepted by --output. validated in Options.Validate.
const (
	outputTree = "tree"
	outputJSON = "json"
	outputYAML = "yaml"
)

// writeHeader prints the human-readable timeline title for the tree
// format. JSON / YAML callers want a clean stream of structured
// records and skip this entirely.
func writeHeader(w io.Writer, format string, r *resolved, o *Options) {
	if normaliseFormat(format) != outputTree {
		return
	}
	_, _ = fmt.Fprintln(w, renderHeader(r, o))
}

// writeEvent emits a single event in the configured format. tree
// formatting matches the streaming-friendly one-line layout and is the
// only format that carries the request/reply direction marker; JSON
// produces NDJSON so downstream tooling can consume the stream
// incrementally; YAML uses the kubectl idiom of one document per
// record separated by `---`. Machine formats emit the raw event as-is;
// the direction marker is a tree-only presentation of ev.Direction,
// which is already present on the structured record.
func writeEvent(w io.Writer, format string, ev *debugpb.TraceEvent) error {
	switch normaliseFormat(format) {
	case outputJSON:
		marshaller := protojson.MarshalOptions{EmitUnpopulated: false}
		buf, err := marshaller.Marshal(ev)
		if err != nil {
			return fmt.Errorf("marshal json: %w", err)
		}
		_, err = fmt.Fprintln(w, string(buf))
		return err
	case outputYAML:
		marshaller := protojson.MarshalOptions{EmitUnpopulated: false}
		buf, err := marshaller.Marshal(ev)
		if err != nil {
			return fmt.Errorf("marshal yaml: %w", err)
		}
		yamlBytes, err := sigsyaml.JSONToYAML(buf)
		if err != nil {
			return fmt.Errorf("convert yaml: %w", err)
		}
		if _, err := fmt.Fprintln(w, "---"); err != nil {
			return err
		}
		_, err = w.Write(yamlBytes)
		return err
	default:
		_, err := fmt.Fprintln(w, renderEvent(ev))
		return err
	}
}

// writeFooter emits the post-timeout summary, suppressed for
// machine-readable formats.
func writeFooter(w io.Writer, format string, c *eventCollector, r *resolved) {
	if normaliseFormat(format) != outputTree {
		return
	}
	renderFooter(w, c, r)
}

func normaliseFormat(format string) string {
	f := strings.ToLower(strings.TrimSpace(format))
	if f == "" {
		return outputTree
	}
	return f
}

// renderHeader returns the one-line trace title for the timeline.
// Mirrors the example in the design handoff:
//
//	Trace trace-... pod/default/client -> svc/default/api tcp/443
func renderHeader(r *resolved, o *Options) string {
	src := endpointDisplay(r.source)
	dst := endpointDisplay(r.destination)
	pp := strings.ToLower(o.Protocol)
	port := ""
	if o.Port > 0 {
		port = fmt.Sprintf("/%d", o.Port)
	}
	return fmt.Sprintf("Trace trace-%08x  %s -> %s %s%s", r.traceID, src, dst, pp, port)
}

func endpointDisplay(e endpoint) string {
	switch {
	case e.pod != nil:
		return "pod/" + e.pod.Namespace + "/" + e.pod.Name
	case e.service != nil:
		return "svc/" + e.service.Namespace + "/" + e.service.Name
	case e.ip.IsValid():
		return e.ip.String()
	}
	return "<unresolved>"
}

// renderEvent renders a single TraceEvent as a one-line timeline
// entry. Format mirrors the design handoff example with the addition
// of a request/reply direction marker and a verdict suffix when
// non-OK. The leg comes straight off ev.Direction — an authoritative
// tag the dataplane stamps from the matched tuple, so kubectl never
// has to infer direction from address orientation (ambiguous under NAT
// and across VPCs with overlapping Pod CIDRs).
func renderEvent(ev *debugpb.TraceEvent) string {
	ms := float64(ev.MonotonicNs) / 1e6
	tuple := fmt.Sprintf("%s:%d->%s:%d",
		ipFormat(ev.SrcIp), ev.SrcPort,
		ipFormat(ev.DstIp), ev.DstPort)
	hook := hookString(ev.Hook)
	reason := reasonString(ev.Reason)
	var aux string
	if ev.HasAuxTuple {
		aux = fmt.Sprintf(" -> %s:%d->%s:%d",
			ipFormat(ev.AuxSrcIp), ev.AuxSrcPort,
			ipFormat(ev.AuxDstIp), ev.AuxDstPort)
	}
	verdict := verdictSuffix(ev.Verdict)
	return fmt.Sprintf("  %9.3fms  %-12s  %-22s  %-32s  %s  %s%s%s",
		ms, ev.NodeName, hook, reason, directionTag(ev.Direction), tuple, aux, verdict)
}

// directionTag renders the fixed-width leg marker. ASCII arrows keep
// the timeline grep-friendly; an unspecified leg reserves the same
// width so columns stay aligned.
func directionTag(d debugpb.TraceDirection) string {
	switch d {
	case debugpb.TraceDirection_TRACE_DIRECTION_REQUEST:
		return "[->]"
	case debugpb.TraceDirection_TRACE_DIRECTION_REPLY:
		return "[<-]"
	}
	return "    "
}

func ipFormat(b []byte) string {
	if len(b) != 4 {
		return "?"
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func hookString(h debugpb.TraceHook) string {
	switch h {
	case debugpb.TraceHook_TRACE_HOOK_POD_EGRESS:
		return "pod_egress"
	case debugpb.TraceHook_TRACE_HOOK_POD_INGRESS:
		return "pod_ingress"
	case debugpb.TraceHook_TRACE_HOOK_VXLAN_INGRESS:
		return "vxlan_ingress"
	case debugpb.TraceHook_TRACE_HOOK_NODE_INGRESS:
		return "node_ingress"
	}
	return "?"
}

func reasonString(r debugpb.TraceEventReason) string {
	switch r {
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_ENTER_POD_EGRESS:
		return "enter pod_egress"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_ENTER_POD_INGRESS:
		return "enter pod_ingress"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_ENTER_VXLAN_INGRESS:
		return "enter vxlan_ingress"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_ENTER_NODE_INGRESS:
		return "enter node_ingress"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_MISS_IFINDEX_SUBNET:
		return "ifindex->subnet miss"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_MISS_SUBNET:
		return "subnet miss"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_MISS_FIB_TABLE:
		return "fib table miss"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_MISS_FIB_ROUTE:
		return "fib route miss"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_MISS_ARP:
		return "arp miss"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_MISS_FDB:
		return "fdb miss"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_MISS_SERVICE:
		return "service miss"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_MISS_BACKEND:
		return "backend miss"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_MISS_CONNTRACK:
		return "conntrack miss"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_POLICY_ACL_PASS:
		return "acl pass"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_POLICY_ACL_DROP:
		return "acl drop"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_POLICY_SG_PASS:
		return "sg pass"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_POLICY_SG_DROP:
		return "sg drop"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_SERVICE_LOOKUP_HIT:
		return "service lookup hit"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_SERVICE_BACKEND_SELECTED:
		return "backend selected"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_DNAT_APPLIED:
		return "dnat applied"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_SNAT_APPLIED:
		return "snat applied"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_NAPT_ALLOCATED:
		return "napt allocated"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_REVERSE_NAT_APPLIED:
		return "reverse nat applied"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_REDIRECT_IFINDEX:
		return "redirect ifindex"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_REDIRECT_VXLAN:
		return "redirect vxlan"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_PASS_KERNEL:
		return "pass to kernel"
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_DROP_SHOT:
		return "drop"
	}
	return r.String()
}

func verdictSuffix(v debugpb.TraceVerdict) string {
	switch v {
	case debugpb.TraceVerdict_TRACE_VERDICT_DROP:
		return "  [DROP]"
	case debugpb.TraceVerdict_TRACE_VERDICT_REDIRECT:
		return "  [REDIRECT]"
	}
	return ""
}

// renderFooter prints the result summary after the timeout fires.
func renderFooter(w io.Writer, c *eventCollector, r *resolved) {
	count := c.Count()
	if count == 0 {
		_, _ = fmt.Fprintf(w, "\nResult: no events received for trace-%08x — packet did not enter any instrumented hook on the watched nodes.\n", r.traceID)
		return
	}
	last := c.Last()
	switch last.Verdict {
	case debugpb.TraceVerdict_TRACE_VERDICT_DROP:
		_, _ = fmt.Fprintf(w, "\nResult: dropped at %s (%s)\n", hookString(last.Hook), reasonString(last.Reason))
	case debugpb.TraceVerdict_TRACE_VERDICT_REDIRECT:
		_, _ = fmt.Fprintf(w, "\nResult: last seen redirected at %s\n", hookString(last.Hook))
	default:
		_, _ = fmt.Fprintf(w, "\nResult: %d events received\n", count)
	}
}

// eventCollector keeps a sortable copy of every observed event so we
// can render an ordered final timeline and (optionally) persist NDJSON
// to --output-file.
type eventCollector struct {
	mu     sync.Mutex
	events []*debugpb.TraceEvent
	file   *os.File
	enc    *json.Encoder
}

func newEventCollector(outputFile string) *eventCollector {
	c := &eventCollector{}
	if outputFile != "" {
		f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err == nil {
			c.file = f
			c.enc = json.NewEncoder(f)
		}
	}
	return c
}

func (c *eventCollector) Add(ev *debugpb.TraceEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	if c.enc != nil {
		_ = c.enc.Encode(ev)
	}
}

func (c *eventCollector) Sort() {
	c.mu.Lock()
	defer c.mu.Unlock()
	sort.Slice(c.events, func(i, j int) bool {
		// Per-node monotonic clocks aren't comparable across nodes;
		// fall back to receive time for cross-node ordering. Within
		// the same node the receive time and monotonic clock agree.
		if c.events[i].NodeName == c.events[j].NodeName {
			return c.events[i].MonotonicNs < c.events[j].MonotonicNs
		}
		return c.events[i].ReceivedNs < c.events[j].ReceivedNs
	})
}

func (c *eventCollector) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func (c *eventCollector) Last() *debugpb.TraceEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return &debugpb.TraceEvent{}
	}
	return c.events[len(c.events)-1]
}

func (c *eventCollector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file != nil {
		return c.file.Close()
	}
	return nil
}
