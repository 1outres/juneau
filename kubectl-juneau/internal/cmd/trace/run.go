package trace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
	"github.com/1outres/juneau/kubectl-juneau/internal/factory/nodeagent"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Run is the trace command's main entry. It is split from Complete /
// Validate so tests can drive Run with a fake client.
func (o *Options) Run(ctx context.Context) error {
	cl, err := o.Factory.Kube()
	if err != nil {
		return err
	}

	// Handle SIGINT / SIGTERM as a soft stop: cancel the run context
	// so the streams unwind, then defer-Cleanup deletes the CRD
	// best-effort. spec.expiresAt is the safety net if cleanup
	// itself fails.
	runCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	resolved, err := o.resolveSession(runCtx, cl)
	if err != nil {
		return err
	}

	// Service / IP destinations have no node affinity kubectl can
	// statically derive — backends may be anywhere, NAPT IPs may be
	// owned by any node, etc. Attach to every daemon so the
	// LearnTuple fan-out in PropagateLearnedTuple has a peer set
	// large enough to cover the post-NAT path. Pod-to-Pod traces
	// keep the narrow [source, dest] node set.
	wantAll := o.DestService != "" || o.DestIP != ""
	if wantAll || len(resolved.nodes) == 0 {
		nodes, err := allDaemonNodes(runCtx, cl)
		if err != nil {
			return err
		}
		resolved.nodes = nodes
	}
	if len(resolved.nodes) == 0 {
		return fmt.Errorf("trace: no juneaud nodes available to attach")
	}

	session, _, err := o.createSession(runCtx, cl, resolved)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := session.Cleanup(); cerr != nil {
			_, _ = fmt.Fprintf(o.Factory.Streams().ErrOut, "trace: cleanup failed: %v\n", cerr)
		} else if !o.KeepSession {
			ackCtx, ackCancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = session.WaitForCleanupAck(ackCtx, 2*time.Second)
			ackCancel()
		}
	}()

	streams, err := o.attachStreams(runCtx, resolved.nodes, resolved.traceID)
	if err != nil {
		return err
	}
	defer streams.Close()

	collector := newEventCollector(o.OutputFile)
	defer func() {
		if err := collector.Close(); err != nil {
			_, _ = fmt.Fprintf(o.Factory.Streams().ErrOut, "trace: close output file: %v\n", err)
		}
	}()

	go o.driveProbe(runCtx, resolved)

	deadline := time.NewTimer(o.Timeout)
	defer deadline.Stop()

	out := o.Factory.Streams().Out
	errOut := o.Factory.Streams().ErrOut
	writeHeader(out, o.OutputFormat, resolved, o)

	for {
		select {
		case <-runCtx.Done():
			collector.Sort()
			writeFooter(out, o.OutputFormat, collector, resolved)
			return nil
		case <-deadline.C:
			collector.Sort()
			writeFooter(out, o.OutputFormat, collector, resolved)
			return nil
		case ev := <-streams.Events():
			collector.Add(ev)
			if err := writeEvent(out, o.OutputFormat, ev); err != nil {
				_, _ = fmt.Fprintf(errOut, "trace: render: %v\n", err)
			}
			// NAT-class events carry a post-translation tuple that
			// remote-node hooks need in their trace_tuple_map for the
			// continuation to match. Mirror it via Debug.LearnTuple
			// to every other daemon. Async: trace rendering must not
			// stall on RPC roundtrips.
			if isNATEvent(ev.Reason) && ev.HasAuxTuple {
				go streams.PropagateLearnedTuple(runCtx, ev)
			}
		case streamErr := <-streams.Errors():
			_, _ = fmt.Fprintf(errOut, "trace: stream error: %v\n", streamErr)
		}
	}
}

// allDaemonNodes lists every node currently hosting a juneaud Pod.
// Used as the fallback fan-out when neither side of the trace
// resolves to a Pod.
func allDaemonNodes(ctx context.Context, cl client.Client) ([]string, error) {
	var pods corev1.PodList
	if err := cl.List(ctx, &pods, client.InNamespace("kube-system"), client.MatchingLabelsSelector{
		Selector: labels.SelectorFromSet(labels.Set{"app": "cni-daemon"}),
	}); err != nil {
		return nil, fmt.Errorf("list daemon pods: %w", err)
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(pods.Items))
	for i := range pods.Items {
		n := pods.Items[i].Spec.NodeName
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// streamSet manages one WatchTrace stream per node. Events from
// every stream merge into a single channel so Run can render them
// as they arrive.
type streamSet struct {
	clients []nodeagentClientHandle
	events  chan *debugpb.TraceEvent
	errors  chan error
	wg      sync.WaitGroup
	cancel  context.CancelFunc
}

type nodeagentClientHandle struct {
	node string
	cl   nodeagent.Client
}

func (s *streamSet) Events() <-chan *debugpb.TraceEvent { return s.events }
func (s *streamSet) Errors() <-chan error               { return s.errors }

// PropagateLearnedTuple installs the post-NAT tuple from `ev` on
// every daemon node *other than* the one that emitted the event.
// Best-effort: per-node failures are surfaced on the error channel
// but never block trace rendering.
//
// The originating node's BPF program already learned the tuple
// locally via trace_learn_tuple, so re-installing there would be a
// redundant write and a wasted RPC. Skip it.
func (s *streamSet) PropagateLearnedTuple(ctx context.Context, ev *debugpb.TraceEvent) {
	if ev == nil || !ev.HasAuxTuple {
		return
	}
	tuple := &debugpb.TraceTuple{
		Scope:    ev.Scope,
		VpcId:    ev.VpcId,
		SrcIp:    ev.AuxSrcIp,
		DstIp:    ev.AuxDstIp,
		SrcPort:  0, // ephemeral source ports are wildcarded BPF-side
		DstPort:  ev.AuxDstPort,
		Protocol: ev.Protocol,
	}
	req := &debugpb.LearnTupleRequest{TraceId: ev.TraceId, Tuple: tuple}

	for _, h := range s.clients {
		if h.node == ev.NodeName {
			continue
		}
		// 2s is enough for an RPC over the local exec / port-forward
		// tunnel; capping prevents a stuck peer from leaking
		// goroutines.
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := h.cl.Debug().LearnTuple(callCtx, req)
		cancel()
		if err != nil {
			s.reportError(fmt.Errorf("node %s: LearnTuple: %w", h.node, err))
		}
	}
}

// isNATEvent reports whether the reason carries a useful aux tuple
// that should be fanned out to peer daemons. Only NAT-class events
// currently propagate; map-miss / policy events are observation-only.
func isNATEvent(r debugpb.TraceEventReason) bool {
	switch r {
	case debugpb.TraceEventReason_TRACE_EVENT_REASON_DNAT_APPLIED,
		debugpb.TraceEventReason_TRACE_EVENT_REASON_SNAT_APPLIED,
		debugpb.TraceEventReason_TRACE_EVENT_REASON_NAPT_ALLOCATED,
		debugpb.TraceEventReason_TRACE_EVENT_REASON_REVERSE_NAT_APPLIED:
		return true
	}
	return false
}
func (s *streamSet) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	// Close client conns in parallel so a single hung exec channel
	// does not block the rest of the shutdown. The cleanup defer
	// upstream in Run depends on this returning promptly so the
	// TraceSession CRD delete is not delayed past the user's
	// patience.
	done := make(chan struct{})
	go func() {
		for _, h := range s.clients {
			_ = h.cl.Close()
		}
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

// attachStreams dials each node's nodeagent and starts a WatchTrace
// stream. Returns a streamSet whose Events channel surfaces events
// from any node; per-node errors surface on Errors but do not abort
// the overall command — except when no node attaches successfully,
// in which case it returns an aggregate error so the caller exits
// non-zero rather than masking a cluster-wide outage as a clean
// "no events" trace.
func (o *Options) attachStreams(ctx context.Context, nodes []string, traceID uint32) (*streamSet, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	// Buffer headroom: each node may produce up to 2 setup errors
	// (NodeAgent dial + WatchTrace handshake) before Run starts
	// consuming, plus a margin for runtime stream errors. Sizing the
	// buffer to len(nodes)*2+16 prevents a setup-time deadlock that
	// otherwise hangs the command on cluster-wide RBAC/connectivity
	// failures.
	set := &streamSet{
		events: make(chan *debugpb.TraceEvent, 1024),
		errors: make(chan error, len(nodes)*2+16),
		cancel: cancel,
	}

	attached := 0
	for _, node := range nodes {
		client, err := o.Factory.NodeAgent(streamCtx, node)
		if err != nil {
			set.reportError(fmt.Errorf("node %s: %w", node, err))
			continue
		}
		set.clients = append(set.clients, nodeagentClientHandle{node: node, cl: client})

		stream, err := client.Debug().WatchTrace(streamCtx, &debugpb.WatchTraceRequest{
			TraceIds: []uint32{traceID},
		})
		if err != nil {
			set.reportError(fmt.Errorf("node %s: WatchTrace: %w", node, err))
			continue
		}

		attached++
		set.wg.Add(1)
		go func(node string) {
			defer set.wg.Done()
			for {
				ev, err := stream.Recv()
				if err != nil {
					if streamCtx.Err() == nil {
						set.reportError(fmt.Errorf("node %s: stream closed: %w", node, err))
					}
					return
				}
				select {
				case set.events <- ev:
				case <-streamCtx.Done():
					return
				}
			}
		}(node)
	}

	if attached == 0 {
		// Surface the failure path explicitly so a misconfigured
		// cluster (RBAC, daemon outage) does not look like a healthy
		// trace with zero matching packets.
		setupErrs := drainErrors(set.errors)
		set.Close()
		if len(nodes) == 0 {
			return nil, fmt.Errorf("trace: no nodes resolved to attach to")
		}
		return nil, fmt.Errorf("trace: failed to attach to any of %d node(s): %w",
			len(nodes), errors.Join(setupErrs...))
	}
	return set, nil
}

// drainErrors empties the buffered error channel without blocking.
// Used to collect setup-time errors when attachStreams fails open.
func drainErrors(ch <-chan error) []error {
	var errs []error
	for {
		select {
		case e := <-ch:
			errs = append(errs, e)
		default:
			return errs
		}
	}
}

// reportError pushes err onto the error channel without blocking.
// Setup-time callers run before Run consumes from Errors(), so a
// blocking send on a saturated buffer would deadlock the command.
// The buffer is sized to absorb the expected setup volume (see
// attachStreams); this non-blocking guard is the safety net for the
// runtime path and any future caller that exceeds the budget.
func (s *streamSet) reportError(err error) {
	select {
	case s.errors <- err:
	default:
	}
}
