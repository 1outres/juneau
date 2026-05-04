package trace

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
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

	// If no nodes were resolved (e.g. --to-ip with no source Pod),
	// fan out to every node hosting a daemon. Operators can narrow
	// the watch later by attaching --from-pod.
	if len(resolved.nodes) == 0 {
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
			fmt.Fprintf(o.Factory.Streams().ErrOut, "trace: cleanup failed: %v\n", cerr)
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
			fmt.Fprintf(o.Factory.Streams().ErrOut, "trace: close output file: %v\n", err)
		}
	}()

	go o.driveProbe(runCtx, resolved)

	deadline := time.NewTimer(o.Timeout)
	defer deadline.Stop()

	out := o.Factory.Streams().Out
	header := renderHeader(resolved, o)
	fmt.Fprintln(out, header)

	for {
		select {
		case <-runCtx.Done():
			collector.Sort()
			renderFooter(out, collector, resolved)
			return nil
		case <-deadline.C:
			collector.Sort()
			renderFooter(out, collector, resolved)
			return nil
		case ev := <-streams.Events():
			collector.Add(ev)
			fmt.Fprintln(out, renderEvent(ev))
		case streamErr := <-streams.Errors():
			fmt.Fprintf(o.Factory.Streams().ErrOut, "trace: stream error: %v\n", streamErr)
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
	cl   nodeAgentCloser
}

type nodeAgentCloser interface {
	Close() error
}

func (s *streamSet) Events() <-chan *debugpb.TraceEvent { return s.events }
func (s *streamSet) Errors() <-chan error               { return s.errors }
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
// from any node; errors surface on Errors but do not abort the
// overall command.
func (o *Options) attachStreams(ctx context.Context, nodes []string, traceID uint32) (*streamSet, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	set := &streamSet{
		events: make(chan *debugpb.TraceEvent, 1024),
		errors: make(chan error, 16),
		cancel: cancel,
	}

	for _, node := range nodes {
		client, err := o.Factory.NodeAgent(streamCtx, node)
		if err != nil {
			set.errors <- fmt.Errorf("node %s: %w", node, err)
			continue
		}
		set.clients = append(set.clients, nodeagentClientHandle{node: node, cl: client})

		stream, err := client.Debug().WatchTrace(streamCtx, &debugpb.WatchTraceRequest{
			TraceIds: []uint32{traceID},
		})
		if err != nil {
			set.errors <- fmt.Errorf("node %s: WatchTrace: %w", node, err)
			continue
		}

		set.wg.Add(1)
		go func(node string) {
			defer set.wg.Done()
			for {
				ev, err := stream.Recv()
				if err != nil {
					if streamCtx.Err() == nil {
						set.errors <- fmt.Errorf("node %s: stream closed: %w", node, err)
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
	return set, nil
}
