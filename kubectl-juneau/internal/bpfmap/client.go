package bpfmap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
	"github.com/1outres/juneau/kubectl-juneau/internal/factory"
)

// Client is the abstraction the cmd layer depends on. The production
// implementation dials each node through factory.NodeAgent. Tests
// substitute a fake by implementing the interface.
type Client interface {
	// ListNodes returns every node currently running a daemon Pod.
	// Sorted by node name so ordering is stable across calls.
	ListNodes(ctx context.Context) ([]string, error)

	// ListMaps queries one node and returns its descriptor schema.
	ListMaps(ctx context.Context, node string) ([]Schema, error)

	// DumpMap streams entries from one node, invoking emit for each
	// matched entry. Returning an error from emit aborts iteration
	// and propagates the error.
	DumpMap(ctx context.Context, node, mapName string, opts DumpOptions, emit func(Entry) error) error
}

// DumpOptions are the cmd-layer's input shape; the Client mirrors
// them onto the wire request as-is.
type DumpOptions struct {
	KeyFilter []*debugpb.BPFMapField
	InnerKey  []*debugpb.BPFMapField
	Limit     uint32
}

// FactoryClient is the production Client; it dials each node through
// the supplied Factory and rides on the existing trace transport.
type FactoryClient struct {
	Factory factory.Factory
	// Namespace and LabelSelector mirror the daemon DaemonSet
	// defaults. Overridable for clusters that re-label things.
	Namespace     string
	LabelSelector string
}

// NewFactoryClient returns a FactoryClient with daemon defaults.
func NewFactoryClient(f factory.Factory) *FactoryClient {
	return &FactoryClient{Factory: f}
}

func (c *FactoryClient) namespace() string {
	if c.Namespace == "" {
		return "kube-system"
	}
	return c.Namespace
}

func (c *FactoryClient) labelSelector() string {
	if c.LabelSelector == "" {
		return "app=cni-daemon"
	}
	return c.LabelSelector
}

// ListNodes implements Client. Lists daemon Pods and returns the
// distinct nodes hosting them.
func (c *FactoryClient) ListNodes(ctx context.Context) ([]string, error) {
	cl, err := c.Factory.Kube()
	if err != nil {
		return nil, err
	}
	sel, err := labels.Parse(c.labelSelector())
	if err != nil {
		return nil, fmt.Errorf("parse label selector: %w", err)
	}
	var pods corev1.PodList
	if err := cl.List(ctx, &pods, client.InNamespace(c.namespace()), client.MatchingLabelsSelector{Selector: sel}); err != nil {
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

// ListMaps implements Client. Each call dials the node and closes the
// transport when finished.
func (c *FactoryClient) ListMaps(ctx context.Context, node string) ([]Schema, error) {
	agent, err := c.Factory.NodeAgent(ctx, node)
	if err != nil {
		return nil, err
	}
	defer func() { _ = agent.Close() }()
	resp, err := agent.Debug().ListBPFMaps(ctx, &debugpb.ListBPFMapsRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]Schema, 0, len(resp.Maps))
	for _, m := range resp.Maps {
		out = append(out, FromSchemaProto(m))
	}
	return out, nil
}

// DumpMap implements Client. Drains the gRPC stream, invoking emit
// for every entry. EOF is treated as a clean end-of-stream.
func (c *FactoryClient) DumpMap(ctx context.Context, node, mapName string, opts DumpOptions, emit func(Entry) error) error {
	agent, err := c.Factory.NodeAgent(ctx, node)
	if err != nil {
		return err
	}
	defer func() { _ = agent.Close() }()

	stream, err := agent.Debug().DumpBPFMap(ctx, &debugpb.DumpBPFMapRequest{
		Name:      mapName,
		KeyFilter: opts.KeyFilter,
		InnerKey:  opts.InnerKey,
		Limit:     opts.Limit,
	})
	if err != nil {
		return err
	}
	for {
		entry, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := emit(FromEntryProto(node, entry)); err != nil {
			return err
		}
	}
}

// ----- Aggregators ------------------------------------------------------

// AggregateListMaps queries every node concurrently. Each node's
// schema list is preserved in the response keyed by node name so the
// caller can render per-node deltas (helpful when an old daemon is
// still running an old schema).
func AggregateListMaps(ctx context.Context, c Client, nodes []string) (map[string][]Schema, []NodeError) {
	out := make(map[string][]Schema, len(nodes))
	errs := make([]NodeError, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, node := range nodes {
		wg.Add(1)
		go func(node string) {
			defer wg.Done()
			schemas, err := c.ListMaps(ctx, node)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, NodeError{Node: node, Err: err})
				return
			}
			out[node] = schemas
		}(node)
	}
	wg.Wait()
	sort.Slice(errs, func(i, j int) bool { return errs[i].Node < errs[j].Node })
	return out, errs
}

// AggregateDumpMap fans dump out to every node. emit is invoked once
// per matched entry across all nodes; ordering is per-stream (cilium/
// ebpf does not order map iteration). Per-node errors are collected
// and returned alongside the (possibly partial) success.
func AggregateDumpMap(ctx context.Context, c Client, nodes []string, mapName string, opts DumpOptions, emit func(Entry) error) []NodeError {
	errs := make([]NodeError, 0)
	var emitMu sync.Mutex
	var errMu sync.Mutex
	var wg sync.WaitGroup

	for _, node := range nodes {
		wg.Add(1)
		go func(node string) {
			defer wg.Done()
			err := c.DumpMap(ctx, node, mapName, opts, func(e Entry) error {
				emitMu.Lock()
				defer emitMu.Unlock()
				return emit(e)
			})
			if err != nil {
				errMu.Lock()
				errs = append(errs, NodeError{Node: node, Err: err})
				errMu.Unlock()
			}
		}(node)
	}
	wg.Wait()
	sort.Slice(errs, func(i, j int) bool { return errs[i].Node < errs[j].Node })
	return errs
}

// NodeError pairs a per-node failure with the node it came from.
// Callers render these as warnings rather than fatal errors so a
// partial outage does not mask the data we did manage to fetch.
type NodeError struct {
	Node string
	Err  error
}

// Compile-time assertions.
var _ Client = (*FactoryClient)(nil)
