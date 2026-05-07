package reconciler

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/maglev"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// LBOwnerSlotCount is the prime that sizes the Maglev slot table; it
// must equal MAX_LB_OWNER_TABLE in daemon/bpf/maps.h. Exposed as a
// package-level constant so tests and tooling can build matching
// fixtures without hard-coding the literal twice.
const LBOwnerSlotCount uint32 = 4093

// LBOwner keeps the lb_owner_table BPF map in sync with current Node
// membership using Maglev consistent hashing. The map maps a flow-hash
// slot index to the underlay IPv4 (NBO) of the Node responsible for
// that slot's flows. Every Juneau Node holds an identical copy: each
// daemon computes the table independently from the same Node-membership
// snapshot (via NetworkEndpoint informer), so the cluster converges on
// the same answer without inter-Node coordination.
//
// Runs as a singleton: any NWEP add / change / delete fires one
// Reconcile call against runner.SingletonKey, the reconciler lists the
// full Kind=Node NWEP set, recomputes the Maglev table, and diffs
// against the previously-applied table to update only changed slots.
//
// Concurrency: Reconcile is safe to call from a single worker
// goroutine (the Runner contract). Internal state is guarded by `mu`
// so external readers (e.g. metrics endpoints) can safely call
// Snapshot.
type LBOwner struct {
	client    client.Client
	podEgress *program.PodEgress
	slotCount uint32

	// rebuildHook is invoked at the end of every successful
	// Reconcile with the count of slots that changed in this pass.
	// Tests use it to assert diff-based update behaviour without
	// peeking into BPF internals; production callers leave it nil.
	rebuildHook func(slotsChanged int)

	// mapWriter abstracts the BPF map update / read surface so the
	// reconciler is testable without mocking the full
	// program.PodEgress chain. Production code passes a real
	// *ebpf.Map via the constructor; tests pass an in-memory fake.
	mapWriter slotTableWriter

	mu       sync.Mutex
	slots    []uint32 // last applied slot table (NBO IP per slot)
	rebuilds uint64
}

// slotTableWriter is the minimal surface LBOwner needs over the BPF
// lb_owner_table map. Production code passes an adapter around an
// *ebpf.Map; tests pass a fake.
type slotTableWriter interface {
	UpdateSlot(slot uint32, ownerNBO uint32) error
}

// LBOwnerOption configures NewLBOwner. Use the OnRebuild hook to wire
// metrics or test assertions to slot-update events.
type LBOwnerOption func(*LBOwner)

// WithLBOwnerRebuildHook registers fn to be called once per successful
// Reconcile with the count of slots that changed. The hook runs on the
// reconciler's goroutine; long work belongs elsewhere.
func WithLBOwnerRebuildHook(fn func(slotsChanged int)) LBOwnerOption {
	return func(r *LBOwner) {
		r.rebuildHook = fn
	}
}

// WithLBOwnerSlotCount overrides the slot table size. Tests use this
// to keep tables small and assertions cheap; production callers should
// not set it (the default LBOwnerSlotCount mirrors the BPF map's
// MAX_LB_OWNER_TABLE).
func WithLBOwnerSlotCount(m uint32) LBOwnerOption {
	return func(r *LBOwner) {
		r.slotCount = m
	}
}

// NewLBOwner constructs the reconciler bound to the given pod-egress
// program. The lb_owner_table map handle is taken from podEgress.Objs;
// see program/pod_egress.go for how that handle is shared across all
// TC programs via LIBBPF_PIN_BY_NAME.
func NewLBOwner(cl client.Client, podEgress *program.PodEgress, opts ...LBOwnerOption) *LBOwner {
	r := &LBOwner{
		client:    cl,
		podEgress: podEgress,
		slotCount: LBOwnerSlotCount,
	}
	for _, opt := range opts {
		opt(r)
	}
	r.mapWriter = bpfMapSlotWriter{m: r.podEgress.Objs.LbOwnerTable}
	r.slots = make([]uint32, r.slotCount)
	return r
}

// newLBOwnerWithWriter builds an LBOwner around an explicit
// slotTableWriter. Used by unit tests; production callers go through
// NewLBOwner.
func newLBOwnerWithWriter(cl client.Client, w slotTableWriter, slotCount uint32, opts ...LBOwnerOption) *LBOwner {
	r := &LBOwner{
		client:    cl,
		slotCount: slotCount,
	}
	for _, opt := range opts {
		opt(r)
	}
	r.mapWriter = w
	r.slots = make([]uint32, r.slotCount)
	return r
}

func (r *LBOwner) Name() string { return "lb-owner" }

// Reconcile is invoked with runner.SingletonKey on every NWEP event.
// The key is ignored — the desired state depends on the full set of
// Kind=Node NWEPs, not the specific one that fired the event.
func (r *LBOwner) Reconcile(ctx context.Context, _ string) error {
	nodeIPs, err := r.listNodeUnderlayIPs(ctx)
	if err != nil {
		return err
	}

	// Build the new Maglev slot table. NodeID is the dotted-quad form
	// of the underlay IP — a stable, unique identifier per Node and
	// the same value the data plane will store in the slot.
	ids := make([]maglev.NodeID, len(nodeIPs))
	ipByID := make(map[maglev.NodeID]uint32, len(nodeIPs))
	for i, nbo := range nodeIPs {
		id := maglev.NodeID(formatNBO(nbo))
		ids[i] = id
		ipByID[id] = nbo
	}
	tbl := maglev.BuildTable(ids, r.slotCount)

	// Translate slots from NodeID to NBO IPv4 — that's what the BPF
	// map stores. Empty slots (only possible when the Node set is
	// empty) become 0, which lb_resolve_owner already treats as
	// "no owner".
	desired := make([]uint32, r.slotCount)
	for i, owner := range tbl.Slots {
		if owner == maglev.Empty {
			continue
		}
		desired[i] = ipByID[owner]
	}

	// Diff against the previously-applied table and write only the
	// slots that changed. Even on first reconcile this avoids
	// 4093 redundant Update calls when most slots are zero.
	r.mu.Lock()
	defer r.mu.Unlock()

	changed := 0
	for slot, want := range desired {
		if r.slots[slot] == want {
			continue
		}
		s := uint32(slot)
		if err := r.mapWriter.UpdateSlot(s, want); err != nil {
			return fmt.Errorf("update lb_owner_table[%d]: %w", slot, err)
		}
		r.slots[slot] = want
		changed++
	}

	r.rebuilds++
	zap.S().Infow("lb-owner: reconciled", "nodes", len(nodeIPs), "slots_changed", changed, "rebuild", r.rebuilds)
	if r.rebuildHook != nil {
		r.rebuildHook(changed)
	}
	return nil
}

// Snapshot returns a copy of the currently-applied slot table, mostly
// for tests and observability. The returned slice is safe to retain.
func (r *LBOwner) Snapshot() []uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]uint32, len(r.slots))
	copy(out, r.slots)
	return out
}

// listNodeUnderlayIPs returns every Kind=Node NetworkEndpoint's
// underlay IP in network-byte-order uint32, sorted ascending. NWEPs
// without status.nodeIP are skipped — the controller-side reconciler
// will fire another event once it publishes the IP, at which point we
// pick the Node up.
func (r *LBOwner) listNodeUnderlayIPs(ctx context.Context) ([]uint32, error) {
	var nweps juneauv1alpha1.NetworkEndpointList
	if err := r.client.List(ctx, &nweps); err != nil {
		return nil, fmt.Errorf("list NetworkEndpoints: %w", err)
	}
	out := make([]uint32, 0, len(nweps.Items))
	for i := range nweps.Items {
		nwep := &nweps.Items[i]
		if nwep.Spec.Kind != juneauv1alpha1.EndpointKindNode {
			continue
		}
		if nwep.Status.NodeIP == "" {
			continue
		}
		v4 := net.ParseIP(nwep.Status.NodeIP).To4()
		if v4 == nil {
			zap.S().Warnw("lb-owner: skipping NWEP with non-IPv4 nodeIP", "namespace", nwep.Namespace, "name", nwep.Name, "nodeIP", nwep.Status.NodeIP)
			continue
		}
		out = append(out, binary.BigEndian.Uint32(v4))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// formatNBO renders a network-byte-order IPv4 as dotted-quad. We pass
// the dotted-quad string into Maglev (rather than the raw bytes) so
// log lines and trace events carry a human-readable Node identity.
func formatNBO(nbo uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], nbo)
	return net.IP(b[:]).String()
}

// bpfMapSlotWriter adapts an *ebpf.Map to slotTableWriter.
type bpfMapSlotWriter struct {
	m *ebpf.Map
}

func (w bpfMapSlotWriter) UpdateSlot(slot uint32, ownerNBO uint32) error {
	return w.m.Update(&slot, &ownerNBO, ebpf.UpdateAny)
}
