package grpc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/trace"
	"github.com/1outres/juneau/daemon/pkg/debugpb"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// DebugServer implements the operator-facing debug RPC. It bridges
// kubectl-juneau to the daemon's in-process trace bus and BPF map
// programmer; lifecycle is owned by Server.
//
// All methods are safe for concurrent use; the underlying Bus
// serialises subscriber bookkeeping internally.
type DebugServer struct {
	debugpb.UnimplementedDebugServer

	bus      *trace.Bus
	store    *trace.Store
	nodeName string

	// snapshotMu guards the per-trace-id event ringbuffer used by
	// GetTraceSnapshot. Snapshots are sized small (< 1k events per
	// session) so a mutex-guarded slice is plenty fast.
	snapshotMu      sync.Mutex
	snapshotByID    map[uint32]*snapshotBuffer
	snapshotEnabled bool
	snapshotCancel  context.CancelFunc
	snapshotCap     int
}

// snapshotBuffer is a fixed-capacity ring of recent events kept per
// trace_id so GetTraceSnapshot can answer kubectl queries that arrive
// after the first events were already published.
type snapshotBuffer struct {
	events  []trace.Event
	dropped uint64
	cap     int
}

// NewDebugServer wires the debug RPC to the daemon's trace plane.
// snapshotCap bounds the per-session backlog; 0 disables the
// snapshot ring entirely (GetTraceSnapshot returns an empty event
// list — the live stream is the source of truth).
func NewDebugServer(bus *trace.Bus, store *trace.Store, nodeName string, snapshotCap int) *DebugServer {
	d := &DebugServer{
		bus:          bus,
		store:        store,
		nodeName:     nodeName,
		snapshotByID: make(map[uint32]*snapshotBuffer),
		snapshotCap:  snapshotCap,
	}
	if snapshotCap > 0 {
		d.snapshotEnabled = true
	}
	return d
}

// Start runs the snapshot collector. Idempotent — calling Start more
// than once is a no-op. The collector subscribes to the bus and
// folds every event into the per-trace-id ring; clients that connect
// late get the buffered prefix via GetTraceSnapshot.
func (d *DebugServer) Start(ctx context.Context) {
	if !d.snapshotEnabled {
		return
	}
	d.snapshotMu.Lock()
	if d.snapshotCancel != nil {
		d.snapshotMu.Unlock()
		return
	}
	collectorCtx, cancel := context.WithCancel(ctx)
	d.snapshotCancel = cancel
	d.snapshotMu.Unlock()

	sub := d.bus.Subscribe(nil, 1024)
	go func() {
		defer sub.Close()
		for {
			select {
			case <-collectorCtx.Done():
				return
			case ev, ok := <-sub.Channel():
				if !ok {
					return
				}
				d.recordSnapshot(ev)
			}
		}
	}()
}

// Stop tears down the snapshot collector.
func (d *DebugServer) Stop() {
	d.snapshotMu.Lock()
	if d.snapshotCancel != nil {
		d.snapshotCancel()
		d.snapshotCancel = nil
	}
	d.snapshotMu.Unlock()
}

func (d *DebugServer) recordSnapshot(ev trace.Event) {
	d.snapshotMu.Lock()
	defer d.snapshotMu.Unlock()
	buf, ok := d.snapshotByID[ev.TraceID]
	if !ok {
		buf = &snapshotBuffer{cap: d.snapshotCap}
		d.snapshotByID[ev.TraceID] = buf
	}
	if len(buf.events) >= buf.cap {
		// Drop oldest; preserve recency. Track drops so kubectl
		// surfaces the omission honestly.
		buf.events = append(buf.events[1:], ev)
		buf.dropped++
		return
	}
	buf.events = append(buf.events, ev)
}

// WatchTrace streams matching events to the client until the stream
// is cancelled. Empty trace_ids selects every event; daemons may cap
// concurrent unbounded subscribers in production.
func (d *DebugServer) WatchTrace(req *debugpb.WatchTraceRequest, srv debugpb.Debug_WatchTraceServer) error {
	if d.bus == nil {
		return status.Error(codes.FailedPrecondition, "trace bus not available")
	}
	bufSize := int(req.BufferHint)
	if bufSize <= 0 {
		bufSize = 256
	}
	sub := d.bus.Subscribe(req.TraceIds, bufSize)
	defer sub.Close()

	ctx := srv.Context()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-sub.Channel():
			if !ok {
				return nil
			}
			if err := srv.Send(traceEventToProto(ev, d.nodeName)); err != nil {
				return err
			}
		}
	}
}

// GetTraceSnapshot returns the buffered prefix for one session.
func (d *DebugServer) GetTraceSnapshot(_ context.Context, req *debugpb.GetTraceSnapshotRequest) (*debugpb.TraceSnapshot, error) {
	if req.TraceId == 0 {
		return nil, status.Error(codes.InvalidArgument, "traceID must be non-zero")
	}
	d.snapshotMu.Lock()
	buf := d.snapshotByID[req.TraceId]
	var events []trace.Event
	var dropped uint64
	if buf != nil {
		events = append(events, buf.events...)
		dropped = buf.dropped
	}
	d.snapshotMu.Unlock()

	out := &debugpb.TraceSnapshot{
		TraceId:       req.TraceId,
		NodeName:      d.nodeName,
		DroppedEvents: dropped,
	}
	for _, ev := range events {
		out.RecentEvents = append(out.RecentEvents, traceEventToProto(ev, d.nodeName))
	}
	return out, nil
}

// LearnTuple installs a translated tuple on this node. Used by
// kubectl to mirror tuples it learns from one daemon over to peers
// whose dataplane may also see the post-NAT continuation.
func (d *DebugServer) LearnTuple(_ context.Context, req *debugpb.LearnTupleRequest) (*emptypb.Empty, error) {
	if d.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "trace store not available")
	}
	if req.TraceId == 0 || req.Tuple == nil {
		return nil, status.Error(codes.InvalidArgument, "traceID and tuple are required")
	}
	key, err := tupleFromProto(req.Tuple)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "tuple: %v", err)
	}
	if err := d.store.LearnTuple(req.TraceId, key); err != nil {
		return nil, status.Errorf(codes.Internal, "learn tuple: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// InjectProbe is a placeholder. Active probe support is gated behind
// a daemon-side capability advertisement; until that lands kubectl
// uses INJECT_PROBE_STRATEGY_POD_EXEC and never reaches this RPC.
func (d *DebugServer) InjectProbe(_ context.Context, req *debugpb.InjectProbeRequest) (*debugpb.InjectProbeResponse, error) {
	if req.Strategy == debugpb.InjectProbeStrategy_INJECT_PROBE_STRATEGY_POD_EXEC {
		return nil, status.Error(codes.Unimplemented, "pod-exec is driven by kubectl, not the daemon")
	}
	zap.S().Warnw("trace: InjectProbe not implemented", "strategy", req.Strategy.String())
	return nil, status.Error(codes.Unimplemented, "InjectProbe is not implemented in this build")
}

// ---- Conversion helpers ---------------------------------------------

func traceEventToProto(ev trace.Event, nodeName string) *debugpb.TraceEvent {
	out := &debugpb.TraceEvent{
		TraceId:     ev.TraceID,
		Reason:      reasonToProto(ev.Reason),
		Hook:        hookToProto(ev.Hook),
		NodeName:    nodeName,
		Ifindex:     ev.Ifindex,
		VpcId:       ev.VPCID,
		SubnetId:    ev.SubnetID,
		MonotonicNs: uint64(ev.At),
		ReceivedNs:  uint64(ev.ReceivedAt.UnixNano()),
		Protocol:    protoToProto(ev.Protocol),
		Verdict:     verdictToProto(ev.Verdict),
		Scope:       scopeToProto(ev.Scope),
		SrcIp:       cloneIP(ev.SrcIP),
		DstIp:       cloneIP(ev.DstIP),
		SrcPort:     uint32(ev.SrcPort),
		DstPort:     uint32(ev.DstPort),
		HasAuxTuple: ev.HasAux,
		Aux1:        ev.Aux1,
		Aux2:        ev.Aux2,
	}
	if ev.HasAux {
		out.AuxSrcIp = cloneIP(ev.AuxSrc)
		out.AuxDstIp = cloneIP(ev.AuxDst)
		out.AuxSrcPort = uint32(ev.AuxSrcP)
		out.AuxDstPort = uint32(ev.AuxDstP)
	}
	return out
}

func cloneIP(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func tupleFromProto(t *debugpb.TraceTuple) (trace.TupleKey, error) {
	if len(t.SrcIp) != 4 || len(t.DstIp) != 4 {
		return trace.TupleKey{}, errors.New("expected IPv4 (4-byte) src/dst")
	}
	scope := trace.ScopeHost
	if t.Scope == debugpb.TupleScope_TUPLE_SCOPE_VPC {
		scope = trace.ScopeVPC
	}
	var src, dst [4]byte
	copy(src[:], t.SrcIp)
	copy(dst[:], t.DstIp)
	return trace.TupleKey{
		Scope:    scope,
		Protocol: protoFromProto(t.Protocol),
		VPCID:    t.VpcId,
		SrcIP:    src,
		DstIP:    dst,
		SrcPort:  uint16(t.SrcPort),
		DstPort:  uint16(t.DstPort),
	}, nil
}

func protoFromProto(p debugpb.TraceProtocol) uint8 {
	switch p {
	case debugpb.TraceProtocol_TRACE_PROTOCOL_TCP:
		return 6
	case debugpb.TraceProtocol_TRACE_PROTOCOL_UDP:
		return 17
	case debugpb.TraceProtocol_TRACE_PROTOCOL_ICMP:
		return 1
	}
	return 0
}

func protoToProto(p uint8) debugpb.TraceProtocol {
	switch p {
	case 6:
		return debugpb.TraceProtocol_TRACE_PROTOCOL_TCP
	case 17:
		return debugpb.TraceProtocol_TRACE_PROTOCOL_UDP
	case 1:
		return debugpb.TraceProtocol_TRACE_PROTOCOL_ICMP
	}
	return debugpb.TraceProtocol_TRACE_PROTOCOL_UNSPECIFIED
}

func reasonToProto(r trace.Reason) debugpb.TraceEventReason {
	return debugpb.TraceEventReason(r)
}

func hookToProto(h trace.Hook) debugpb.TraceHook {
	return debugpb.TraceHook(h)
}

func verdictToProto(v trace.Verdict) debugpb.TraceVerdict {
	switch v {
	case trace.VerdictOK:
		return debugpb.TraceVerdict_TRACE_VERDICT_OK
	case trace.VerdictDrop:
		return debugpb.TraceVerdict_TRACE_VERDICT_DROP
	case trace.VerdictRedirect:
		return debugpb.TraceVerdict_TRACE_VERDICT_REDIRECT
	}
	return debugpb.TraceVerdict_TRACE_VERDICT_UNSPECIFIED
}

func scopeToProto(s trace.Scope) debugpb.TupleScope {
	if s == trace.ScopeVPC {
		return debugpb.TupleScope_TUPLE_SCOPE_VPC
	}
	return debugpb.TupleScope_TUPLE_SCOPE_HOST
}

// SnapshotEvictTimer is exposed so callers can short-circuit the
// per-session backlog from outside (e.g. on session expiry). Returns
// the number of events that were dropped from the buffer so callers
// can surface the count as a diagnostic.
func (d *DebugServer) SnapshotEvictTimer(traceID uint32) (uint64, error) {
	if !d.snapshotEnabled {
		return 0, nil
	}
	if traceID == 0 {
		return 0, fmt.Errorf("traceID must be non-zero")
	}
	d.snapshotMu.Lock()
	defer d.snapshotMu.Unlock()
	buf, ok := d.snapshotByID[traceID]
	if !ok {
		return 0, nil
	}
	delete(d.snapshotByID, traceID)
	return buf.dropped, nil
}

// startSnapshotEvictor expires session backlogs that have outlived
// their session by `ttl`. Defensive: prevents memory growth when
// kubectl crashes mid-stream and the session CRD is later cleaned up
// without anyone draining the snapshot.
func (d *DebugServer) startSnapshotEvictor(ctx context.Context, ttl time.Duration) {
	if !d.snapshotEnabled {
		return
	}
	go func() {
		t := time.NewTicker(ttl)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				active := make(map[uint32]struct{})
				for _, id := range d.store.ActiveTraceIDs() {
					active[id] = struct{}{}
				}
				d.snapshotMu.Lock()
				for id := range d.snapshotByID {
					if _, ok := active[id]; !ok {
						delete(d.snapshotByID, id)
					}
				}
				d.snapshotMu.Unlock()
			}
		}
	}()
}
