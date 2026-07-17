package trace

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
)

func TestAttachStreamsReturnsErrorWhenAllNodesFail(t *testing.T) {
	// fakeFactory.NodeAgent returns ErrNotImplemented for every node,
	// matching a cluster where RBAC / connectivity blocks every dial.
	// attachStreams must surface that as an error so Run exits
	// non-zero instead of waiting out the timeout silently.
	o := &Options{Factory: &fakeFactory{ns: "default"}}
	set, err := o.attachStreams(context.Background(), []string{"node-a", "node-b"}, 1)
	if err == nil {
		set.Close()
		t.Fatalf("expected error when no nodes attach, got nil")
	}
	if !strings.Contains(err.Error(), "failed to attach") {
		t.Fatalf("error should mention attach failure, got %q", err.Error())
	}
}

func TestAttachStreamsReturnsErrorWhenNodesEmpty(t *testing.T) {
	// Defensive: an empty node set is also a usage error (Run guards
	// this upstream, but attachStreams should not silently succeed
	// either).
	o := &Options{Factory: &fakeFactory{ns: "default"}}
	if _, err := o.attachStreams(context.Background(), nil, 1); err == nil {
		t.Fatalf("expected error when no nodes provided")
	}
}

func TestAuxContinuationTuple(t *testing.T) {
	ev := &debugpb.TraceEvent{
		Scope:       debugpb.TupleScope_TUPLE_SCOPE_HOST,
		VpcId:       0,
		Protocol:    debugpb.TraceProtocol_TRACE_PROTOCOL_TCP,
		Direction:   debugpb.TraceDirection_TRACE_DIRECTION_REQUEST,
		HasAuxTuple: true,
		AuxSrcIp:    []byte{10, 0, 1, 5},
		AuxDstIp:    []byte{1, 1, 1, 1},
		AuxSrcPort:  40000,
		AuxDstPort:  80,
	}
	tuple := auxContinuationTuple(ev)

	// Same-leg continuation: aux orientation kept, translated dst port
	// kept, ephemeral src port wildcarded.
	if !bytes.Equal(tuple.SrcIp, ev.AuxSrcIp) || !bytes.Equal(tuple.DstIp, ev.AuxDstIp) {
		t.Errorf("continuation must keep aux orientation: %+v", tuple)
	}
	if tuple.DstPort != 80 || tuple.SrcPort != 0 {
		t.Errorf("continuation ports wrong: src=%d dst=%d", tuple.SrcPort, tuple.DstPort)
	}
	if tuple.Scope != ev.Scope || tuple.Protocol != ev.Protocol || tuple.VpcId != ev.VpcId {
		t.Errorf("continuation must carry scope/proto/vpc: %+v", tuple)
	}
	// The authoritative leg carries over so a reverse-NAT (reply) event
	// relays a Reply-tagged continuation, not a hardcoded Request.
	if tuple.Direction != ev.Direction {
		t.Errorf("continuation must carry the event's leg: got %v want %v", tuple.Direction, ev.Direction)
	}
}
