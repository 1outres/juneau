package trace

import (
	"context"
	"strings"
	"testing"
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
