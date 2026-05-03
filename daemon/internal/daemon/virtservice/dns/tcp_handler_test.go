package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/1outres/juneau/daemon/internal/daemon/virtservice"
)

// TestTCPHandlerRoundTrip stands up the TCPHandler against an in-memory
// net.Pipe, sends a length-prefixed DNS query, and reads back the
// length-prefixed response. Exercises framing + handler reuse without
// pulling in gVisor.
func TestTCPHandlerRoundTrip(t *testing.T) {
	resolver := stubResolver{
		resp: Response{
			RCode:         RCodeNoError,
			Authoritative: true,
			Answers: []Answer{{
				Name:  "demo.ns1.svc.cluster.local.",
				Type:  TypeA,
				Class: ClassINET,
				TTL:   30,
				A:     netip.MustParseAddr("10.96.1.5"),
			}},
		},
	}
	h := NewTCPHandler(resolver, stubVPCResolver{name: "tenant-a", enableService: true, ok: true})
	h.IdleTimeout = 200 * time.Millisecond

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	go h.handleConn(context.Background(), server, virtservice.TenantID{VPCID: 7, SubnetID: 11})

	// Send query.
	wire := packQuery(t, "demo.ns1.svc.cluster.local.", dnsmessage.TypeA, 0xfeed, 0)
	out := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(wire)))
	copy(out[2:], wire)
	if _, err := client.Write(out); err != nil {
		t.Fatalf("write query: %v", err)
	}

	// Read response.
	var lenBuf [2]byte
	if _, err := io.ReadFull(client, lenBuf[:]); err != nil {
		t.Fatalf("read length: %v", err)
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen == 0 || respLen > 2048 {
		t.Fatalf("bad response length %d", respLen)
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(client, respBuf); err != nil {
		t.Fatalf("read response: %v", err)
	}

	var p dnsmessage.Parser
	hdr, err := p.Start(respBuf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hdr.ID != 0xfeed {
		t.Errorf("response id = 0x%x, want 0xfeed", hdr.ID)
	}
	if !hdr.Response {
		t.Errorf("QR not set")
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("rcode = %d, want NOERROR", hdr.RCode)
	}
}

// TestTCPHandlerIdleTimeoutClosesConnection ensures the connection is
// closed when the client doesn't send anything within IdleTimeout.
func TestTCPHandlerIdleTimeoutClosesConnection(t *testing.T) {
	h := NewTCPHandler(stubResolver{}, stubVPCResolver{ok: true, name: "x", enableService: true})
	h.IdleTimeout = 50 * time.Millisecond

	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.handleConn(context.Background(), server, virtservice.TenantID{})
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleConn did not return after idle timeout")
	}
}
