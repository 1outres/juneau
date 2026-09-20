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
	h := NewTCPHandler(resolver, stubVPCResolver{name: "tenant-a", serviceEnabled: true, consume: true, ok: true})
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

func TestTCPHandlerReturnsCompleteLargeCustomRRSetWithoutEDNS(t *testing.T) {
	zone := readyDNSZone("zone", "tenant-a", "example.com")
	addresses := make([]string, 100)
	want := make(map[netip.Addr]struct{}, len(addresses))
	for i := range addresses {
		address := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		addresses[i] = address.String()
		want[address] = struct{}{}
	}
	record := readyDNSRecord("api", zone.Name, "api", 30, addresses...)
	resolver := NewCustomZone(newCustomDNSClient(t, zone, record), noShuffle)
	h := NewTCPHandler(resolver, stubVPCResolver{name: "tenant-a", ok: true})
	h.IdleTimeout = time.Second

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	go h.handleConn(context.Background(), server, virtservice.TenantID{VPCID: 7, SubnetID: 11})

	query := packQuery(t, "api.example.com.", dnsmessage.TypeA, 0xbeef, 0)
	if err := writeDNSMessage(client, query); err != nil {
		t.Fatalf("write query: %v", err)
	}
	response, err := readDNSMessage(client, 65535)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if len(response) <= 512 {
		t.Fatalf("response length = %d, want more than the UDP default limit", len(response))
	}

	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if message.Truncated {
		t.Fatal("TCP response has TC set")
	}
	if len(message.Answers) != len(addresses) {
		t.Fatalf("answers = %d, want %d", len(message.Answers), len(addresses))
	}
	for _, answer := range message.Answers {
		body, ok := answer.Body.(*dnsmessage.AResource)
		if !ok {
			t.Fatalf("answer body = %T, want A", answer.Body)
		}
		address := netip.AddrFrom4(body.A)
		if _, exists := want[address]; !exists {
			t.Fatalf("unexpected address %s", address)
		}
		delete(want, address)
	}
	if len(want) != 0 {
		t.Fatalf("missing addresses: %v", want)
	}
}

func TestTCPHandlerIdleTimeoutClosesConnection(t *testing.T) {
	h := NewTCPHandler(stubResolver{}, stubVPCResolver{ok: true, name: "x", serviceEnabled: true})
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
