package dns

import (
	"context"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/1outres/juneau/daemon/internal/daemon/virtservice"
)

type stubVPCResolver struct {
	name          string
	enableService bool
	ok            bool
}

func (s stubVPCResolver) LookupByID(_ context.Context, _ uint32) (string, bool, bool) {
	return s.name, s.enableService, s.ok
}

type captureResponder struct {
	calls [][]byte
}

func (c *captureResponder) WriteResponse(payload []byte) error {
	c.calls = append(c.calls, append([]byte(nil), payload...))
	return nil
}

func packQuery(t *testing.T, name string, qtype dnsmessage.Type, id uint16, edns0 uint16) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			OpCode:           0,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{Name: n, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	if edns0 > 0 {
		// Append a minimal OPT record advertising the buffer size.
		optName, _ := dnsmessage.NewName(".")
		msg.Additionals = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  optName,
				Type:  dnsmessage.TypeOPT,
				Class: dnsmessage.Class(edns0),
				TTL:   0,
			},
			Body: &dnsmessage.OPTResource{},
		}}
	}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return wire
}

func TestHandlerEchoesQueryAndAnswers(t *testing.T) {
	resolver := stubResolver{
		resp: Response{
			RCode:         RCodeNoError,
			Authoritative: true,
			Answers: []Answer{
				{
					Name:  "demo.ns1.svc.cluster.local.",
					Type:  TypeA,
					Class: ClassINET,
					TTL:   30,
					A:     netip.MustParseAddr("10.96.1.5"),
				},
			},
		},
	}
	h := NewHandler(resolver, stubVPCResolver{name: "tenant-a", enableService: true, ok: true})

	wire := packQuery(t, "demo.ns1.svc.cluster.local.", dnsmessage.TypeA, 0xbeef, 0)
	resp := &captureResponder{}
	req := virtservice.PacketRequest{
		Tenant:     virtservice.TenantID{VPCID: 7, SubnetID: 11},
		Service:    virtservice.ServiceIDDNS,
		ClientIP:   netip.MustParseAddr("10.0.0.42"),
		ClientPort: 4711,
		Payload:    wire,
	}
	if err := h.HandlePacket(context.Background(), req, resp); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}
	if len(resp.calls) != 1 {
		t.Fatalf("expected 1 response, got %d", len(resp.calls))
	}

	var p dnsmessage.Parser
	hdr, err := p.Start(resp.calls[0])
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if hdr.ID != 0xbeef {
		t.Errorf("response id = 0x%x, want 0xbeef", hdr.ID)
	}
	if !hdr.Response {
		t.Errorf("QR bit not set")
	}
	if !hdr.Authoritative {
		t.Errorf("AA bit should be set for authoritative cluster zone answer")
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("rcode = %d, want NOERROR", hdr.RCode)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatalf("question: %v", err)
	}
	if q.Name.String() != "demo.ns1.svc.cluster.local." {
		t.Errorf("question name = %q", q.Name.String())
	}
	_ = p.SkipAllQuestions()
	answer, err := p.AnswerHeader()
	if err != nil {
		t.Fatalf("answer header: %v", err)
	}
	if answer.Type != dnsmessage.TypeA {
		t.Errorf("answer type = %d", answer.Type)
	}
	body, err := p.AResource()
	if err != nil {
		t.Fatalf("answer body: %v", err)
	}
	if body.A != [4]byte{10, 96, 1, 5} {
		t.Errorf("answer A = %v", body.A)
	}
}

func TestHandlerServerFailureWhenVPCUnknown(t *testing.T) {
	h := NewHandler(stubResolver{}, stubVPCResolver{ok: false})
	wire := packQuery(t, "demo.ns1.svc.cluster.local.", dnsmessage.TypeA, 0x1234, 0)
	resp := &captureResponder{}
	req := virtservice.PacketRequest{
		Tenant:  virtservice.TenantID{VPCID: 9999},
		Payload: wire,
	}
	if err := h.HandlePacket(context.Background(), req, resp); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}
	if len(resp.calls) != 1 {
		t.Fatalf("expected 1 response, got %d", len(resp.calls))
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(resp.calls[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("rcode = %d, want SERVFAIL", hdr.RCode)
	}
}

func TestHandlerTruncatesOversizedResponse(t *testing.T) {
	// Build a resolver that returns far more A records than fit in 512 bytes.
	answers := make([]Answer, 100)
	for i := range answers {
		answers[i] = Answer{
			Name:  "demo.ns1.svc.cluster.local.",
			Type:  TypeA,
			Class: ClassINET,
			TTL:   30,
			A:     netip.AddrFrom4([4]byte{10, 96, 1, byte(i)}),
		}
	}
	h := NewHandler(stubResolver{
		resp: Response{RCode: RCodeNoError, Answers: answers, Authoritative: true},
	}, stubVPCResolver{name: "tenant-a", enableService: true, ok: true})

	wire := packQuery(t, "demo.ns1.svc.cluster.local.", dnsmessage.TypeA, 1, 0)
	resp := &captureResponder{}
	if err := h.HandlePacket(context.Background(), virtservice.PacketRequest{
		Tenant:  virtservice.TenantID{VPCID: 1, SubnetID: 1},
		Payload: wire,
	}, resp); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	var p dnsmessage.Parser
	hdr, err := p.Start(resp.calls[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !hdr.Truncated {
		t.Errorf("expected TC bit set when response > 512 bytes")
	}
	if len(resp.calls[0]) > 512 {
		t.Errorf("truncated response should be ≤512 bytes (no EDNS0), got %d", len(resp.calls[0]))
	}
}
