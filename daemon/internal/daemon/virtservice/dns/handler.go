package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/1outres/juneau/daemon/internal/daemon/virtservice"
)

// VPCResolver maps a numeric VPC ID (the value the BPF flow map records)
// back to the Vpc.metadata.name + Vpc.spec.enableService that resolvers
// need to apply policy. The handler keeps this on the dependency
// boundary so we can fake it in tests without instantiating informers.
type VPCResolver interface {
	// LookupByID returns (name, enableService, ok). ok==false means
	// "no Vpc with this ID is currently in cache" — the handler
	// answers ServerFailure in that case rather than guess.
	LookupByID(ctx context.Context, vpcID uint32) (name string, enableService bool, ok bool)
}

// Handler glues the packet plane PacketHandler interface to a Resolver.
// One instance is shared across every (Subnet × UDP/53) binding
// the DNS service registers.
type Handler struct {
	resolver Resolver
	vpcs     VPCResolver
	// MaxResponseBytes caps the wire size of UDP responses. When the
	// resolver returns more than this, the handler truncates and
	// sets the TC bit, prompting the client to retry over TCP.
	// Defaults to the EDNS0 buffer size advertised by the client,
	// or 512 (RFC 1035) when none was advertised.
	MaxResponseBytes int
}

// NewHandler constructs a UDP DNS handler over the supplied resolver
// and VPC resolver.
func NewHandler(resolver Resolver, vpcs VPCResolver) *Handler {
	return &Handler{resolver: resolver, vpcs: vpcs}
}

// HandlePacket implements virtservice.PacketHandler. It is invoked
// once per inbound UDP datagram on every (Subnet × DNS VIP) binding.
func (h *Handler) HandlePacket(ctx context.Context, req virtservice.PacketRequest, resp virtservice.Responder) error {
	if h == nil || h.resolver == nil {
		return errors.New("dns: handler not initialised")
	}

	parsed, err := h.parseQuery(req)
	if err != nil {
		// Best-effort: send back a FORMERR with the same id so the
		// resolver doesn't time out. If we can't even parse the id,
		// drop silently (the client will retry).
		zap.S().Debugf("dns: parse error for tenant=%+v: %v", req.Tenant, err)
		if msg, mkErr := h.makeErrorResponse(req.Payload, dnsmessage.RCodeFormatError); mkErr == nil {
			_ = resp.WriteResponse(msg)
		}
		return nil
	}

	vpcName, enableService, ok := h.vpcs.LookupByID(ctx, req.Tenant.VPCID)
	if !ok {
		zap.S().Warnf("dns: unknown VPC id=%d (tenant=%+v); answering ServerFailure", req.Tenant.VPCID, req.Tenant)
		return h.writeRCode(resp, parsed, dnsmessage.RCodeServerFailure)
	}

	q := Query{
		Name:                parsed.questionName,
		Type:                parsed.questionType,
		Class:               parsed.questionClass,
		CallerVPC:           vpcName,
		CallerEnableService: enableService,
		CallerIP:            req.ClientIP,
	}

	res, err := h.resolver.Resolve(ctx, q)
	if err != nil {
		zap.S().Warnf("dns: resolver error for %s: %v", q.Name, err)
		return h.writeRCode(resp, parsed, dnsmessage.RCodeServerFailure)
	}

	wire, err := h.encodeResponse(parsed, res)
	if err != nil {
		zap.S().Warnf("dns: encode error for %s: %v", q.Name, err)
		return h.writeRCode(resp, parsed, dnsmessage.RCodeServerFailure)
	}
	return resp.WriteResponse(wire)
}

// parsedQuery holds the bits of the inbound DNS message the encoder
// needs to echo back (id, opcode, RD bit, original question section).
type parsedQuery struct {
	id              uint16
	opcode          dnsmessage.OpCode
	rd              bool
	question        dnsmessage.Question
	questionName    string
	questionType    QueryType
	questionClass   QueryClass

	// EDNS0 buffer size advertised by the client (0 if no OPT record).
	udpBufSize uint16
}

func (h *Handler) parseQuery(req virtservice.PacketRequest) (parsedQuery, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(req.Payload)
	if err != nil {
		return parsedQuery{}, fmt.Errorf("parse header: %w", err)
	}
	if hdr.Response {
		return parsedQuery{}, errors.New("not a query (QR=1)")
	}

	q, err := p.Question()
	if err != nil {
		return parsedQuery{}, fmt.Errorf("parse question: %w", err)
	}
	// Skip remaining questions; we only honour the first as the
	// stdlib client and most resolvers do.
	if err := p.SkipAllQuestions(); err != nil {
		return parsedQuery{}, fmt.Errorf("skip questions: %w", err)
	}

	parsed := parsedQuery{
		id:              hdr.ID,
		opcode:          hdr.OpCode,
		rd:              hdr.RecursionDesired,
		question:        q,
		questionName:    strings.ToLower(q.Name.String()),
		questionType:    QueryType(q.Type),
		questionClass:   QueryClass(q.Class),
	}

	// Walk the additional section to find an OPT record carrying the
	// EDNS0 buffer size.
	if err := p.SkipAllAnswers(); err != nil {
		return parsed, nil // best-effort; ignore missing sections
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return parsed, nil
	}
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		if rh.Type == dnsmessage.TypeOPT {
			parsed.udpBufSize = uint16(rh.Class)
			if parsed.udpBufSize < 512 {
				parsed.udpBufSize = 512 // RFC 6891 floor
			}
		}
		if err := p.SkipAdditional(); err != nil {
			break
		}
	}
	return parsed, nil
}

func (h *Handler) writeRCode(resp virtservice.Responder, parsed parsedQuery, rcode dnsmessage.RCode) error {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 parsed.id,
			Response:           true,
			OpCode:             parsed.opcode,
			RecursionDesired:   parsed.rd,
			RecursionAvailable: true,
			RCode:              rcode,
		},
		Questions: []dnsmessage.Question{parsed.question},
	}
	wire, err := msg.Pack()
	if err != nil {
		return err
	}
	return resp.WriteResponse(wire)
}

// makeErrorResponse builds a minimal error response when even the
// query is unparseable beyond the header. Carries only the inbound
// id so the client's resolver library can correlate.
func (h *Handler) makeErrorResponse(query []byte, rcode dnsmessage.RCode) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("query too short for error response")
	}
	hdr := dnsmessage.Header{
		ID:       uint16(query[0])<<8 | uint16(query[1]),
		Response: true,
		RCode:    rcode,
	}
	msg := dnsmessage.Message{Header: hdr}
	return msg.Pack()
}

// encodeResponse produces the wire bytes for a Response. Truncates
// (and sets TC) when the encoded message exceeds the EDNS0 buffer or
// the default 512-byte UDP limit.
func (h *Handler) encodeResponse(parsed parsedQuery, res Response) ([]byte, error) {
	maxBytes := int(parsed.udpBufSize)
	if maxBytes == 0 {
		maxBytes = 512
	}
	if h.MaxResponseBytes > 0 && (maxBytes == 0 || h.MaxResponseBytes < maxBytes) {
		maxBytes = h.MaxResponseBytes
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 parsed.id,
			Response:           true,
			OpCode:             parsed.opcode,
			Authoritative:      res.Authoritative,
			RecursionDesired:   parsed.rd,
			RecursionAvailable: true,
			RCode:              dnsmessage.RCode(res.RCode),
		},
		Questions: []dnsmessage.Question{parsed.question},
	}

	for _, ans := range res.Answers {
		rr, err := buildResource(ans)
		if err != nil {
			return nil, fmt.Errorf("encode answer: %w", err)
		}
		msg.Answers = append(msg.Answers, rr)
	}

	wire, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	if len(wire) > maxBytes {
		// RFC 1035 §4.1.1: truncate to fit; clients will retry over
		// TCP. We keep the question section so the client can
		// correlate, and drop all answers; clients implementing
		// EDNS0 know to retry.
		msg.Header.Truncated = true
		msg.Answers = nil
		wire, err = msg.Pack()
		if err != nil {
			return nil, err
		}
	}
	return wire, nil
}

func buildResource(ans Answer) (dnsmessage.Resource, error) {
	name, err := dnsmessage.NewName(ans.Name)
	if err != nil {
		return dnsmessage.Resource{}, fmt.Errorf("name %q: %w", ans.Name, err)
	}
	hdr := dnsmessage.ResourceHeader{
		Name:  name,
		Type:  dnsmessage.Type(ans.Type),
		Class: dnsmessage.Class(ans.Class),
		TTL:   ans.TTL,
	}
	switch ans.Type {
	case TypeA:
		if !ans.A.Is4() {
			return dnsmessage.Resource{}, fmt.Errorf("A record needs IPv4, got %s", ans.A)
		}
		ip := ans.A.As4()
		return dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: ip}}, nil
	case TypeCNAME:
		cname, err := dnsmessage.NewName(ans.CNAME)
		if err != nil {
			return dnsmessage.Resource{}, fmt.Errorf("cname %q: %w", ans.CNAME, err)
		}
		return dnsmessage.Resource{Header: hdr, Body: &dnsmessage.CNAMEResource{CNAME: cname}}, nil
	case TypePTR:
		ptr, err := dnsmessage.NewName(ans.PTR)
		if err != nil {
			return dnsmessage.Resource{}, fmt.Errorf("ptr %q: %w", ans.PTR, err)
		}
		return dnsmessage.Resource{Header: hdr, Body: &dnsmessage.PTRResource{PTR: ptr}}, nil
	default:
		return dnsmessage.Resource{}, fmt.Errorf("unsupported answer type %d", ans.Type)
	}
}
