package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
)

// UpstreamForwarder relays queries the cluster zone declined to a
// configured upstream resolver. We re-encode the query (verbatim
// question, fresh ID) onto a new UDP socket, copy the answer back, and
// translate the wire response into our Resolver shape so the wrapping
// chain can wrap it consistently with internal answers.
//
// Upstream selection is round-robin across the configured servers.
// First success wins.
type UpstreamForwarder struct {
	servers []netConn
	timeout time.Duration
}

type netConn struct {
	addr string // "host:port"
}

// NewUpstreamForwarder constructs a forwarder pointed at the given
// host:port endpoints. Returns nil + error when no servers are
// configured; callers should treat that as "internal-only resolver".
func NewUpstreamForwarder(servers []string, timeout time.Duration) (*UpstreamForwarder, error) {
	if len(servers) == 0 {
		return nil, errors.New("dns: at least one upstream server required")
	}
	if timeout <= 0 {
		timeout = DefaultUpstreamTimeout
	}
	conns := make([]netConn, 0, len(servers))
	for _, s := range servers {
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			// Allow plain "1.2.3.4" to default to :53.
			if !strings.Contains(s, ":") {
				host = s
				port = "53"
			} else {
				return nil, fmt.Errorf("parse upstream %q: %w", s, err)
			}
		}
		conns = append(conns, netConn{addr: net.JoinHostPort(host, port)})
	}
	return &UpstreamForwarder{servers: conns, timeout: timeout}, nil
}

// Resolve forwards q to the first upstream that answers within
// timeout. Returns ErrNotInZone-style behaviour is not appropriate
// here — the caller (chain) decides whether to fall back further.
func (f *UpstreamForwarder) Resolve(ctx context.Context, q Query) (Response, error) {
	wire, err := encodeOutboundQuery(q)
	if err != nil {
		return Response{}, fmt.Errorf("encode upstream query: %w", err)
	}

	deadline := time.Now().Add(f.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	var lastErr error
	for _, srv := range f.servers {
		resp, err := f.queryOne(ctx, srv.addr, wire, deadline)
		if err != nil {
			zap.S().Debugf("dns: upstream %s failed: %v", srv.addr, err)
			lastErr = err
			continue
		}
		return decodeUpstreamResponse(resp, q)
	}
	if lastErr != nil {
		return Response{RCode: RCodeServerFailure}, lastErr
	}
	return Response{RCode: RCodeServerFailure}, errors.New("dns: all upstreams failed")
}

func (f *UpstreamForwarder) queryOne(ctx context.Context, addr string, wire []byte, deadline time.Time) ([]byte, error) {
	d := net.Dialer{Timeout: f.timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// encodeOutboundQuery synthesises a fresh DNS query bound for an
// upstream resolver. We deliberately mint a new ID so concurrent
// queries on the same socket can't collide; the answer's id is
// matched at decode time.
func encodeOutboundQuery(q Query) ([]byte, error) {
	name, err := dnsmessage.NewName(q.Name)
	if err != nil {
		return nil, fmt.Errorf("name %q: %w", q.Name, err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               uint16(time.Now().UnixNano()),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.Type(q.Type),
			Class: dnsmessage.Class(q.Class),
		}},
	}
	return msg.Pack()
}

// decodeUpstreamResponse translates the upstream's wire answer into
// our Response shape. We surface the upstream's RCode + answers
// verbatim; the caller does its own truncation / TTL clamping at the
// wire layer.
func decodeUpstreamResponse(wire []byte, q Query) (Response, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(wire)
	if err != nil {
		return Response{RCode: RCodeServerFailure}, fmt.Errorf("upstream parse header: %w", err)
	}
	if !hdr.Response {
		return Response{RCode: RCodeServerFailure}, errors.New("upstream did not set QR")
	}

	if err := p.SkipAllQuestions(); err != nil {
		return Response{RCode: RCodeServerFailure}, fmt.Errorf("skip questions: %w", err)
	}

	res := Response{RCode: RCode(hdr.RCode), Authoritative: false}
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if rh.Class != dnsmessage.ClassINET {
			if err := p.SkipAnswer(); err != nil {
				break
			}
			continue
		}
		switch rh.Type {
		case dnsmessage.TypeA:
			body, err := p.AResource()
			if err != nil {
				return Response{RCode: RCodeServerFailure}, fmt.Errorf("upstream A body: %w", err)
			}
			res.Answers = append(res.Answers, Answer{
				Name:  rh.Name.String(),
				Type:  TypeA,
				Class: ClassINET,
				TTL:   rh.TTL,
				A:     netip.AddrFrom4(body.A),
			})
		case dnsmessage.TypeCNAME:
			body, err := p.CNAMEResource()
			if err != nil {
				return Response{RCode: RCodeServerFailure}, fmt.Errorf("upstream CNAME body: %w", err)
			}
			res.Answers = append(res.Answers, Answer{
				Name:  rh.Name.String(),
				Type:  TypeCNAME,
				Class: ClassINET,
				TTL:   rh.TTL,
				CNAME: body.CNAME.String(),
			})
		default:
			if err := p.SkipAnswer(); err != nil {
				return Response{RCode: RCodeServerFailure}, fmt.Errorf("upstream skip answer: %w", err)
			}
		}
	}
	return res, nil
}
