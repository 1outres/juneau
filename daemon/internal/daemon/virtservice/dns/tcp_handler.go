package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"go.uber.org/zap"

	"github.com/1outres/juneau/daemon/internal/daemon/virtservice"
)

// TCPHandler is the DNS-over-TCP companion to Handler. The packet
// plane terminates UDP/53 directly; TCP/53 lands here via the gVisor
// netstack listener bound by the Registry. Each accepted connection
// reads one or more RFC 1035 §4.2.2 length-prefixed messages, runs
// each through the same Resolver chain as the UDP path, and writes
// length-prefixed responses back.
//
// Tenant identity comes from the listener (one per (vpc, subnet)
// binding) rather than the BPF flow_map; the accept loop carries
// TenantID into HandleConn via its context. The vpc resolver is still
// consulted to populate Vpc.spec.enableService at handler-call time
// because that bit can flip without the binding changing.
type TCPHandler struct {
	resolver Resolver
	vpcs     VPCResolver

	// IdleTimeout caps how long we wait for the next message on an
	// established connection. RFC 7766 recommends ≤30s for DNS-over-TCP;
	// we lean shorter to release netstack memory faster on idle clients.
	IdleTimeout time.Duration

	// MaxMessageBytes caps a single inbound DNS message size; RFC
	// 1035 §4.2.1 limits to 65535 bytes (the 2-byte length prefix
	// is uint16). Messages larger than this are treated as protocol
	// errors and the connection is dropped.
	MaxMessageBytes int
}

// NewTCPHandler builds a handler over the same Resolver / VPCResolver
// as the UDP path. Defaults: 8s idle timeout, 65535 byte message cap.
func NewTCPHandler(resolver Resolver, vpcs VPCResolver) *TCPHandler {
	return &TCPHandler{
		resolver:        resolver,
		vpcs:            vpcs,
		IdleTimeout:     8 * time.Second,
		MaxMessageBytes: 65535,
	}
}

// AcceptLoop runs until ctx is cancelled or the listener closes.
// Spawns one goroutine per accepted connection so a slow upstream
// query for one client can't block another.
func (h *TCPHandler) AcceptLoop(ctx context.Context, l net.Listener, tenant virtservice.TenantID) {
	// Watch for ctx cancellation by closing the listener; gonet
	// listeners surface that as ErrClosed from Accept.
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			zap.S().Warnf("dns: TCP accept error: %v", err)
			return
		}
		go h.handleConn(ctx, conn, tenant)
	}
}

func (h *TCPHandler) handleConn(ctx context.Context, conn net.Conn, tenant virtservice.TenantID) {
	defer func() { _ = conn.Close() }()

	clientIP, clientPort := splitTCPAddr(conn.RemoteAddr())
	for {
		if err := conn.SetReadDeadline(time.Now().Add(h.IdleTimeout)); err != nil {
			return
		}
		query, err := readDNSMessage(conn, h.MaxMessageBytes)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				zap.S().Debugf("dns: TCP read error from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}

		response, ok := h.resolveOnce(ctx, tenant, clientIP, clientPort, query)
		if !ok {
			return
		}
		if err := writeDNSMessage(conn, response); err != nil {
			zap.S().Debugf("dns: TCP write error to %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
}

// resolveOnce runs the same parse → policy → resolve → encode flow
// the UDP handler uses, but never truncates: TCP responses are size-
// limited only by the 16-bit length prefix.
func (h *TCPHandler) resolveOnce(ctx context.Context, tenant virtservice.TenantID, clientIP netip.Addr, clientPort uint16, query []byte) ([]byte, bool) {
	udp := &Handler{
		resolver:         h.resolver,
		vpcs:             h.vpcs,
		MaxResponseBytes: 65535, // TCP cap
	}
	cap := &captureResponderTCP{}
	req := virtservice.PacketRequest{
		Tenant:     tenant,
		Service:    virtservice.ServiceIDDNS,
		ClientIP:   clientIP,
		ClientPort: clientPort,
		Payload:    query,
	}
	if err := udp.HandlePacket(ctx, req, cap); err != nil {
		return nil, false
	}
	if cap.body == nil {
		return nil, false
	}
	return cap.body, true
}

// captureResponderTCP collects the wire-format response written by the
// shared Handler so the TCP path can length-prefix it.
type captureResponderTCP struct {
	body []byte
}

func (c *captureResponderTCP) WriteResponse(payload []byte) error {
	c.body = append([]byte(nil), payload...)
	return nil
}

func readDNSMessage(r net.Conn, maxBytes int) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 {
		return nil, errors.New("dns: zero-length TCP message")
	}
	if maxBytes > 0 && n > maxBytes {
		return nil, errors.New("dns: TCP message exceeds size cap")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeDNSMessage(w net.Conn, body []byte) error {
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(body)))
	copy(out[2:], body)
	_, err := w.Write(out)
	return err
}

func splitTCPAddr(addr net.Addr) (netip.Addr, uint16) {
	if addr == nil {
		return netip.Addr{}, 0
	}
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, 0
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return netip.Addr{}, 0
	}
	return ip.Unmap(), uint16(tcp.Port)
}
