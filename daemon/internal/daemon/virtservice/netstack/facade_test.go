package netstack

import (
	"context"
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestListenTCPAllowsSameVIPAcrossVPCs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	facade := New(nil)
	t.Cleanup(func() {
		if err := facade.Stop(); err != nil {
			t.Errorf("stop facade: %v", err)
		}
	})

	vip := netip.MustParseAddr("10.0.1.2")
	for _, vpcID := range []uint32{1, 2} {
		if err := facade.EnsureNIC(ctx, vpcID, vip); err != nil {
			t.Fatalf("ensure VPC %d NIC: %v", vpcID, err)
		}
		listener, err := facade.ListenTCP(vpcID, vip, 53)
		if err != nil {
			t.Fatalf("listen on VPC %d: %v", vpcID, err)
		}
		t.Cleanup(func() {
			if err := listener.Close(); err != nil {
				t.Errorf("close VPC %d listener: %v", vpcID, err)
			}
		})
	}
}

func TestListenTCPRepliesOnEachVPCNIC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	facade := New(nil)
	t.Cleanup(func() {
		if err := facade.Stop(); err != nil {
			t.Errorf("stop facade: %v", err)
		}
	})

	vip := netip.MustParseAddr("10.0.1.2")
	for _, vpcID := range []uint32{1, 2} {
		if err := facade.EnsureNIC(ctx, vpcID, vip); err != nil {
			t.Fatalf("ensure VPC %d NIC: %v", vpcID, err)
		}
		listener, err := facade.ListenTCP(vpcID, vip, 53)
		if err != nil {
			t.Fatalf("listen on VPC %d: %v", vpcID, err)
		}
		t.Cleanup(func() {
			if err := listener.Close(); err != nil {
				t.Errorf("close VPC %d listener: %v", vpcID, err)
			}
		})

		facade.mu.Lock()
		nic := facade.nics[vpcID]
		nic.cancel()
		facade.mu.Unlock()
		<-nic.done
		facade.mu.Lock()
		nic.cancel = nil
		nic.done = nil
		facade.mu.Unlock()

		syn, err := hex.DecodeString("4500003c00044000400624ac0a00010b0a000102e23c00350767cece00000000a002faf066e20000020405b40402080abb9d5bdb0000000001030307")
		if err != nil {
			t.Fatalf("decode SYN fixture: %v", err)
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(syn),
		})
		nic.endpoint.InjectInbound(ipv4.ProtocolNumber, pkt)
		pkt.DecRef()

		readCtx, readCancel := context.WithTimeout(context.Background(), time.Second)
		reply := nic.endpoint.ReadContext(readCtx)
		readCancel()
		if reply == nil {
			t.Fatalf("VPC %d NIC produced no SYN-ACK", vpcID)
		}
		view := reply.ToView()
		reply.DecRef()
		replyBytes := view.AsSlice()
		ip := header.IPv4(replyBytes)
		tcp := header.TCP(replyBytes[ip.HeaderLength():])
		t.Logf("VPC %d reply %s:%d -> %s:%d flags=%v", vpcID, ip.SourceAddress(), tcp.SourcePort(), ip.DestinationAddress(), tcp.DestinationPort(), tcp.Flags())
		if got := tcp.Flags(); got&header.TCPFlagSyn == 0 || got&header.TCPFlagAck == 0 {
			t.Fatalf("VPC %d reply flags = %v, want SYN|ACK", vpcID, got)
		}
		view.Release()
	}
}
