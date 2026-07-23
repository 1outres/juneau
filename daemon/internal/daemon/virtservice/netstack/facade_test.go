package netstack

import (
	"context"
	"net/netip"
	"testing"
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
