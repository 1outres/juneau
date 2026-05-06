package reconciler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// Subnet keeps hostEgress.SubnetMap in sync with Subnet objects. It looks
// up the VPC's main RouteTable to derive the table id written into the
// map. The owning VPC's vpcID is also tracked so that a delayed VpcID
// allocation propagates into subnet_map.vpc_id; without that, packets
// from this Subnet would carry vpc_id=0 and fail the owner_vpc_id check
// in handle_service.
//
// Beyond subnet_map, this reconciler is also the canonical writer of the
// per-Subnet virtual-service ARP entry: arp_table[(vni, dns_vip)] =
// dns_mac. Pod ARP for the DNS VIP is answered out of arp_table by
// handle_arp in pod_egress.c, so without this entry every Pod ARP for
// .2 would fail before the daemon ever saw a DNS query.
type Subnet struct {
	client     client.Client
	hostEgress *program.PodEgress

	mu        sync.Mutex
	snapshots map[string]subnetSnapshot
}

// subnetSnapshot remembers what we wrote to BPF for a Subnet so a later
// reconcile (or delete) can clean up the right keys even when the
// in-memory Subnet object is no longer available.
type subnetSnapshot struct {
	vni   uint32
	dnsIP uint32 // host byte order; 0 means "no DNS entry written"
	aclID uint32 // ACL programmed on this Subnet's boundary; 0 = none
}

func NewSubnet(cl client.Client, hostEgress *program.PodEgress) *Subnet {
	return &Subnet{
		client:     cl,
		hostEgress: hostEgress,
		snapshots:  make(map[string]subnetSnapshot),
	}
}

func (r *Subnet) Name() string { return "subnet" }

func (r *Subnet) Reconcile(ctx context.Context, key string) error {
	var subnet juneauv1alpha1.Subnet
	err := r.client.Get(ctx, client.ObjectKey{Name: key}, &subnet)
	if apierrors.IsNotFound(err) {
		return r.delete(key)
	}
	if err != nil {
		return err
	}
	return r.upsert(ctx, &subnet)
}

func (r *Subnet) upsert(ctx context.Context, subnet *juneauv1alpha1.Subnet) error {
	zap.S().Infof("subnet: reconciling %s (VNI=%d)", subnet.Name, subnet.Status.VNI)

	var vpc juneauv1alpha1.Vpc
	if err := r.client.Get(ctx, client.ObjectKey{Name: subnet.Spec.Vpc}, &vpc); err != nil {
		return err
	}

	// spec.routeTable lets a Subnet override the Vpc's main RouteTable
	// for traffic originating from its Pods. Falling back to the main RT
	// preserves the original behaviour when the field is empty.
	rtName := subnet.Spec.RouteTable
	if rtName == "" {
		rtName = vpc.Status.MainRouteTable
	}
	var routeTable juneauv1alpha1.RouteTable
	if err := r.client.Get(ctx, client.ObjectKey{Name: rtName}, &routeTable); err != nil {
		return err
	}

	netgwmac, err := net.ParseMAC(subnet.Status.GatewayMAC)
	if err != nil {
		return err
	}

	gwmac, err := convert.HardwareAddrToUint8Array(netgwmac)
	if err != nil {
		return err
	}

	_, ipnet, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		return err
	}

	netgwaddr := net.ParseIP(subnet.Status.Gateway)
	if netgwaddr == nil {
		return fmt.Errorf("failed to parse gateway IP: %s", subnet.Status.Gateway)
	}

	gwaddr, err := convert.IPv4ToUint32(netgwaddr)
	if err != nil {
		return err
	}

	mask, err := convert.IPMaskToUint32(ipnet.Mask)
	if err != nil {
		return err
	}

	// status.networkACL carries the resolved ACLID the daemon
	// programs into subnet_map. nil status (no ACL configured) and a
	// status with ACLID==0 (ACL named in spec but not yet allocated)
	// both program a 0; the data plane treats 0 as "no ACL", so the
	// boundary falls back to default-allow until the controller
	// publishes a real number.
	var aclID uint32
	if subnet.Status.NetworkACL != nil {
		aclID = subnet.Status.NetworkACL.ACLID
	}

	if err := r.hostEgress.Objs.SubnetMap.Update(
		&bpf.PodEgressSubnetKey{SubnetId: subnet.Status.VNI},
		&bpf.PodEgressSubnetVal{
			TableId: routeTable.Status.TableID,
			VpcId:   vpc.Status.VpcID,
			GwMac:   gwmac,
			GwAddr:  gwaddr,
			Mask:    mask,
			AclId:   aclID,
		},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update SubnetMap: %w", err)
	}

	// Reconcile the per-Subnet DNS VIP ARP entry. Empty DNS / DNSMAC
	// indicates the Subnet is too narrow for a `.2` (e.g. /31) and the
	// virtual DNS service is intentionally absent for it.
	dnsIPHost, err := r.upsertDNSARP(subnet)
	if err != nil {
		return err
	}

	r.mu.Lock()
	prev := r.snapshots[subnet.Name]
	r.snapshots[subnet.Name] = subnetSnapshot{vni: subnet.Status.VNI, dnsIP: dnsIPHost, aclID: aclID}
	r.mu.Unlock()

	// If a prior reconcile wrote a DNS ARP entry for a different VNI/IP
	// that we no longer want (Subnet renumbered, DNS removed), drop the
	// stale entry now. We keep this logic outside the snapshot mutex to
	// avoid holding it across a BPF syscall.
	if prev.dnsIP != 0 && (prev.vni != subnet.Status.VNI || prev.dnsIP != dnsIPHost) {
		if err := r.deleteDNSARP(prev.vni, prev.dnsIP); err != nil {
			return err
		}
	}

	return nil
}

// upsertDNSARP writes (or refreshes) the arp_table entry that lets
// pod_egress.handle_arp reply to Pod ARPs for this Subnet's DNS VIP. The
// returned host-byte-order DNS IP is recorded in the snapshot so future
// reconciles know exactly which key to clean up. Returns 0 when the
// Subnet has no DNS VIP (status.dns is empty) or DNS is not yet ready.
func (r *Subnet) upsertDNSARP(subnet *juneauv1alpha1.Subnet) (uint32, error) {
	if subnet.Status.DNS == "" || subnet.Status.DNSMAC == "" {
		return 0, nil
	}

	dnsAddr := net.ParseIP(subnet.Status.DNS)
	if dnsAddr == nil {
		return 0, fmt.Errorf("failed to parse DNS IP: %s", subnet.Status.DNS)
	}
	dnsHost, err := convert.IPv4ToUint32(dnsAddr)
	if err != nil {
		return 0, fmt.Errorf("convert DNS IP: %w", err)
	}

	dnsMAC, err := net.ParseMAC(subnet.Status.DNSMAC)
	if err != nil {
		return 0, fmt.Errorf("parse DNS MAC: %w", err)
	}
	dnsMACArr, err := convert.HardwareAddrToUint8Array(dnsMAC)
	if err != nil {
		return 0, fmt.Errorf("convert DNS MAC: %w", err)
	}

	if err := r.hostEgress.Objs.ArpTable.Update(
		&bpf.PodEgressArpTableKey{SubnetId: subnet.Status.VNI, Ipaddr: dnsHost},
		&bpf.PodEgressArpTableVal{Mac: dnsMACArr},
		ebpf.UpdateAny,
	); err != nil {
		return 0, fmt.Errorf("update ArpTable for DNS VIP: %w", err)
	}
	return dnsHost, nil
}

func (r *Subnet) deleteDNSARP(vni, dnsHost uint32) error {
	if vni == 0 || dnsHost == 0 {
		return nil
	}
	if err := r.hostEgress.Objs.ArpTable.Delete(
		&bpf.PodEgressArpTableKey{SubnetId: vni, Ipaddr: dnsHost},
	); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete ArpTable DNS VIP entry: %w", err)
	}
	return nil
}

// FanOutNetworkACLToSubnets re-enqueues every Subnet that references
// the changed NetworkACL. Used so that a fresh ACLID allocation or a
// rulesetVersion bump propagates into subnet_map.acl_id without
// waiting for an unrelated Subnet event.
func (r *Subnet) FanOutNetworkACLToSubnets(obj any) []string {
	acl, ok := obj.(*juneauv1alpha1.NetworkACL)
	if !ok {
		return nil
	}

	var subnetList juneauv1alpha1.SubnetList
	if err := r.client.List(context.Background(), &subnetList); err != nil {
		zap.S().Warnf("subnet: list subnets for networkacl %q fan-out: %v", acl.Name, err)
		return nil
	}
	keys := make([]string, 0, len(subnetList.Items))
	for i := range subnetList.Items {
		s := &subnetList.Items[i]
		if s.Spec.NetworkACL != acl.Name {
			continue
		}
		keys = append(keys, s.Name)
	}
	return keys
}

// FanOutVpcToSubnets re-enqueues every Subnet that belongs to the
// changed Vpc. Used so that VpcID / spec.service changes propagate
// into subnet_map without waiting for an unrelated Subnet event.
func (r *Subnet) FanOutVpcToSubnets(obj any) []string {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil
	}

	var subnetList juneauv1alpha1.SubnetList
	if err := r.client.List(context.Background(), &subnetList, client.MatchingFields{"spec.vpc": vpc.Name}); err != nil {
		zap.S().Warnf("subnet: list subnets for vpc %q fan-out: %v", vpc.Name, err)
		return nil
	}
	keys := make([]string, 0, len(subnetList.Items))
	for i := range subnetList.Items {
		keys = append(keys, subnetList.Items[i].Name)
	}
	return keys
}

// FanOutRouteTableToSubnets re-enqueues every Subnet whose effective
// RouteTable matches the changed RouteTable. This makes
// RouteTable.Status.TableID changes (initial allocation, reassignment)
// propagate into subnet_map.table_id without waiting for an unrelated
// Subnet event.
func (r *Subnet) FanOutRouteTableToSubnets(obj any) []string {
	rt, ok := obj.(*juneauv1alpha1.RouteTable)
	if !ok {
		return nil
	}

	var subnetList juneauv1alpha1.SubnetList
	if err := r.client.List(context.Background(), &subnetList, client.MatchingFields{"spec.vpc": rt.Spec.Vpc}); err != nil {
		zap.S().Warnf("subnet: list subnets for routetable %q fan-out: %v", rt.Name, err)
		return nil
	}

	// A Subnet is affected when either: (a) it explicitly references
	// this RouteTable, or (b) it has no override and this RouteTable is
	// the Vpc's main one. Check the Vpc's MainRouteTable once for case
	// (b) to avoid a Get per Subnet.
	var vpc juneauv1alpha1.Vpc
	if err := r.client.Get(context.Background(), client.ObjectKey{Name: rt.Spec.Vpc}, &vpc); err != nil {
		zap.S().Warnf("subnet: get vpc %q for routetable fan-out: %v", rt.Spec.Vpc, err)
	}
	isMain := vpc.Status.MainRouteTable == rt.Name

	keys := make([]string, 0, len(subnetList.Items))
	for i := range subnetList.Items {
		s := &subnetList.Items[i]
		switch {
		case s.Spec.RouteTable == rt.Name:
			keys = append(keys, s.Name)
		case s.Spec.RouteTable == "" && isMain:
			keys = append(keys, s.Name)
		}
	}
	return keys
}

func (r *Subnet) delete(key string) error {
	r.mu.Lock()
	snap, ok := r.snapshots[key]
	r.mu.Unlock()
	if !ok {
		return nil
	}

	zap.S().Infof("subnet: deleting %s (VNI=%d)", key, snap.vni)

	if err := r.hostEgress.Objs.SubnetMap.Delete(&bpf.PodEgressSubnetKey{SubnetId: snap.vni}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete SubnetMap: %w", err)
	}

	if err := r.deleteDNSARP(snap.vni, snap.dnsIP); err != nil {
		return err
	}

	r.mu.Lock()
	delete(r.snapshots, key)
	r.mu.Unlock()

	return nil
}
