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
type Subnet struct {
	client     client.Client
	hostEgress *program.HostEgress

	mu        sync.Mutex
	snapshots map[string]uint32 // subnet name -> VNI used at last write
}

func NewSubnet(cl client.Client, hostEgress *program.HostEgress) *Subnet {
	return &Subnet{
		client:     cl,
		hostEgress: hostEgress,
		snapshots:  make(map[string]uint32),
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

	if err := r.hostEgress.Objs.SubnetMap.Update(
		&bpf.HostEgressSubnetKey{SubnetId: subnet.Status.VNI},
		&bpf.HostEgressSubnetVal{
			TableId: routeTable.Status.TableID,
			VpcId:   vpc.Status.VpcID,
			GwMac:   gwmac,
			GwAddr:  gwaddr,
			Mask:    mask,
		},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update SubnetMap: %w", err)
	}

	r.mu.Lock()
	r.snapshots[subnet.Name] = subnet.Status.VNI
	r.mu.Unlock()

	return nil
}

// FanOutVpcToSubnets re-enqueues every Subnet that belongs to the
// changed Vpc. Used so that VpcID/enableService changes propagate into
// subnet_map without waiting for an unrelated Subnet event.
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
	vni, ok := r.snapshots[key]
	r.mu.Unlock()
	if !ok {
		return nil
	}

	zap.S().Infof("subnet: deleting %s (VNI=%d)", key, vni)

	if err := r.hostEgress.Objs.SubnetMap.Delete(&bpf.HostEgressSubnetKey{SubnetId: vni}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete SubnetMap: %w", err)
	}

	r.mu.Lock()
	delete(r.snapshots, key)
	r.mu.Unlock()

	return nil
}
