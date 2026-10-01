package reconciler

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

const (
	fibRouteTypeConnected       = 1
	fibRouteTypeEndpoint        = 2
	fibRouteTypeInternetGateway = 3
	fibRouteTypeService         = 4
	fibRouteTypeNAPT            = 6
	fibRouteTypePeering         = 7
	fibRouteTypeTransit         = 8
	fibRouteTypeBlackhole       = 9
	fibRouteTypeVpcEndpoint     = 10
	fibRouteTypeL2Gateway       = 11
	fibRouteTypeVPN             = 12
	fibRouteTypePeeringVPN      = 13
)

// Fib keeps podEgress.FibMap in sync with RouteTable objects. Each
// RouteTable owns a FIB inner map; on update the reconciler builds a fresh
// inner map, atomically swaps it into FibMap, and closes the old one.
//
// A RouteTable's contents also depend on referenced Subnets and
// NetworkEndpoints, so Subnet/NWEP events fan out to re-enqueue every
// RouteTable via FanOutAllRouteTables.
type Fib struct {
	client    client.Client
	podEgress *program.PodEgress

	mu        sync.Mutex
	snapshots map[string]fibSnapshot // rt name -> current inner map
}

type fibSnapshot struct {
	tableID uint32
	fib     *ebpf.Map
}

func NewFib(cl client.Client, podEgress *program.PodEgress) *Fib {
	return &Fib{
		client:    cl,
		podEgress: podEgress,
		snapshots: make(map[string]fibSnapshot),
	}
}

func (r *Fib) Name() string { return "fib" }

func (r *Fib) Reconcile(ctx context.Context, key string) error {
	var rt juneauv1alpha1.RouteTable
	err := r.client.Get(ctx, client.ObjectKey{Name: key}, &rt)
	if apierrors.IsNotFound(err) {
		return r.delete(key)
	}
	if err != nil {
		return err
	}
	if rt.Status.TableID == 0 {
		return r.delete(key)
	}
	var pending []juneauv1alpha1.Route
	if !routeTableReady(&rt) {
		var ok bool
		pending, ok = pendingVPNRoutes(&rt)
		if !ok {
			return r.delete(key)
		}
	}
	if err := r.upsert(ctx, key, &rt, pending); err != nil {
		_ = r.delete(key)
		return err
	}
	return nil
}

func (r *Fib) upsert(ctx context.Context, key string, rt *juneauv1alpha1.RouteTable, pending []juneauv1alpha1.Route) error {
	fib, err := ebpf.NewMap(r.podEgress.MapSpecs.FibInner.Copy())
	if err != nil {
		return fmt.Errorf("create new FIB inner map: %w", err)
	}
	defer func() {
		if fib != nil {
			_ = fib.Close()
		}
	}()

	for _, route := range rt.Status.Routes {
		if err := r.populateRoute(ctx, fib, &route); err != nil {
			return err
		}
	}
	for _, route := range pending {
		ip, prefix, err := net.ParseCIDR(route.Dst)
		if err != nil || ip.To4() == nil {
			return fmt.Errorf("invalid pending VPN prefix %q", route.Dst)
		}
		bits, _ := prefix.Mask.Size()
		if err := fib.Update(&bpf.PodEgressFibKey{Dst: binary.LittleEndian.Uint32(ip.To4()), Prefixlen: uint32(bits)}, &bpf.PodEgressFibVal{Type: fibRouteTypeBlackhole}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("blackhole pending VPN route %s: %w", route.Dst, err)
		}
	}

	if err := r.podEgress.Objs.FibMap.Update(rt.Status.TableID, uint32(fib.FD()), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update FibMap for table %d: %w", rt.Status.TableID, err)
	}

	r.mu.Lock()
	old, hadOld := r.snapshots[key]
	r.snapshots[key] = fibSnapshot{tableID: rt.Status.TableID, fib: fib}
	r.mu.Unlock()

	// Outer FibMap now references the new inner map; transfer ownership
	// away from the deferred cleanup.
	fib = nil

	if hadOld && old.tableID != rt.Status.TableID {
		if err := r.podEgress.Objs.FibMap.Delete(old.tableID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			zap.S().Warnf("fib: delete stale FibMap entry %d: %v", old.tableID, err)
		}
	}

	if hadOld && old.fib != nil {
		if err := old.fib.Close(); err != nil {
			zap.S().Warnf("fib: close old inner map for %s: %v", key, err)
		}
	}

	return nil
}

func (r *Fib) delete(key string) error {
	r.mu.Lock()
	old, ok := r.snapshots[key]
	if ok {
		delete(r.snapshots, key)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}

	if err := r.podEgress.Objs.FibMap.Delete(old.tableID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete FibMap entry %d: %w", old.tableID, err)
	}
	if old.fib != nil {
		if err := old.fib.Close(); err != nil {
			zap.S().Warnf("fib: close inner map on delete for %s: %v", key, err)
		}
	}
	return nil
}

func (r *Fib) populateRoute(ctx context.Context, fib *ebpf.Map, route *juneauv1alpha1.Route) error {
	netaddr, ipnet, err := net.ParseCIDR(route.Dst)
	if err != nil {
		return fmt.Errorf("parse FIB CIDR %s: %w", route.Dst, err)
	}
	if netaddr.To4() == nil {
		return fmt.Errorf("FIB route %s is not IPv4", route.Dst)
	}

	prefixlen, _ := ipnet.Mask.Size()
	key := bpf.PodEgressFibKey{
		Dst:       binary.LittleEndian.Uint32(netaddr.To4()),
		Prefixlen: uint32(prefixlen),
	}

	val, skip, err := r.buildFibVal(ctx, route)
	if err != nil {
		return fmt.Errorf("build FIB route for %s via %s: %w", route.Dst, route.Via.Type, err)
	}
	if skip {
		return fmt.Errorf("FIB route for %s via %s is not ready", route.Dst, route.Via.Type)
	}

	if err := fib.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update FIB inner map for %s: %w", route.Dst, err)
	}
	return nil
}

func (r *Fib) buildFibVal(ctx context.Context, route *juneauv1alpha1.Route) (bpf.PodEgressFibVal, bool, error) {
	switch route.Via.Type {
	case juneauv1alpha1.ViaConnected:
		// A connected route leads either to a Subnet or, when the
		// controller resolved one, to the gateway port of an
		// L2Network. The two forward differently enough to be separate
		// route types, but from the Vpc they are the same statement:
		// this prefix is attached here.
		if route.L2Network != "" {
			var network juneauv1alpha1.L2Network
			if err := r.client.Get(ctx, client.ObjectKey{Name: route.L2Network}, &network); err != nil {
				return bpf.PodEgressFibVal{}, false, err
			}
			if network.Status.VNI == 0 {
				return bpf.PodEgressFibVal{}, true, nil
			}
			return buildL2GatewayFibVal(&network), false, nil
		}
		var subnet juneauv1alpha1.Subnet
		if err := r.client.Get(ctx, client.ObjectKey{Name: route.Subnet}, &subnet); err != nil {
			return bpf.PodEgressFibVal{}, false, err
		}
		val, err := buildConnectedFibVal(&subnet)
		return val, false, err

	case juneauv1alpha1.ViaVpcPeering:
		if route.Via.VPN != nil {
			var vpn juneauv1alpha1.VPN
			if err := r.client.Get(ctx, client.ObjectKey{Namespace: route.Via.VPN.Namespace, Name: route.Via.VPN.Name}, &vpn); err != nil {
				return bpf.PodEgressFibVal{}, false, err
			}
			if vpn.Spec.Subnet != route.Subnet {
				return bpf.PodEgressFibVal{}, false, fmt.Errorf("peered VPN gateway Subnet changed")
			}
			var peering juneauv1alpha1.VpcPeering
			if err := r.client.Get(ctx, client.ObjectKey{Name: route.Via.VpcPeering}, &peering); err != nil {
				return bpf.PodEgressFibVal{}, false, err
			}
			if _, ok := peering.Spec.PeerOf(vpn.Spec.Vpc); !ok || peering.DeletionTimestamp != nil || !meta.IsStatusConditionTrue(peering.Status.Conditions, juneauv1alpha1.VpcPeeringStatusReady) {
				return bpf.PodEgressFibVal{}, false, fmt.Errorf("peering %s is not ready for VPN Vpc %s", peering.Name, vpn.Spec.Vpc)
			}
			subnet, _, _, endpoint, err := resolveVPNGateway(ctx, r.client, &vpn)
			if err != nil {
				return bpf.PodEgressFibVal{}, false, err
			}
			val, skip, err := buildVPNFibVal(&vpn, subnet, endpoint)
			val.Type = fibRouteTypePeeringVPN
			return val, skip, err
		}
		var subnet juneauv1alpha1.Subnet
		if err := r.client.Get(ctx, client.ObjectKey{Name: route.Subnet}, &subnet); err != nil {
			return bpf.PodEgressFibVal{}, false, err
		}
		val, err := buildPeeringFibVal(&subnet)
		return val, false, err

	case juneauv1alpha1.ViaEndpoint:
		var subnet juneauv1alpha1.Subnet
		if err := r.client.Get(ctx, client.ObjectKey{Name: route.Subnet}, &subnet); err != nil {
			return bpf.PodEgressFibVal{}, false, err
		}
		var nwep juneauv1alpha1.NetworkEndpoint
		if err := r.client.Get(ctx, client.ObjectKey{Name: route.Via.Endpoint}, &nwep); err != nil {
			return bpf.PodEgressFibVal{}, false, err
		}
		val, err := buildEndpointFibVal(&subnet, &nwep)
		return val, false, err

	case juneauv1alpha1.ViaInternetGateway:
		val, err := buildInternetGatewayFibVal()
		return val, false, err

	case juneauv1alpha1.ViaService:
		return buildServiceFibVal(), false, nil

	case juneauv1alpha1.ViaVpcEndpoint:
		return buildVpcEndpointFibVal(), false, nil

	case juneauv1alpha1.ViaNATGateway:
		var natGateway juneauv1alpha1.NATGateway
		if err := r.client.Get(ctx, client.ObjectKey{Name: route.Via.NATGateway}, &natGateway); err != nil {
			return bpf.PodEgressFibVal{}, false, err
		}
		if natGateway.Status.GatewayID == 0 {
			return bpf.PodEgressFibVal{}, true, nil
		}
		return buildNATGatewayFibVal(&natGateway), false, nil

	case juneauv1alpha1.ViaVPN:
		if route.Via.VPN == nil || route.Via.VPN.Namespace == "" || route.Via.VPN.Name == "" || route.Subnet == "" {
			return bpf.PodEgressFibVal{}, false, fmt.Errorf("VPN route has no resolved gateway")
		}
		var vpn juneauv1alpha1.VPN
		if err := r.client.Get(ctx, client.ObjectKey{Namespace: route.Via.VPN.Namespace, Name: route.Via.VPN.Name}, &vpn); err != nil {
			return bpf.PodEgressFibVal{}, false, err
		}
		if vpn.Spec.Subnet != route.Subnet {
			return bpf.PodEgressFibVal{}, false, fmt.Errorf("VPN gateway Subnet changed")
		}
		subnet, _, _, endpoint, err := resolveVPNGateway(ctx, r.client, &vpn)
		if err != nil {
			return bpf.PodEgressFibVal{}, false, err
		}
		return buildVPNFibVal(&vpn, subnet, endpoint)

	case juneauv1alpha1.ViaTransitGateway:
		var routeTable juneauv1alpha1.TransitGatewayRouteTable
		if err := r.client.Get(ctx, client.ObjectKey{Name: route.TransitGatewayRouteTable}, &routeTable); err != nil {
			return bpf.PodEgressFibVal{}, false, err
		}
		if routeTable.Status.TableID == 0 {
			return bpf.PodEgressFibVal{}, true, nil
		}
		return buildTransitGatewayFibVal(&routeTable), false, nil

	default:
		return bpf.PodEgressFibVal{}, true, fmt.Errorf("unsupported route type %q", route.Via.Type)
	}
}

func buildVPNFibVal(vpn *juneauv1alpha1.VPN, subnet *juneauv1alpha1.Subnet, ep *juneauv1alpha1.NetworkEndpoint) (bpf.PodEgressFibVal, bool, error) {
	mac, err := net.ParseMAC(ep.Spec.MACAddress)
	if err != nil {
		return bpf.PodEgressFibVal{}, false, err
	}
	dmac, err := convert.HardwareAddrToUint8Array(mac)
	if err != nil {
		return bpf.PodEgressFibVal{}, false, err
	}
	gw, err := net.ParseMAC(subnet.Status.GatewayMAC)
	if err != nil {
		return bpf.PodEgressFibVal{}, false, err
	}
	smac, err := convert.HardwareAddrToUint8Array(gw)
	if err != nil {
		return bpf.PodEgressFibVal{}, false, err
	}
	return bpf.PodEgressFibVal{Type: fibRouteTypeVPN, Dmac: dmac, Smac: smac, SubnetId: subnet.Status.VNI, VpnId: bpf.PodEgressVpnIdentity{Bytes: vpnIdentity(vpn.UID)}}, false, nil
}

func routeTableReady(rt *juneauv1alpha1.RouteTable) bool {
	condition := meta.FindStatusCondition(rt.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
	return condition != nil && condition.Status == metav1.ConditionTrue && condition.ObservedGeneration == rt.Generation && rt.Status.ObservedGeneration == rt.Generation
}

func pendingVPNRoutes(rt *juneauv1alpha1.RouteTable) ([]juneauv1alpha1.Route, bool) {
	condition := meta.FindStatusCondition(rt.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "VPNEndpointPending" || condition.ObservedGeneration != rt.Generation || rt.Status.ObservedGeneration != rt.Generation || rt.Status.TableID == 0 {
		return nil, false
	}
	keys := rt.Status.PendingVPNs
	if rt.Status.PendingVPN != "" {
		if len(keys) != 0 {
			return nil, false
		}
		keys = []string{rt.Status.PendingVPN}
	}
	if len(keys) == 0 {
		return nil, false
	}
	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		if key == "" || seen[key] {
			return nil, false
		}
		seen[key] = false
	}
	pending := make([]juneauv1alpha1.Route, 0, len(keys))
	for _, route := range rt.Spec.Routes {
		isPending := route.Via.Type == juneauv1alpha1.ViaVPN && route.Via.VPN != nil && slices.Contains(keys, route.Via.VPN.Namespace+"/"+route.Via.VPN.Name)
		resolved := false
		installedDestination := false
		for _, installed := range rt.Status.Routes {
			if installed.Dst != route.Dst {
				continue
			}
			installedDestination = true
			if installed.Via.Type != route.Via.Type {
				continue
			}
			if route.Via.Type == juneauv1alpha1.ViaVPN && (installed.Via.VPN == nil || installed.Via.VPN.Namespace != route.Via.VPN.Namespace || installed.Via.VPN.Name != route.Via.VPN.Name || installed.Subnet == "") {
				continue
			}
			resolved = true
		}
		if isPending {
			if installedDestination {
				return nil, false
			}
			seen[route.Via.VPN.Namespace+"/"+route.Via.VPN.Name] = true
			pending = append(pending, route)
		} else if !resolved {
			return nil, false
		}
	}
	for _, found := range seen {
		if !found {
			return nil, false
		}
	}
	for _, installed := range rt.Status.Routes {
		if installed.Via.Type != juneauv1alpha1.ViaVPN {
			continue
		}
		valid := false
		for _, route := range rt.Spec.Routes {
			if installed.Dst == route.Dst && installed.Via.VPN != nil && route.Via.VPN != nil && installed.Via.VPN.Namespace == route.Via.VPN.Namespace && installed.Via.VPN.Name == route.Via.VPN.Name && !slices.Contains(keys, route.Via.VPN.Namespace+"/"+route.Via.VPN.Name) {
				valid = true
			}
		}
		if !valid {
			return nil, false
		}
	}
	return pending, true
}

func buildConnectedFibVal(subnet *juneauv1alpha1.Subnet) (bpf.PodEgressFibVal, error) {
	return buildSubnetFibVal(subnet, fibRouteTypeConnected)
}

// buildPeeringFibVal builds a FIB value for a route that leaves the Vpc
// through a VpcPeering. Route.Subnet already names the peer Vpc's
// Subnet, so the data plane forwards exactly like a connected route. The
// separate type only keeps map dumps and traces honest about why the
// route is there.
func buildPeeringFibVal(subnet *juneauv1alpha1.Subnet) (bpf.PodEgressFibVal, error) {
	return buildSubnetFibVal(subnet, fibRouteTypePeering)
}

func buildSubnetFibVal(subnet *juneauv1alpha1.Subnet, routeType uint8) (bpf.PodEgressFibVal, error) {
	netmac, err := net.ParseMAC(subnet.Status.GatewayMAC)
	if err != nil {
		return bpf.PodEgressFibVal{}, err
	}
	mac, err := convert.HardwareAddrToUint8Array(netmac)
	if err != nil {
		return bpf.PodEgressFibVal{}, err
	}
	return bpf.PodEgressFibVal{
		Type:     routeType,
		Smac:     mac,
		SubnetId: subnet.Status.VNI,
	}, nil
}

// buildL2GatewayFibVal builds a FIB value for a route into an
// L2Network. Only the type and the VNI travel: the ifindex of the
// gateway port is node-local, so every node reads the same route and
// looks its own port up in l2_gateway.
func buildL2GatewayFibVal(network *juneauv1alpha1.L2Network) bpf.PodEgressFibVal {
	return bpf.PodEgressFibVal{
		Type:     fibRouteTypeL2Gateway,
		SubnetId: network.Status.VNI,
	}
}

func buildEndpointFibVal(subnet *juneauv1alpha1.Subnet, nwep *juneauv1alpha1.NetworkEndpoint) (bpf.PodEgressFibVal, error) {
	nextHopMAC, err := net.ParseMAC(nwep.Spec.MACAddress)
	if err != nil {
		return bpf.PodEgressFibVal{}, err
	}
	dmac, err := convert.HardwareAddrToUint8Array(nextHopMAC)
	if err != nil {
		return bpf.PodEgressFibVal{}, err
	}
	sourceMAC, err := net.ParseMAC(subnet.Status.GatewayMAC)
	if err != nil {
		return bpf.PodEgressFibVal{}, err
	}
	smac, err := convert.HardwareAddrToUint8Array(sourceMAC)
	if err != nil {
		return bpf.PodEgressFibVal{}, err
	}
	return bpf.PodEgressFibVal{
		Type:     fibRouteTypeEndpoint,
		Dmac:     dmac,
		Smac:     smac,
		SubnetId: subnet.Status.VNI,
	}, nil
}

// buildInternetGatewayFibVal builds a FIB value for the internet-gateway
// route type. Only the type is meaningful here; the BPF side resolves smac,
// dmac, and oif at runtime via bpf_fib_lookup.
func buildInternetGatewayFibVal() (bpf.PodEgressFibVal, error) {
	return bpf.PodEgressFibVal{
		Type: fibRouteTypeInternetGateway,
	}, nil
}

// buildServiceFibVal builds a FIB value for the service route type. Only
// the type is meaningful — the BPF side dispatches to handle_service which
// uses service_map / backend_map / ct_map for the actual rewrite.
func buildServiceFibVal() bpf.PodEgressFibVal {
	return bpf.PodEgressFibVal{
		Type: fibRouteTypeService,
	}
}

// buildVpcEndpointFibVal builds a FIB value for the Vpc endpoint pool
// route type. Only the type is meaningful — the BPF side dispatches to
// handle_service, which first resolves the VpcEndpoint VIP to a Service
// ClusterIP through vpc_endpoint_map.
func buildVpcEndpointFibVal() bpf.PodEgressFibVal {
	return bpf.PodEgressFibVal{
		Type: fibRouteTypeVpcEndpoint,
	}
}

// buildNATGatewayFibVal builds a FIB value for the NAT-gateway route
// type. The NATGateway's GatewayID is overloaded into the subnet_id
// field; the BPF side reads it as a NATGWID and uses it to look up the
// per-node host_napt_ip via the napt_src map.
func buildNATGatewayFibVal(natGateway *juneauv1alpha1.NATGateway) bpf.PodEgressFibVal {
	return bpf.PodEgressFibVal{
		Type:     fibRouteTypeNAPT,
		SubnetId: natGateway.Status.GatewayID,
	}
}

// buildTransitGatewayFibVal builds a FIB value for a route that leaves
// the Vpc through a TransitGateway. The destination is not known here:
// it lives in the transit route table, which the BPF side looks up in a
// second pass. The table id is overloaded into the subnet_id field, the
// same reuse buildNATGatewayFibVal makes for its gateway id.
func buildTransitGatewayFibVal(routeTable *juneauv1alpha1.TransitGatewayRouteTable) bpf.PodEgressFibVal {
	return bpf.PodEgressFibVal{
		Type:     fibRouteTypeTransit,
		SubnetId: routeTable.Status.TableID,
	}
}

// CloseAll closes every retained inner FIB map. Called by Manager on shutdown.
func (r *Fib) CloseAll() error {
	r.mu.Lock()
	snaps := r.snapshots
	r.snapshots = make(map[string]fibSnapshot)
	r.mu.Unlock()

	var errs []error
	for _, snap := range snaps {
		if snap.fib == nil {
			continue
		}
		if err := snap.fib.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// FanOutAllRouteTables is a keys-func for Runner.WatchFanOut: returns every
// RouteTable's key regardless of which object triggered the event. Used to
// re-enqueue all RTs when a referenced Subnet or NetworkEndpoint changes.
func (r *Fib) FanOutVPNRouteTables(obj any) []string {
	var namespace, name string
	switch item := obj.(type) {
	case *juneauv1alpha1.VPN:
		namespace, name = item.Namespace, item.Name
	case *corev1.Pod:
		if !strings.HasPrefix(item.Name, "vpn-") {
			return nil
		}
	case *juneauv1alpha1.NetworkInterface:
		if !strings.HasPrefix(item.Name, "vpn-") || !strings.HasSuffix(item.Name, ".eth0") {
			return nil
		}
	default:
		return nil
	}
	var tables juneauv1alpha1.RouteTableList
	if err := r.client.List(context.Background(), &tables); err != nil {
		zap.S().Warnf("fib: list VPN RouteTables for fan-out: %v", err)
		return nil
	}
	var keys []string
	for i := range tables.Items {
		for _, route := range tables.Items[i].Spec.Routes {
			if route.Via.Type != juneauv1alpha1.ViaVPN || route.Via.VPN == nil {
				continue
			}
			if namespace == "" || (route.Via.VPN.Namespace == namespace && route.Via.VPN.Name == name) {
				keys = append(keys, tables.Items[i].Name)
				break
			}
		}
	}
	return keys
}

func (r *Fib) FanOutAllRouteTables(any) []string {
	var rts juneauv1alpha1.RouteTableList
	if err := r.client.List(context.Background(), &rts); err != nil {
		zap.S().Warnf("fib: list RouteTables for fan-out: %v", err)
		return nil
	}
	keys := make([]string, 0, len(rts.Items))
	for i := range rts.Items {
		keys = append(keys, rts.Items[i].Name)
	}
	return keys
}
