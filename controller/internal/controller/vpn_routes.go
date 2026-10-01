package controller

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *VPNReconciler) gatewayRoutes(ctx context.Context, vpn *juneau.VPN, vpc *juneau.Vpc, gatewaySubnet *juneau.Subnet) ([]string, []string, error) {
	tableName := gatewaySubnet.Spec.RouteTable
	if tableName == "" {
		tableName = vpc.Status.MainRouteTable
	}
	if tableName == "" {
		return nil, nil, fmt.Errorf("Vpc %s has no main RouteTable", vpc.Name)
	}
	var table juneau.RouteTable
	if err := r.Get(ctx, client.ObjectKey{Name: tableName}, &table); err != nil {
		return nil, nil, err
	}
	if table.Spec.Vpc != vpc.Name || table.DeletionTimestamp != nil {
		return nil, nil, fmt.Errorf("gateway RouteTable %s is not active in Vpc %s", tableName, vpc.Name)
	}
	if !vpnTableReady(&table, vpn) {
		return nil, nil, fmt.Errorf("gateway RouteTable %s is not Ready in Vpc %s", tableName, vpc.Name)
	}
	var subnetList juneau.SubnetList
	if err := r.List(ctx, &subnetList); err != nil {
		return nil, nil, err
	}
	subnetByName := make(map[string]*juneau.Subnet, len(subnetList.Items))
	peeringSubnetByName := make(map[string]*juneau.Subnet, len(subnetList.Items))
	for i := range subnetList.Items {
		subnet := &subnetList.Items[i]
		if subnet.DeletionTimestamp != nil {
			continue
		}
		if conditionReady(subnet.Status.Conditions, juneau.SubnetStatusReady, subnet.Generation) {
			subnetByName[subnet.Name] = subnet
			peeringSubnetByName[subnet.Name] = subnet
		} else if subnet.Spec.Vpc != vpc.Name {
			pending, err := r.peeringSubnetPendingOnVPN(ctx, vpn, subnet)
			if err != nil {
				return nil, nil, err
			}
			if pending {
				peeringSubnetByName[subnet.Name] = subnet
			}
		}
	}
	remote, advertised := []string{}, []string{}
	var tables juneau.RouteTableList
	if err := r.List(ctx, &tables); err != nil {
		return nil, nil, err
	}
	remoteSet := map[string]struct{}{}
	for i := range tables.Items {
		other := &tables.Items[i]
		if other.Spec.Vpc != vpc.Name || other.DeletionTimestamp != nil || !vpnTableReady(other, vpn) {
			continue
		}
		for _, route := range other.Spec.Routes {
			if route.Via.Type != juneau.ViaVPN || route.Via.VPN == nil || route.Via.VPN.Namespace != vpn.Namespace || route.Via.VPN.Name != vpn.Name {
				continue
			}
			if _, err := vpnIPv4Prefix(route.Dst, true); err != nil {
				return nil, nil, err
			}
			remoteSet[route.Dst] = struct{}{}
		}
	}
	for dst := range remoteSet {
		remote = append(remote, dst)
	}
	if err := validateGatewayVPNPolicy(table.Spec.Routes, vpn, remote); err != nil {
		return nil, nil, err
	}
	advertisedSet := map[string]struct{}{}
	for _, subnet := range subnetByName {
		if subnet.Spec.Vpc == vpc.Name {
			advertisedSet[subnet.Spec.CIDR] = struct{}{}
		}
	}
	for _, route := range table.Status.Routes {
		subnet := subnetByName[route.Subnet]
		switch route.Via.Type {
		case juneau.ViaVpcPeering:
			subnet = peeringSubnetByName[route.Subnet]
			if subnet == nil || subnet.Spec.Vpc == vpc.Name || subnet.Spec.CIDR != route.Dst {
				continue
			}
			var peering juneau.VpcPeering
			if err := r.Get(ctx, client.ObjectKey{Name: route.Via.VpcPeering}, &peering); err != nil {
				continue
			}
			peer, direct := peering.Spec.PeerOf(vpc.Name)
			if peering.DeletionTimestamp != nil || !conditionReady(peering.Status.Conditions, juneau.VpcPeeringStatusReady, peering.Generation) || !direct || peer != subnet.Spec.Vpc {
				continue
			}
		case juneau.ViaTransitGateway:
			if route.Dst == "0.0.0.0/0" || route.TransitGatewayRouteTable == "" || route.Via.TransitGateway == "" {
				continue
			}
			var transit juneau.TransitGatewayRouteTable
			if err := r.Get(ctx, client.ObjectKey{Name: route.TransitGatewayRouteTable}, &transit); err != nil || transit.DeletionTimestamp != nil || transit.Spec.TransitGateway != route.Via.TransitGateway || !conditionReady(transit.Status.Conditions, juneau.TransitGatewayRouteTableStatusReady, transit.Generation) {
				continue
			}
			var gateway juneau.TransitGateway
			if err := r.Get(ctx, client.ObjectKey{Name: route.Via.TransitGateway}, &gateway); err != nil || gateway.DeletionTimestamp != nil || !conditionReady(gateway.Status.Conditions, juneau.TransitGatewayStatusReady, gateway.Generation) {
				continue
			}
			var attachments juneau.TransitGatewayAttachmentList
			if err := r.List(ctx, &attachments); err != nil {
				return nil, nil, err
			}
			associated := false
			for i := range attachments.Items {
				a := &attachments.Items[i]
				if a.Spec.Vpc == vpc.Name && a.Spec.TransitGateway == gateway.Name && a.Spec.Association == transit.Name && a.DeletionTimestamp == nil && conditionReady(a.Status.Conditions, juneau.TransitGatewayAttachmentStatusReady, a.Generation) {
					associated = true
				}
			}
			if !associated {
				continue
			}
			valid := false
			for _, resolved := range transit.Status.Routes {
				target := subnetByName[resolved.Subnet]
				if resolved.Dst != route.Dst || resolved.Blackhole || resolved.VPN != nil || target == nil || target.Spec.Vpc == vpc.Name || target.Spec.CIDR != route.Dst {
					continue
				}
				for i := range attachments.Items {
					a := &attachments.Items[i]
					if a.Name == resolved.Attachment && a.Spec.TransitGateway == gateway.Name && a.Spec.Vpc == target.Spec.Vpc && a.DeletionTimestamp == nil && conditionReady(a.Status.Conditions, juneau.TransitGatewayAttachmentStatusReady, a.Generation) {
						valid = true
					}
				}
			}
			if !valid {
				continue
			}
		default:
			continue
		}
		advertisedSet[route.Dst] = struct{}{}
	}
	for _, route := range table.Status.Routes {
		if route.Via.Type != juneau.ViaService && route.Via.Type != juneau.ViaVpcEndpoint {
			continue
		}
		slices.Sort(remote)
		serviceRoutes, err := r.serviceAdvertisements(ctx, vpn, vpc, &table, subnetByName, remote)
		if err != nil {
			return nil, nil, err
		}
		for _, prefix := range serviceRoutes {
			advertisedSet[prefix] = struct{}{}
		}
		break
	}
	for dst := range advertisedSet {
		if _, err := vpnIPv4Prefix(dst, false); err != nil {
			return nil, nil, err
		}
		advertised = append(advertised, dst)
	}
	slices.Sort(remote)
	slices.Sort(advertised)
	if err := validateGatewayRoutes(remote, advertised); err != nil {
		return nil, nil, err
	}
	return remote, advertised, nil
}

func (r *VPNReconciler) peeringSubnetPendingOnVPN(ctx context.Context, vpn *juneau.VPN, subnet *juneau.Subnet) (bool, error) {
	condition := meta.FindStatusCondition(subnet.Status.Conditions, juneau.SubnetStatusReady)
	_, macErr := net.ParseMAC(subnet.Status.GatewayMAC)
	if subnet.DeletionTimestamp != nil || subnet.Status.VNI == 0 || macErr != nil || condition == nil || condition.Status != metav1.ConditionFalse || condition.ObservedGeneration != subnet.Generation || condition.Reason != subnetReasonVpcNotReady {
		return false, nil
	}
	var vpc juneau.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: subnet.Spec.Vpc}, &vpc); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if vpc.DeletionTimestamp != nil || vpc.Status.VpcID == 0 || vpc.Status.MainRouteTable == "" {
		return false, nil
	}
	condition = meta.FindStatusCondition(vpc.Status.Conditions, juneau.VpcStatusReady)
	if condition == nil || condition.ObservedGeneration != vpc.Generation || condition.Status != metav1.ConditionTrue && (condition.Status != metav1.ConditionFalse || condition.Reason != vpcReasonRouteTableNotReady) {
		return false, nil
	}
	var table juneau.RouteTable
	if err := r.Get(ctx, client.ObjectKey{Name: vpc.Status.MainRouteTable}, &table); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if table.Spec.Vpc != vpc.Name || table.DeletionTimestamp != nil || table.Status.TableID == 0 {
		return false, nil
	}
	condition = meta.FindStatusCondition(table.Status.Conditions, juneau.RouteTableStatusReady)
	if condition == nil || condition.ObservedGeneration != table.Generation {
		return false, nil
	}
	pending := condition.Status == metav1.ConditionFalse && condition.Reason == routeTableReasonVPNEndpointPending && routeTableVPNPending(&table.Status, vpn.Namespace+"/"+vpn.Name)
	ready := condition.Status == metav1.ConditionTrue && table.Status.ObservedGeneration == table.Generation
	if !pending && !ready {
		return false, nil
	}
	var sourceTables juneau.RouteTableList
	if err := r.List(ctx, &sourceTables); err != nil {
		return false, err
	}
	prefixes := make(map[string]bool)
	for i := range sourceTables.Items {
		candidate := &sourceTables.Items[i]
		if candidate.Spec.Vpc != vpn.Spec.Vpc || candidate.DeletionTimestamp != nil {
			continue
		}
		for _, route := range candidate.Spec.Routes {
			if sameVPNRoute(&route, vpn) {
				prefixes[route.Dst] = true
			}
		}
	}
	for _, route := range table.Spec.Routes {
		if route.Via.Type != juneau.ViaVpcPeering || !prefixes[route.Dst] {
			continue
		}
		var peering juneau.VpcPeering
		if err := r.Get(ctx, client.ObjectKey{Name: route.Via.VpcPeering}, &peering); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return false, err
		}
		if peering.DeletionTimestamp != nil || !conditionReady(peering.Status.Conditions, juneau.VpcPeeringStatusReady, peering.Generation) {
			continue
		}
		if peer, ok := peering.Spec.PeerOf(vpc.Name); ok && peer == vpn.Spec.Vpc {
			if pending {
				return true, nil
			}
			for _, active := range table.Status.Routes {
				if active.Dst == route.Dst && active.Via.Type == juneau.ViaVpcPeering && active.Via.VpcPeering == peering.Name && active.Via.VPN != nil && active.Via.VPN.Namespace == vpn.Namespace && active.Via.VPN.Name == vpn.Name && active.Subnet == vpn.Spec.Subnet {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func vpnTableReady(table *juneau.RouteTable, vpn *juneau.VPN) bool {
	if conditionReady(table.Status.Conditions, juneau.RouteTableStatusReady, table.Generation) {
		return true
	}
	ready := meta.FindStatusCondition(table.Status.Conditions, juneau.RouteTableStatusReady)
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.ObservedGeneration != table.Generation || ready.Reason != routeTableReasonVPNEndpointPending {
		return false
	}
	for _, route := range table.Spec.Routes {
		if !sameVPNRoute(&route, vpn) {
			continue
		}
		if routeTableVPNPending(&table.Status, vpn.Namespace+"/"+vpn.Name) {
			return true
		}
		for _, resolved := range table.Status.Routes {
			if resolved.Dst == route.Dst && sameVPNRoute(&resolved, vpn) && resolved.Subnet == vpn.Spec.Subnet {
				return true
			}
		}
	}
	return false
}

func routeTableVPNPending(status *juneau.RouteTableStatus, key string) bool {
	if status.PendingVPN != "" {
		return len(status.PendingVPNs) == 0 && status.PendingVPN == key
	}
	return slices.Contains(status.PendingVPNs, key)
}

func validateGatewayVPNPolicy(routes []juneau.Route, vpn *juneau.VPN, remote []string) error {
	for _, raw := range remote {
		own, err := vpnIPv4Prefix(raw, true)
		if err != nil {
			return err
		}
		for j := range routes {
			if routes[j].Via.Type != juneau.ViaVPN || sameVPNRoute(&routes[j], vpn) {
				continue
			}
			other, err := vpnIPv4Prefix(routes[j].Dst, true)
			if err != nil {
				return err
			}
			if own.Overlaps(other) {
				return fmt.Errorf("gateway VPN route %s for %s/%s overlaps another VPN route %s", own, vpn.Namespace, vpn.Name, other)
			}
		}
	}
	return nil
}

func vpnIPv4Prefix(raw string, allowDefault bool) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix || !allowDefault && prefix.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("invalid VPN route prefix %q", raw)
	}
	return prefix, nil
}

func validateGatewayRoutes(remote, advertised []string) error {
	for i, raw := range remote {
		p, err := vpnIPv4Prefix(raw, true)
		if err != nil {
			return err
		}
		for _, other := range remote[:i] {
			q, _ := vpnIPv4Prefix(other, true)
			if p.Overlaps(q) && (p.Bits() != 0 && q.Bits() != 0 || p == q) {
				return fmt.Errorf("overlapping VPN routes %s and %s", raw, other)
			}
		}
	}
	for i, raw := range advertised {
		p, err := vpnIPv4Prefix(raw, false)
		if err != nil {
			return err
		}
		for _, other := range advertised[:i] {
			q, _ := vpnIPv4Prefix(other, false)
			if p.Overlaps(q) {
				return fmt.Errorf("overlapping advertised routes %s and %s", raw, other)
			}
		}
		for _, other := range remote {
			q, _ := vpnIPv4Prefix(other, true)
			if q.Bits() != 0 && p.Overlaps(q) {
				return fmt.Errorf("VPN route %s overlaps reachable prefix %s", other, raw)
			}
		}
	}
	return nil
}
