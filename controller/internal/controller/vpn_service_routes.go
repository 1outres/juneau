package controller

import (
	"context"
	"net/netip"
	"strings"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func vpnRouteForAddress(routes []juneau.Route, address netip.Addr) *juneau.Route {
	var chosen *juneau.Route
	longest := -1
	for i := range routes {
		p, err := netip.ParsePrefix(routes[i].Dst)
		if err == nil && p.Contains(address) && p.Bits() > longest {
			chosen, longest = &routes[i], p.Bits()
		}
	}
	return chosen
}

func sameVPNRoute(route *juneau.Route, vpn *juneau.VPN) bool {
	return route.Via.Type == juneau.ViaVPN && route.Via.VPN != nil && route.Via.VPN.Namespace == vpn.Namespace && route.Via.VPN.Name == vpn.Name
}

func vpnBackendReturns(ctx context.Context, r *VPNReconciler, vpn *juneau.VPN, vpc *juneau.Vpc, subnet *juneau.Subnet, remote []string) bool {
	tableName := subnet.Spec.RouteTable
	if tableName == "" {
		tableName = vpc.Status.MainRouteTable
	}
	var table juneau.RouteTable
	if tableName == "" || r.Get(ctx, client.ObjectKey{Name: tableName}, &table) != nil || table.Spec.Vpc != vpc.Name || table.DeletionTimestamp != nil || !vpnTableReady(&table, vpn) {
		return false
	}
	for _, raw := range remote {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return false
		}
		candidates := table.Status.Routes
		if !conditionReady(table.Status.Conditions, juneau.RouteTableStatusReady, table.Generation) {
			candidates = table.Spec.Routes
		}
		route := vpnRouteForAddress(candidates, prefix.Addr())
		if route == nil || !sameVPNRoute(route, vpn) {
			return false
		}
		for i := range candidates {
			other, err := netip.ParsePrefix(candidates[i].Dst)
			if err != nil || other.Bits() > prefix.Bits() && other.Overlaps(prefix) && !sameVPNRoute(&candidates[i], vpn) {
				return false
			}
		}
	}
	return len(remote) > 0
}

func (r *VPNReconciler) serviceAdvertisements(ctx context.Context, vpn *juneau.VPN, vpc *juneau.Vpc, table *juneau.RouteTable, subnets map[string]*juneau.Subnet, remote []string) ([]string, error) {
	var services corev1.ServiceList
	if err := r.List(ctx, &services); err != nil {
		return nil, err
	}
	var slices discoveryv1.EndpointSliceList
	if err := r.List(ctx, &slices); err != nil {
		return nil, err
	}
	var nics juneau.NetworkInterfaceList
	if err := r.List(ctx, &nics); err != nil {
		return nil, err
	}
	eligible := func(svc *corev1.Service) bool {
		if owningVpcOfService(svc) != vpc.Name || svc.Spec.Type == corev1.ServiceTypeExternalName || len(svc.Spec.ClusterIPs) == 0 || svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone || len(svc.Spec.Ports) == 0 {
			return false
		}
		for _, port := range svc.Spec.Ports {
			if port.Protocol != corev1.ProtocolTCP && port.Protocol != corev1.ProtocolUDP {
				return false
			}
			found := false
			for i := range slices.Items {
				slice := &slices.Items[i]
				if slice.Namespace != svc.Namespace || slice.Labels[discoveryv1.LabelServiceName] != svc.Name || slice.AddressType != discoveryv1.AddressTypeIPv4 {
					continue
				}
				matched := false
				for _, sp := range slice.Ports {
					if sp.Port != nil && (port.Name == "" || sp.Name != nil && *sp.Name == port.Name) && (sp.Protocol == nil || *sp.Protocol == port.Protocol) {
						matched = true
					}
				}
				if !matched {
					continue
				}
				for _, ep := range slice.Endpoints {
					if ep.Conditions.Ready != nil && !*ep.Conditions.Ready || ep.Conditions.Terminating != nil && *ep.Conditions.Terminating {
						continue
					}
					if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" || ep.TargetRef.Name == "" || len(ep.Addresses) == 0 {
						return false
					}
					namespace := ep.TargetRef.Namespace
					if namespace == "" {
						namespace = slice.Namespace
					}
					for _, raw := range ep.Addresses {
						ip, err := netip.ParseAddr(raw)
						if err != nil || !ip.Is4() {
							return false
						}
						valid := false
						for j := range nics.Items {
							nic := &nics.Items[j]
							address, err := netip.ParsePrefix(nic.Status.Address)
							if err != nil || address.Addr() != ip || nic.Namespace != namespace || nic.Spec.PodRef.Name != ep.TargetRef.Name || (ep.TargetRef.UID != "" && nic.Spec.PodRef.UID != string(ep.TargetRef.UID)) || nic.Spec.PodRef.Interface != juneau.PodPrimaryInterfaceName || nic.Status.Phase != juneau.NetworkInterfacePhaseReady || nic.Status.ObservedGeneration != nic.Generation {
								continue
							}
							subnet := subnets[nic.Spec.Subnet]
							forward := vpnRouteForAddress(table.Status.Routes, ip)
							if subnet != nil && subnet.Spec.Vpc == vpc.Name && forward != nil && forward.Via.Type == juneau.ViaConnected && forward.Subnet == subnet.Name && vpnBackendReturns(ctx, r, vpn, vpc, subnet, remote) {
								valid = true
							}
						}
						if !valid {
							return false
						}
						found = true
					}
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	var advertised []string
	serviceByKey := make(map[client.ObjectKey]*corev1.Service, len(services.Items))
	for i := range services.Items {
		svc := &services.Items[i]
		serviceByKey[client.ObjectKeyFromObject(svc)] = svc
	}
	for i := range services.Items {
		svc := &services.Items[i]
		if !vpc.Spec.ServiceEnabled() || !eligible(svc) {
			continue
		}
		ips := []string{svc.Spec.ClusterIP}
		ips = append(ips, svc.Spec.ExternalIPs...)
		for _, raw := range ips {
			ip, err := netip.ParseAddr(strings.TrimSpace(raw))
			if err != nil || !ip.Is4() {
				continue
			}
			route := vpnRouteForAddress(table.Status.Routes, ip)
			if route != nil && route.Via.Type == juneau.ViaService {
				advertised = append(advertised, netip.PrefixFrom(ip, 32).String())
			}
		}
	}
	if vpc.Spec.EndpointPool.Configured() {
		var endpoints juneau.VpcEndpointList
		if err := r.List(ctx, &endpoints); err != nil {
			return nil, err
		}
		for i := range endpoints.Items {
			ep := &endpoints.Items[i]
			if ep.Spec.Vpc != vpc.Name || ep.DeletionTimestamp != nil || !conditionReady(ep.Status.Conditions, juneau.VpcEndpointConditionReady, ep.Generation) || !conditionReady(ep.Status.Conditions, juneau.VpcEndpointConditionServiceAccepted, ep.Generation) {
				continue
			}
			svc := serviceByKey[client.ObjectKey{Namespace: ep.Spec.Service.Namespace, Name: ep.Spec.Service.Name}]
			if svc == nil || !eligible(svc) {
				continue
			}
			ip, err := netip.ParseAddr(ep.Status.Address)
			if err != nil || !ip.Is4() {
				continue
			}
			inPool := false
			for _, cidr := range vpc.Spec.EndpointPool.Cidrs() {
				prefix, err := netip.ParsePrefix(cidr)
				if err == nil && prefix.Contains(ip) {
					inPool = true
				}
			}
			if !inPool {
				continue
			}
			route := vpnRouteForAddress(table.Status.Routes, ip)
			if route != nil && route.Via.Type == juneau.ViaVpcEndpoint {
				advertised = append(advertised, netip.PrefixFrom(ip, 32).String())
			}
		}
	}
	return advertised, nil
}
