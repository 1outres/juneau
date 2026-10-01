package controller

import (
	"context"
	"fmt"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *RouteTableReconciler) resolvePeeringVPNRoute(ctx context.Context, sourceVpc, peerVpc string, route juneau.Route) (juneau.Route, error) {
	var peering juneau.VpcPeering
	if err := r.Get(ctx, client.ObjectKey{Name: route.Via.VpcPeering}, &peering); err != nil {
		return route, err
	}
	if destination, ok := peering.Spec.PeerOf(sourceVpc); !ok || destination != peerVpc || !conditionReady(peering.Status.Conditions, juneau.VpcPeeringStatusReady, peering.Generation) {
		return route, fmt.Errorf("peering %s does not directly connect %s to %s", peering.Name, sourceVpc, peerVpc)
	}
	var tables juneau.RouteTableList
	if err := r.List(ctx, &tables); err != nil {
		return route, err
	}
	var reference *juneau.VPNReference
	resolved := true
	var activeSubnets []string
	for i := range tables.Items {
		table := &tables.Items[i]
		if table.Spec.Vpc != peerVpc || table.DeletionTimestamp != nil {
			continue
		}
		for j := range table.Spec.Routes {
			candidate := &table.Spec.Routes[j]
			if candidate.Dst != route.Dst || candidate.Via.Type != juneau.ViaVPN || candidate.Via.VPN == nil {
				continue
			}
			if reference != nil && *reference != *candidate.Via.VPN {
				return route, fmt.Errorf("ambiguous VPN return route for %s in Vpc %s", route.Dst, peerVpc)
			}
			reference = candidate.Via.VPN
			activeRoute := false
			if table.Status.TableID != 0 && table.Status.ObservedGeneration == table.Generation {
				for _, active := range table.Status.Routes {
					if active.Dst == candidate.Dst && active.Via.Type == juneau.ViaVPN && active.Via.VPN != nil && *active.Via.VPN == *reference && active.Subnet != "" {
						activeRoute = true
						activeSubnets = append(activeSubnets, active.Subnet)
					}
				}
			}
			resolved = resolved && activeRoute
		}
	}
	if reference == nil {
		return route, fmt.Errorf("Vpc %s has no explicit VPN route for %s", peerVpc, route.Dst)
	}
	route.Via.VPN = reference.DeepCopy()
	if !resolved {
		return route, vpnRoutePending("Vpc %s has no Ready VPN route for %s", peerVpc, route.Dst)
	}
	gatewaySubnet, err := r.resolveVPNRoute(ctx, peerVpc, reference)
	if err != nil {
		return route, err
	}
	for _, activeSubnet := range activeSubnets {
		if activeSubnet != gatewaySubnet {
			return route, vpnRoutePending("Vpc %s VPN return route %s does not use the gateway Subnet", peerVpc, route.Dst)
		}
	}
	route.Subnet = gatewaySubnet
	return route, nil
}
