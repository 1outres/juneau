package controller

import (
	"context"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func peeringReturnTableRequests(tables []juneau.RouteTable, peerings []juneau.VpcPeering, sourceVpc string, prefixes map[string]bool) []reconcile.Request {
	var requests []reconcile.Request
	for i := range tables {
		table := &tables[i]
		if table.Spec.Vpc == sourceVpc || table.DeletionTimestamp != nil {
			continue
		}
		matched := false
		for _, route := range table.Spec.Routes {
			if route.Via.Type != juneau.ViaVpcPeering || !prefixes[route.Dst] {
				continue
			}
			for j := range peerings {
				peering := &peerings[j]
				if peering.Name != route.Via.VpcPeering || peering.DeletionTimestamp != nil {
					continue
				}
				if peer, ok := peering.Spec.PeerOf(table.Spec.Vpc); ok && peer == sourceVpc {
					requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: table.Name}})
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
	}
	return requests
}

func (r *RouteTableReconciler) peeringVPNDependents(ctx context.Context, sourceVpc string, prefixes map[string]bool, tables []juneau.RouteTable) []reconcile.Request {
	if len(prefixes) == 0 || sourceVpc == "" {
		return nil
	}
	var peerings juneau.VpcPeeringList
	if err := r.List(ctx, &peerings); err != nil {
		log.FromContext(ctx).Error(err, "list VpcPeerings for VPN return route fan-out")
		return nil
	}
	return peeringReturnTableRequests(tables, peerings.Items, sourceVpc, prefixes)
}

func (r *RouteTableReconciler) mapVPNSourceRouteTableToPeeringRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	table, ok := obj.(*juneau.RouteTable)
	if !ok {
		return nil
	}
	prefixes := make(map[string]bool)
	for _, route := range table.Spec.Routes {
		if route.Via.Type == juneau.ViaVPN && route.Via.VPN != nil {
			prefixes[route.Dst] = true
		}
	}
	if len(prefixes) == 0 {
		return nil
	}
	var tables juneau.RouteTableList
	if err := r.List(ctx, &tables); err != nil {
		log.FromContext(ctx).Error(err, "list RouteTables for VPN return route fan-out")
		return nil
	}
	return r.peeringVPNDependents(ctx, table.Spec.Vpc, prefixes, tables.Items)
}

func (r *RouteTableReconciler) vpnSourceTableWatchHandler() handler.EventHandler {
	enqueue := func(ctx context.Context, q workqueue.TypedRateLimitingInterface[reconcile.Request], objects ...client.Object) {
		seen := make(map[reconcile.Request]bool)
		for _, obj := range objects {
			if obj == nil {
				continue
			}
			for _, req := range r.mapVPNSourceRouteTableToPeeringRouteTables(ctx, obj) {
				if !seen[req] {
					seen[req] = true
					q.Add(req)
				}
			}
		}
	}
	return handler.Funcs{
		CreateFunc: func(ctx context.Context, e event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			enqueue(ctx, q, e.Object)
		},
		UpdateFunc: func(ctx context.Context, e event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			enqueue(ctx, q, e.ObjectOld, e.ObjectNew)
		},
		DeleteFunc: func(ctx context.Context, e event.DeleteEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			enqueue(ctx, q, e.Object)
		},
		GenericFunc: func(ctx context.Context, e event.GenericEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			enqueue(ctx, q, e.Object)
		},
	}
}
