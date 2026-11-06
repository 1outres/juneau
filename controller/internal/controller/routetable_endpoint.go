/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	// networkInterfaceAllocationIdentityIndex finds every
	// NetworkInterface of one workload.
	networkInterfaceAllocationIdentityIndex = "spec.allocationIdentity"

	// routeTableEndpointNamespaceIndex finds every RouteTable with an
	// endpoint route into a namespace.
	routeTableEndpointNamespaceIndex = "spec.routes.via.endpoint.namespace"

	// networkEndpointPodUIDIndex is installed by the NetworkEndpoint
	// reconciler.
	networkEndpointPodUIDIndex = "spec.podRef.uid"
)

// resolveEndpointRoute turns an endpoint route into the route the data
// plane programs. The route leads to the NetworkEndpoint of the
// NetworkInterface that holds the address of the workload right now, which
// is the one named by the AllocationLease of the workload's identity.
//
// While no such endpoint can be used, the route is a blackhole and its
// message says why. Only a failure to read the cluster is an error.
func (r *RouteTableReconciler) resolveEndpointRoute(ctx context.Context, rt *juneauv1alpha1.RouteTable, route juneauv1alpha1.Route, vpcSubnets []string) (juneauv1alpha1.ResolvedRoute, error) {
	ref := route.Via.Endpoint
	if ref == nil {
		return blackholeRoute(route, "via.endpoint is not set"), nil
	}
	workload := fmt.Sprintf("allocation identity %q on interface %q in namespace %q", ref.AllocationIdentity, ref.Interface, ref.Namespace)

	holders, err := r.addressHolders(ctx, *ref)
	if err != nil {
		return juneauv1alpha1.ResolvedRoute{}, err
	}
	switch len(holders) {
	case 0:
		return blackholeRoute(route, fmt.Sprintf("no NetworkInterface holds the address of %s", workload)), nil
	case 1:
	default:
		names := make([]string, 0, len(holders))
		for i := range holders {
			names = append(names, holders[i].Name)
		}
		return blackholeRoute(route, fmt.Sprintf("NetworkInterfaces %s all hold an address of %s; give the workload one network for this interface", strings.Join(names, ", "), workload)), nil
	}
	holder := &holders[0]

	endpoint, message, err := r.endpointOfNetworkInterface(ctx, holder)
	if err != nil {
		return juneauv1alpha1.ResolvedRoute{}, err
	}
	if endpoint == nil {
		return blackholeRoute(route, message), nil
	}

	endpointName := endpoint.Namespace + "/" + endpoint.Name
	if endpoint.Spec.Subnet == "" {
		return blackholeRoute(route, fmt.Sprintf("NetworkEndpoint %s is not on a Subnet; an endpoint route needs one in Vpc %q", endpointName, rt.Spec.Vpc)), nil
	}
	if !slices.Contains(vpcSubnets, endpoint.Spec.Subnet) {
		return blackholeRoute(route, fmt.Sprintf("NetworkEndpoint %s is on Subnet %q, which is not in Vpc %q", endpointName, endpoint.Spec.Subnet, rt.Spec.Vpc)), nil
	}
	if endpoint.Spec.MACAddress == "" {
		return blackholeRoute(route, fmt.Sprintf("NetworkEndpoint %s has no MAC address yet", endpointName)), nil
	}

	return juneauv1alpha1.ResolvedRoute{
		Dst:    route.Dst,
		Via:    route.Via,
		Subnet: endpoint.Spec.Subnet,
		NetworkEndpoint: &juneauv1alpha1.ResolvedNetworkEndpointReference{
			Namespace: endpoint.Namespace,
			Name:      endpoint.Name,
		},
		State: juneauv1alpha1.RouteStateActive,
	}, nil
}

// addressHolders returns the NetworkInterfaces of the workload that hold
// the AllocationLease of their identity. Two interfaces share an identity
// while a new Pod of the workload starts before the old one is gone, as
// in a KubeVirt live migration. Only the old one holds the lease then;
// the new one got an address of its own.
func (r *RouteTableReconciler) addressHolders(ctx context.Context, ref juneauv1alpha1.RouteEndpointReference) ([]juneauv1alpha1.NetworkInterface, error) {
	var nics juneauv1alpha1.NetworkInterfaceList
	if err := r.List(ctx, &nics, client.InNamespace(ref.Namespace), client.MatchingFields{
		networkInterfaceAllocationIdentityIndex: ref.AllocationIdentity,
	}); err != nil {
		return nil, fmt.Errorf("list NetworkInterfaces of allocation identity %q in namespace %q: %w", ref.AllocationIdentity, ref.Namespace, err)
	}

	var holders []juneauv1alpha1.NetworkInterface
	for i := range nics.Items {
		nic := &nics.Items[i]
		if nic.Spec.PodRef.Interface != ref.Interface || !nic.DeletionTimestamp.IsZero() {
			continue
		}
		holds, err := r.holdsLease(ctx, nic)
		if err != nil {
			return nil, err
		}
		if holds {
			holders = append(holders, *nic)
		}
	}
	return holders, nil
}

// holdsLease reports whether the AllocationLease of a NetworkInterface's
// identity names the interface's own AllocationClaim as its live holder.
func (r *RouteTableReconciler) holdsLease(ctx context.Context, nic *juneauv1alpha1.NetworkInterface) (bool, error) {
	var lease juneauv1alpha1.AllocationLease
	leaseName := leaseNameForNetworkInterface(nic)
	if err := r.Get(ctx, client.ObjectKey{Name: leaseName}, &lease); err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("get AllocationLease %q: %w", leaseName, err)
	}
	return lease.Spec.ClaimRef.Name == claimNameForNetworkInterface(nic) &&
		lease.Spec.OwnerDeletionTimestamp.IsZero(), nil
}

// endpointOfNetworkInterface finds the NetworkEndpoint the CNI wrote for
// the Pod NIC behind a NetworkInterface. It returns nil and the reason when
// there is none, which is the case until the Pod runs.
func (r *RouteTableReconciler) endpointOfNetworkInterface(ctx context.Context, nic *juneauv1alpha1.NetworkInterface) (*juneauv1alpha1.NetworkEndpoint, string, error) {
	var endpoints juneauv1alpha1.NetworkEndpointList
	if err := r.List(ctx, &endpoints, client.InNamespace(nic.Namespace), client.MatchingFields{
		networkEndpointPodUIDIndex: nic.Spec.PodRef.UID,
	}); err != nil {
		return nil, "", fmt.Errorf("list NetworkEndpoints of Pod %s/%s: %w", nic.Namespace, nic.Spec.PodRef.Name, err)
	}

	var matches []*juneauv1alpha1.NetworkEndpoint
	for i := range endpoints.Items {
		endpoint := &endpoints.Items[i]
		if endpoint.Spec.PodRef != nil && endpoint.Spec.PodRef.Interface == nic.Spec.PodRef.Interface {
			matches = append(matches, endpoint)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Sprintf("NetworkInterface %s/%s has no NetworkEndpoint yet; its Pod is not running", nic.Namespace, nic.Name), nil
	case 1:
		return matches[0], "", nil
	default:
		return nil, fmt.Sprintf("NetworkInterface %s/%s has %d NetworkEndpoints", nic.Namespace, nic.Name, len(matches)), nil
	}
}

func blackholeRoute(route juneauv1alpha1.Route, message string) juneauv1alpha1.ResolvedRoute {
	return juneauv1alpha1.ResolvedRoute{
		Dst:     route.Dst,
		Via:     route.Via,
		State:   juneauv1alpha1.RouteStateBlackhole,
		Message: message,
	}
}

func indexNetworkInterfaceByAllocationIdentity(ctx context.Context, indexer client.FieldIndexer) error {
	if err := indexer.IndexField(ctx, &juneauv1alpha1.NetworkInterface{}, networkInterfaceAllocationIdentityIndex,
		func(obj client.Object) []string {
			nic := obj.(*juneauv1alpha1.NetworkInterface)
			if nic.Spec.AllocationIdentity == "" {
				return nil
			}
			return []string{nic.Spec.AllocationIdentity}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for NetworkInterface.%s: %w", networkInterfaceAllocationIdentityIndex, err)
	}
	return nil
}

func indexRouteTableByEndpointNamespace(ctx context.Context, indexer client.FieldIndexer) error {
	if err := indexer.IndexField(ctx, &juneauv1alpha1.RouteTable{}, routeTableEndpointNamespaceIndex,
		func(obj client.Object) []string {
			rt := obj.(*juneauv1alpha1.RouteTable)
			var namespaces []string
			for _, route := range rt.Spec.Routes {
				if route.Via.Type != juneauv1alpha1.ViaEndpoint || route.Via.Endpoint == nil {
					continue
				}
				if !slices.Contains(namespaces, route.Via.Endpoint.Namespace) {
					namespaces = append(namespaces, route.Via.Endpoint.Namespace)
				}
			}
			return namespaces
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for RouteTable.%s: %w", routeTableEndpointNamespaceIndex, err)
	}
	return nil
}

// routeTablesWithEndpointsIn wakes every RouteTable with an endpoint route
// into the namespace. The objects an endpoint route depends on all live in
// that namespace or point back to it, and a change to any of them can move
// the route to another endpoint or turn it into a blackhole.
func (r *RouteTableReconciler) routeTablesWithEndpointsIn(ctx context.Context, namespace string) []reconcile.Request {
	if namespace == "" {
		return nil
	}
	var routeTables juneauv1alpha1.RouteTableList
	if err := r.List(ctx, &routeTables, client.MatchingFields{routeTableEndpointNamespaceIndex: namespace}); err != nil {
		log.FromContext(ctx).Error(err, "list RouteTables with endpoint routes", "namespace", namespace)
		return nil
	}
	requests := make([]reconcile.Request, 0, len(routeTables.Items))
	for i := range routeTables.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: routeTables.Items[i].Name}})
	}
	return requests
}

func (r *RouteTableReconciler) mapNetworkEndpointToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.routeTablesWithEndpointsIn(ctx, obj.GetNamespace())
}

func (r *RouteTableReconciler) mapNetworkInterfaceToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.routeTablesWithEndpointsIn(ctx, obj.GetNamespace())
}

// mapClaimToRouteTables wakes the RouteTable that owns a table ID claim,
// and the RouteTables that may route to the NetworkInterface behind an
// address claim.
func (r *RouteTableReconciler) mapClaimToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	claim, ok := obj.(*juneauv1alpha1.AllocationClaim)
	if !ok {
		return nil
	}
	return r.routeTablesOfClaim(ctx, claim)
}

func (r *RouteTableReconciler) routeTablesOfClaim(ctx context.Context, claim *juneauv1alpha1.AllocationClaim) []reconcile.Request {
	switch claim.Spec.ResourceRef.Kind {
	case "RouteTable":
		if claim.Spec.ResourceRef.Name == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.ResourceRef.Name}}}
	case "NetworkInterface":
		return r.routeTablesWithEndpointsIn(ctx, claim.Spec.ResourceRef.Namespace)
	default:
		return nil
	}
}

// mapLeaseToRouteTables follows a lease to the claim that holds it. When
// that claim is already gone, so is its NetworkInterface, and the delete
// of either one has woken the RouteTables already.
func (r *RouteTableReconciler) mapLeaseToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	lease, ok := obj.(*juneauv1alpha1.AllocationLease)
	if !ok || lease.Spec.ClaimRef.Name == "" {
		return nil
	}
	var claim juneauv1alpha1.AllocationClaim
	if err := r.Get(ctx, client.ObjectKey{Name: lease.Spec.ClaimRef.Name}, &claim); err != nil {
		if !errors.IsNotFound(err) {
			log.FromContext(ctx).Error(err, "get the AllocationClaim that holds a lease", "lease", lease.Name)
		}
		return nil
	}
	if claim.Spec.ResourceRef.Kind != "NetworkInterface" {
		return nil
	}
	return r.routeTablesOfClaim(ctx, &claim)
}
