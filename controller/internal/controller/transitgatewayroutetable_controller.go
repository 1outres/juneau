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
	stderrors "errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	transitGatewayRouteTableReasonDeleting              = "Deleting"
	transitGatewayRouteTableReasonReconcileFailed       = "ReconcileFailed"
	transitGatewayRouteTableReasonReconcileSucceeded    = "ReconcileSucceeded"
	transitGatewayRouteTableReasonNotReady              = "NotReady"
	transitGatewayRouteTableReasonVPNRoutePending       = "VPNRoutePending"
	transitGatewayRouteTableReasonTransitGatewayMissing = "TransitGatewayNotFound"
	transitGatewayRouteTableReasonAmbiguousRoute        = "AmbiguousRoute"

	transitGatewayRouteTableRequeueAfter = 100 * time.Millisecond
)

// TransitGatewayRouteTableReconciler reconciles a
// TransitGatewayRouteTable object.
//
// The resolved table in status.routes is what the data plane programs:
// every attachment that propagates into this table contributes its
// Vpc's Subnets, and the static spec.routes override those for the same
// destination. A static route can also target an explicit VPN route in
// the attached Vpc.
type TransitGatewayRouteTableReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgatewayroutetables,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgatewayroutetables/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgatewayroutetables/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgatewayattachments,verbs=get;list;watch

func (r *TransitGatewayRouteTableReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauloutresmev1alpha1.TransitGatewayRouteTable
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get TransitGatewayRouteTable", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		if err := r.updateStatus(ctx, &resource, resource.Status.Routes, resource.Status.TableID, metav1.ConditionFalse, transitGatewayRouteTableReasonDeleting, "transit gateway route table is being deleted"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	var transitGateway juneauloutresmev1alpha1.TransitGateway
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.TransitGateway}, &transitGateway); err != nil {
		if errors.IsNotFound(err) {
			if updateErr := r.updateStatus(ctx, &resource, resource.Status.Routes, resource.Status.TableID, metav1.ConditionFalse, transitGatewayRouteTableReasonTransitGatewayMissing, fmt.Sprintf("TransitGateway %q not found", resource.Spec.TransitGateway)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
		if updateErr := r.updateStatus(ctx, &resource, resource.Status.Routes, resource.Status.TableID, metav1.ConditionFalse, transitGatewayRouteTableReasonReconcileFailed, fmt.Sprintf("failed to get TransitGateway %q", resource.Spec.TransitGateway)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	var attachmentList juneauloutresmev1alpha1.TransitGatewayAttachmentList
	if err := r.List(ctx, &attachmentList); err != nil {
		if updateErr := r.updateStatus(ctx, &resource, resource.Status.Routes, resource.Status.TableID, metav1.ConditionFalse, transitGatewayRouteTableReasonReconcileFailed, "failed to list transit gateway attachments"); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	routes, conflicts := propagatedRoutes(&resource, attachmentList.Items)
	if len(conflicts) > 0 {
		if err := r.updateStatus(ctx, &resource, resource.Status.Routes, resource.Status.TableID, metav1.ConditionFalse, transitGatewayRouteTableReasonAmbiguousRoute, strings.Join(conflicts, "; ")); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	pendingVPN := ""
	for _, route := range resource.Spec.Routes {
		resolved, message, err := r.resolveStaticRoute(ctx, &resource, route, attachmentList.Items)
		var pending *transitVPNPending
		if stderrors.As(err, &pending) {
			if pendingVPN == "" || pendingVPN == pending.key {
				pendingVPN = pending.key
				continue
			}
			if updateErr := r.updateStatus(ctx, &resource, nil, resource.Status.TableID, metav1.ConditionFalse, transitGatewayRouteTableReasonNotReady, "more than one VPN route is pending"); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
		if err != nil {
			if updateErr := r.updateStatus(ctx, &resource, nil, resource.Status.TableID, metav1.ConditionFalse, transitGatewayRouteTableReasonReconcileFailed, fmt.Sprintf("failed to resolve static route %s: %v", route.Dst, err)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		if message != "" {
			if err := r.updateStatus(ctx, &resource, resource.Status.Routes, resource.Status.TableID, metav1.ConditionFalse, transitGatewayRouteTableReasonNotReady, message); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		routes[route.Dst] = resolved
	}

	if pendingVPN != "" {
		return ctrl.Result{}, r.updateStatusPendingVPN(ctx, &resource, pendingVPN)
	}
	statusRoutes := make([]juneauloutresmev1alpha1.ResolvedTransitGatewayRoute, 0, len(routes))
	for _, route := range routes {
		statusRoutes = append(statusRoutes, route)
	}
	sort.Slice(statusRoutes, func(i, j int) bool { return statusRoutes[i].Dst < statusRoutes[j].Dst })
	if len(statusRoutes) == 0 {
		statusRoutes = nil
	}

	tableID := resource.Status.TableID
	if tableID == 0 {
		claim, err := r.ensureNumberClaim(ctx, &resource, allocationPoolTransitGatewayRouteTable, schema.GroupVersionKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Version: juneauloutresmev1alpha1.GroupVersion.Version, Kind: "TransitGatewayRouteTable"}, "status.tableID")
		if err != nil {
			if updateErr := r.updateStatus(ctx, &resource, statusRoutes, tableID, metav1.ConditionFalse, transitGatewayRouteTableReasonReconcileFailed, fmt.Sprintf("failed to ensure table ID allocation claim: %v", err)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		if claim.Status.Phase != juneauloutresmev1alpha1.AllocationClaimPhaseAllocated || claim.Status.Value.Number == 0 {
			if err := r.updateStatus(ctx, &resource, statusRoutes, tableID, metav1.ConditionFalse, transitGatewayRouteTableReasonNotReady, "waiting for table ID allocation"); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: transitGatewayRouteTableRequeueAfter}, nil
		}
		if claim.Status.Value.Number > uint64(^uint32(0)) {
			if err := r.updateStatus(ctx, &resource, statusRoutes, tableID, metav1.ConditionFalse, transitGatewayRouteTableReasonReconcileFailed, fmt.Sprintf("allocated table ID %d exceeds supported range", claim.Status.Value.Number)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}

		tableID = uint32(claim.Status.Value.Number)
	}

	if err := r.updateStatus(ctx, &resource, statusRoutes, tableID, metav1.ConditionTrue, transitGatewayRouteTableReasonReconcileSucceeded, ""); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// propagatedRoutes expands the prefixes of every attachment that
// advertises into this route table, keyed by destination. Two
// attachments claiming the same destination is reported instead of
// resolved: picking one silently would send half the traffic to the
// wrong Vpc with nothing in status to explain it.
func propagatedRoutes(routeTable *juneauloutresmev1alpha1.TransitGatewayRouteTable, attachments []juneauloutresmev1alpha1.TransitGatewayAttachment) (map[string]juneauloutresmev1alpha1.ResolvedTransitGatewayRoute, []string) {
	routes := map[string]juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}
	var conflicts []string

	sorted := make([]*juneauloutresmev1alpha1.TransitGatewayAttachment, 0, len(attachments))
	for i := range attachments {
		if attachments[i].Spec.TransitGateway != routeTable.Spec.TransitGateway {
			continue
		}
		if !attachments[i].Spec.PropagatesInto(routeTable.Name) {
			continue
		}
		sorted = append(sorted, &attachments[i])
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	for _, attachment := range sorted {
		for _, prefix := range attachment.Status.Prefixes {
			if existing, ok := routes[prefix.CIDR]; ok {
				conflicts = append(conflicts, fmt.Sprintf(
					"destination %q is propagated by both TransitGatewayAttachment %q and TransitGatewayAttachment %q",
					prefix.CIDR, existing.Attachment, attachment.Name))
				continue
			}
			routes[prefix.CIDR] = juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{
				Dst:        prefix.CIDR,
				Attachment: attachment.Name,
				Subnet:     prefix.Subnet,
				Origin:     juneauloutresmev1alpha1.TransitGatewayRouteOriginPropagated,
			}
		}
	}

	sort.Strings(conflicts)
	return routes, conflicts
}

// resolveStaticRoute turns one spec.routes entry into the resolved form
// the data plane reads. The second return value is a non-empty message
// when the route cannot be resolved.
func (r *TransitGatewayRouteTableReconciler) resolveStaticRoute(ctx context.Context, routeTable *juneauloutresmev1alpha1.TransitGatewayRouteTable, route juneauloutresmev1alpha1.TransitGatewayRoute, attachments []juneauloutresmev1alpha1.TransitGatewayAttachment) (juneauloutresmev1alpha1.ResolvedTransitGatewayRoute, string, error) {
	if route.Blackhole {
		return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{
			Dst:       route.Dst,
			Blackhole: true,
			Origin:    juneauloutresmev1alpha1.TransitGatewayRouteOriginStatic,
		}, "", nil
	}

	var attachment *juneauloutresmev1alpha1.TransitGatewayAttachment
	for i := range attachments {
		if attachments[i].Name == route.Attachment {
			attachment = &attachments[i]
			break
		}
	}
	if attachment == nil {
		return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, fmt.Sprintf("TransitGatewayAttachment %q not found", route.Attachment), nil
	}
	if attachment.Spec.TransitGateway != routeTable.Spec.TransitGateway {
		return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, fmt.Sprintf(
			"TransitGatewayAttachment %q belongs to TransitGateway %q, not %q",
			attachment.Name, attachment.Spec.TransitGateway, routeTable.Spec.TransitGateway), nil
	}

	// The data plane resolves the route to one destination Subnet VNI,
	// so a prefix that spans several Subnets has no single answer.
	for _, prefix := range attachment.Status.Prefixes {
		if prefix.CIDR == route.Dst {
			return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{
				Dst:        route.Dst,
				Attachment: attachment.Name,
				Subnet:     prefix.Subnet,
				Origin:     juneauloutresmev1alpha1.TransitGatewayRouteOriginStatic,
			}, "", nil
		}
	}

	resolved, message, err := r.resolveTransitVPNRoute(ctx, attachment, route.Dst)
	if err != nil || message == "" {
		return resolved, message, err
	}
	return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, fmt.Sprintf("no Subnet in Vpc %q has CIDR %q and %s", attachment.Spec.Vpc, route.Dst, message), nil
}

type transitVPNPending struct {
	key     string
	message string
}

func (p *transitVPNPending) Error() string { return p.message }

func (r *TransitGatewayRouteTableReconciler) resolveTransitVPNRoute(ctx context.Context, attachment *juneauloutresmev1alpha1.TransitGatewayAttachment, dst string) (juneauloutresmev1alpha1.ResolvedTransitGatewayRoute, string, error) {
	if attachment.DeletionTimestamp != nil || !conditionReady(attachment.Status.Conditions, juneauloutresmev1alpha1.TransitGatewayAttachmentStatusReady, attachment.Generation) {
		return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "VPN route attachment is not Ready", nil
	}
	var tables juneauloutresmev1alpha1.RouteTableList
	if err := r.List(ctx, &tables); err != nil {
		return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "", err
	}
	var vpc juneauloutresmev1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: attachment.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "VPN route attached Vpc is missing", nil
		}
		return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "", err
	}
	var found *juneauloutresmev1alpha1.ResolvedTransitGatewayRoute
	for i := range tables.Items {
		table := &tables.Items[i]
		if table.Spec.Vpc != attachment.Spec.Vpc || table.DeletionTimestamp != nil {
			continue
		}
		candidate := transitVPNRoute(table, dst)
		if candidate != nil {
			var vpn juneauloutresmev1alpha1.VPN
			if err := r.Get(ctx, client.ObjectKey{Namespace: candidate.Via.VPN.Namespace, Name: candidate.Via.VPN.Name}, &vpn); err != nil {
				if errors.IsNotFound(err) {
					return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "VPN route references a missing VPN", nil
				}
				return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "", err
			}
			if vpn.Spec.Vpc != attachment.Spec.Vpc || vpn.DeletionTimestamp != nil {
				return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "VPN route references a VPN outside the attached Vpc", nil
			}
			var subnet juneauloutresmev1alpha1.Subnet
			if err := r.Get(ctx, client.ObjectKey{Name: vpn.Spec.Subnet}, &subnet); err != nil {
				if errors.IsNotFound(err) {
					return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "VPN gateway Subnet is missing", nil
				}
				return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "", err
			}
			gatewayTable := subnet.Spec.RouteTable
			if gatewayTable == "" {
				gatewayTable = vpc.Status.MainRouteTable
			}
			if table.Name != gatewayTable {
				continue
			}
			if !conditionReady(table.Status.Conditions, juneauloutresmev1alpha1.RouteTableStatusReady, table.Generation) {
				if vpnTableReady(table, &vpn) {
					return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "", &transitVPNPending{key: vpn.Namespace + "/" + vpn.Name, message: "VPN gateway RouteTable is not Ready"}
				}
				return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "VPN gateway RouteTable is not Ready", nil
			}
			gateway, err := (&RouteTableReconciler{Client: r.Client}).resolveVPNRoute(ctx, attachment.Spec.Vpc, candidate.Via.VPN)
			if err != nil {
				if stderrors.Is(err, errVPNRoutePending) {
					return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "", &transitVPNPending{key: vpn.Namespace + "/" + vpn.Name, message: fmt.Sprintf("VPN route is not ready: %v", err)}
				}
				return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, fmt.Sprintf("VPN route is not ready: %v", err), nil
			}
			if found != nil {
				return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "ambiguous VPN route in attached Vpc", nil
			}
			found = &juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{
				Dst: dst, Attachment: attachment.Name, Subnet: gateway,
				VPN: candidate.Via.VPN.DeepCopy(), Origin: juneauloutresmev1alpha1.TransitGatewayRouteOriginStatic,
			}
		}
	}
	if found == nil {
		return juneauloutresmev1alpha1.ResolvedTransitGatewayRoute{}, "no explicit VPN route in the attached Vpc gateway RouteTable", nil
	}
	return *found, "", nil
}

func transitVPNRoute(table *juneauloutresmev1alpha1.RouteTable, dst string) *juneauloutresmev1alpha1.Route {
	prefix, err := netip.ParsePrefix(dst)
	if err != nil || !prefix.Addr().Is4() {
		return nil
	}
	var best *juneauloutresmev1alpha1.Route
	bestBits := -1
	for i := range table.Spec.Routes {
		candidate := &table.Spec.Routes[i]
		p, err := netip.ParsePrefix(candidate.Dst)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		if p.Overlaps(prefix) && p.Bits() > prefix.Bits() {
			return nil
		}
		if p.Bits() <= prefix.Bits() && p.Contains(prefix.Addr()) && p.Bits() > bestBits {
			best, bestBits = candidate, p.Bits()
		}
	}
	if best == nil || best.Via.Type != juneauloutresmev1alpha1.ViaVPN || best.Via.VPN == nil {
		return nil
	}
	return best
}

func (r *TransitGatewayRouteTableReconciler) ensureNumberClaim(ctx context.Context, resource *juneauloutresmev1alpha1.TransitGatewayRouteTable, poolName string, gvk schema.GroupVersionKind, attribute string) (*juneauloutresmev1alpha1.AllocationClaim, error) {
	claim := newAllocationClaim(poolName, gvk, "", resource.Name, attribute)
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, claim, func() error {
		claim.Spec = newAllocationClaim(poolName, gvk, "", resource.Name, attribute).Spec
		return controllerutil.SetControllerReference(resource, claim, r.Scheme)
	})
	if err != nil {
		return nil, err
	}
	return claim, nil
}

func (r *TransitGatewayRouteTableReconciler) updateStatus(ctx context.Context, resource *juneauloutresmev1alpha1.TransitGatewayRouteTable, routes []juneauloutresmev1alpha1.ResolvedTransitGatewayRoute, tableID uint32, ready metav1.ConditionStatus, reason, message string) error {
	return r.writeStatus(ctx, resource, routes, tableID, ready, reason, message, "")
}

func (r *TransitGatewayRouteTableReconciler) updateStatusPendingVPN(ctx context.Context, resource *juneauloutresmev1alpha1.TransitGatewayRouteTable, key string) error {
	return r.writeStatus(ctx, resource, nil, resource.Status.TableID, metav1.ConditionFalse, transitGatewayRouteTableReasonVPNRoutePending, "VPN "+key+" route is waiting for its gateway endpoint", key)
}

func (r *TransitGatewayRouteTableReconciler) writeStatus(ctx context.Context, resource *juneauloutresmev1alpha1.TransitGatewayRouteTable, routes []juneauloutresmev1alpha1.ResolvedTransitGatewayRoute, tableID uint32, ready metav1.ConditionStatus, reason, message, pendingVPN string) error {
	updated := resource.DeepCopy()
	updated.Status.PendingVPN = pendingVPN
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.Routes = routes
	updated.Status.TableID = tableID
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:               juneauloutresmev1alpha1.TransitGatewayRouteTableStatusReady,
		Status:             ready,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: updated.Generation,
	})

	if updated.Status.ObservedGeneration == resource.Status.ObservedGeneration &&
		updated.Status.TableID == resource.Status.TableID &&
		updated.Status.PendingVPN == resource.Status.PendingVPN &&
		reflect.DeepEqual(updated.Status.Routes, resource.Status.Routes) &&
		reflect.DeepEqual(updated.Status.Conditions, resource.Status.Conditions) {
		return nil
	}

	resource.Status = updated.Status
	return r.Status().Update(ctx, resource)
}

// SetupWithManager sets up the controller with the Manager.
func (r *TransitGatewayRouteTableReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.TransitGatewayRouteTable{}).
		Watches(&juneauloutresmev1alpha1.TransitGateway{}, handler.EnqueueRequestsFromMapFunc(r.mapTransitGatewayToRouteTables)).
		Watches(&juneauloutresmev1alpha1.TransitGatewayAttachment{}, handler.EnqueueRequestsFromMapFunc(r.mapAttachmentToRouteTables)).
		Watches(&juneauloutresmev1alpha1.RouteTable{}, handler.EnqueueRequestsFromMapFunc(r.mapVPNDependencyToRouteTables)).
		Watches(&juneauloutresmev1alpha1.VPN{}, handler.EnqueueRequestsFromMapFunc(r.mapVPNDependencyToRouteTables)).
		Watches(&juneauloutresmev1alpha1.Subnet{}, handler.EnqueueRequestsFromMapFunc(r.mapVPNDependencyToRouteTables)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapVPNDependencyToRouteTables)).
		Watches(&juneauloutresmev1alpha1.NetworkInterface{}, handler.EnqueueRequestsFromMapFunc(r.mapVPNDependencyToRouteTables)).
		Watches(&juneauloutresmev1alpha1.NetworkEndpoint{}, handler.EnqueueRequestsFromMapFunc(r.mapVPNDependencyToRouteTables)).
		Watches(&juneauloutresmev1alpha1.AllocationClaim{}, handler.EnqueueRequestsFromMapFunc(r.mapClaimToRouteTables)).
		Named("transitgatewayroutetable").
		Complete(r)
}

func (r *TransitGatewayRouteTableReconciler) mapVPNDependencyToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	switch dependency := obj.(type) {
	case *corev1.Pod:
		if !strings.HasPrefix(dependency.Name, "vpn-") {
			return nil
		}
	case *juneauloutresmev1alpha1.NetworkInterface:
		if !strings.HasPrefix(dependency.Spec.PodRef.Name, "vpn-") {
			return nil
		}
	case *juneauloutresmev1alpha1.NetworkEndpoint:
		if !strings.HasPrefix(dependency.Name, "vpn-") {
			return nil
		}
	}
	var tables juneauloutresmev1alpha1.TransitGatewayRouteTableList
	if err := r.List(ctx, &tables); err != nil {
		log.FromContext(ctx).Error(err, "list TransitGatewayRouteTables for VPN update")
		return nil
	}
	var requests []reconcile.Request
	for i := range tables.Items {
		for _, route := range tables.Items[i].Spec.Routes {
			if !route.Blackhole {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: tables.Items[i].Name}})
				break
			}
		}
	}
	return requests
}

func (r *TransitGatewayRouteTableReconciler) mapTransitGatewayToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	transitGateway, ok := obj.(*juneauloutresmev1alpha1.TransitGateway)
	if !ok {
		return nil
	}
	return r.routeTablesOfTransitGateway(ctx, transitGateway.Name)
}

// mapAttachmentToRouteTables enqueues every route table of the
// attachment's gateway. The attachment feeds propagated routes into the
// tables it propagates to and static routes may name it from any table
// of the same gateway, so a narrower fan-out would miss updates.
func (r *TransitGatewayRouteTableReconciler) mapAttachmentToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	attachment, ok := obj.(*juneauloutresmev1alpha1.TransitGatewayAttachment)
	if !ok || attachment.Spec.TransitGateway == "" {
		return nil
	}
	return r.routeTablesOfTransitGateway(ctx, attachment.Spec.TransitGateway)
}

func (r *TransitGatewayRouteTableReconciler) mapClaimToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	_ = ctx
	claim, ok := obj.(*juneauloutresmev1alpha1.AllocationClaim)
	if !ok || claim.Spec.ResourceRef.Kind != "TransitGatewayRouteTable" || claim.Spec.ResourceRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.ResourceRef.Name}}}
}

func (r *TransitGatewayRouteTableReconciler) routeTablesOfTransitGateway(ctx context.Context, transitGateway string) []reconcile.Request {
	var routeTableList juneauloutresmev1alpha1.TransitGatewayRouteTableList
	if err := r.List(ctx, &routeTableList); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(routeTableList.Items))
	for i := range routeTableList.Items {
		if routeTableList.Items[i].Spec.TransitGateway != transitGateway {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: routeTableList.Items[i].Name}})
	}
	return requests
}
