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
	"net"
	"reflect"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
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

// serviceVpcAnnotation mirrors webhook.ServiceAnnotationVpc and
// svcpolicy.AnnotationVpc. Duplicated as a literal so the controller
// package does not pull the daemon-side svcpolicy or the webhook
// package into its dependency graph.
const serviceVpcAnnotation = "juneau.loutres.me/vpc"

const (
	routeTableReasonDeleting           = "Deleting"
	routeTableReasonReconcileFailed    = "ReconcileFailed"
	routeTableReasonReconcileSucceeded = "ReconcileSucceeded"
	routeTableReasonNotReady           = "NotReady"
)

// RouteTableReconciler reconciles a RouteTable object
type RouteTableReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// ServiceCIDR is the cluster-wide CIDR used by Kubernetes Services.
	// When the owning VPC has Service routing enabled (any of
	// spec.service.provider / spec.service.consume configured), the
	// reconciler injects a route for this CIDR with via.type=service
	// into the RouteTable's status.routes.
	ServiceCIDR *net.IPNet
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=routetables,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=routetables/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=routetables/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkinterfaces;networkendpoints;allocationleases,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the RouteTable object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile
func (r *RouteTableReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauloutresmev1alpha1.RouteTable
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get RouteTable", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		if err := r.updateStatus(ctx, &resource, resource.Status.Routes, resource.Status.TableID, metav1.ConditionFalse, routeTableReasonDeleting, "route table is being deleted"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	var statusRoutes []juneauloutresmev1alpha1.ResolvedRoute
	var subnetNames []string

	var vpc juneauloutresmev1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.Vpc}, &vpc); err != nil && !errors.IsNotFound(err) {
		if updateErr := r.updateStatus(ctx, &resource, resource.Status.Routes, resource.Status.TableID, metav1.ConditionFalse, routeTableReasonReconcileFailed, "failed to fetch VPC"); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	var subnets juneauloutresmev1alpha1.SubnetList
	if err := r.List(ctx, &subnets, client.MatchingFields{"spec.vpc": resource.Spec.Vpc}); err != nil {
		if updateErr := r.updateStatus(ctx, &resource, resource.Status.Routes, resource.Status.TableID, metav1.ConditionFalse, routeTableReasonReconcileFailed, "failed to list subnets for VPC"); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}
	for _, subnet := range subnets.Items {
		statusRoutes = append(statusRoutes, juneauloutresmev1alpha1.ResolvedRoute{
			State:  juneauloutresmev1alpha1.RouteStateActive,
			Dst:    subnet.Spec.CIDR,
			Subnet: subnet.Name,
			Via: juneauloutresmev1alpha1.RouteVia{
				Type: juneauloutresmev1alpha1.ViaConnected,
			},
		})
		subnetNames = append(subnetNames, subnet.Name)
	}

	// An L2Network is reachable from the Vpc only through its gateway,
	// so only a segment that declares one gets a route. A segment with
	// no CIDR has no destination to write down at all.
	var l2Networks juneauloutresmev1alpha1.L2NetworkList
	if err := r.List(ctx, &l2Networks, client.MatchingFields{"spec.vpc": resource.Spec.Vpc}); err != nil {
		if updateErr := r.updateStatus(ctx, &resource, resource.Status.Routes, resource.Status.TableID, metav1.ConditionFalse, routeTableReasonReconcileFailed, "failed to list l2networks for VPC"); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}
	for i := range l2Networks.Items {
		l2 := &l2Networks.Items[i]
		if l2.Spec.Gateway == nil || l2.Spec.CIDR == "" {
			continue
		}
		statusRoutes = append(statusRoutes, juneauloutresmev1alpha1.ResolvedRoute{
			State:     juneauloutresmev1alpha1.RouteStateActive,
			Dst:       l2.Spec.CIDR,
			L2Network: l2.Name,
			Via: juneauloutresmev1alpha1.RouteVia{
				Type: juneauloutresmev1alpha1.ViaConnected,
			},
		})
	}

	if vpc.Spec.ServiceEnabled() && r.ServiceCIDR != nil {
		statusRoutes = append(statusRoutes, juneauloutresmev1alpha1.ResolvedRoute{
			State: juneauloutresmev1alpha1.RouteStateActive,
			Dst:   r.ServiceCIDR.String(),
			Via: juneauloutresmev1alpha1.RouteVia{
				Type: juneauloutresmev1alpha1.ViaService,
			},
		})
	}

	// Per-Service /32 routes for spec.externalIPs entries owned by this
	// Vpc. The BPF FIB is an LPM_TRIE so a /32 wins over the cluster
	// Service CIDR (whether or not the externalIP is inside it). Only
	// the owner Vpc's RouteTables get the route — injecting it into
	// every Vpc would silently strand legitimate egress through other
	// Vpcs to the same IP.
	if vpc.Spec.ServiceEnabled() {
		extRoutes, err := r.collectExternalIPRoutes(ctx, &vpc)
		if err != nil {
			if updateErr := r.updateStatus(ctx, &resource, statusRoutes, resource.Status.TableID, metav1.ConditionFalse, routeTableReasonReconcileFailed, fmt.Sprintf("failed to collect Service externalIPs: %v", err)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		statusRoutes = append(statusRoutes, extRoutes...)
	}

	statusRoutes = append(statusRoutes, vpcEndpointPoolRoutes(&vpc)...)

	// The default VPC's main RouteTable optionally carries a 0/0
	// route via the default NATGateway. The route is only injected
	// when a default NATGateway exists and is Ready. Operators that
	// need internet egress in the default VPC must either bootstrap
	// the default ExternalNetwork + NATGateway pair or add their own
	// 0/0 route.
	if resource.Name == defaultVpcName && resource.Spec.Vpc == defaultVpcName {
		var defaultNATGW juneauloutresmev1alpha1.NATGateway
		err := r.Get(ctx, client.ObjectKey{Name: defaultVpcName}, &defaultNATGW)
		if err == nil && defaultNATGW.Status.GatewayID != 0 {
			statusRoutes = append(statusRoutes, juneauloutresmev1alpha1.ResolvedRoute{
				State: juneauloutresmev1alpha1.RouteStateActive,
				Dst:   "0.0.0.0/0",
				Via: juneauloutresmev1alpha1.RouteVia{
					Type:       juneauloutresmev1alpha1.ViaNATGateway,
					NATGateway: defaultNATGW.Name,
				},
			})
		} else if err != nil && !errors.IsNotFound(err) {
			if updateErr := r.updateStatus(ctx, &resource, statusRoutes, resource.Status.TableID, metav1.ConditionFalse, routeTableReasonReconcileFailed, fmt.Sprintf("failed to fetch default NATGateway: %v", err)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
	}

	for _, route := range resource.Spec.Routes {
		if getRoute(statusRoutes, route.Dst) != nil {
			continue
		}
		resolved, err := r.resolveSpecRoute(ctx, &resource, route, subnetNames)
		var notReady *routeNotReadyError
		switch {
		case stderrors.As(err, &notReady):
			if err := r.updateStatus(ctx, &resource, statusRoutes, resource.Status.TableID, metav1.ConditionFalse, routeTableReasonNotReady, notReady.message); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		case err != nil:
			if updateErr := r.updateStatus(ctx, &resource, statusRoutes, resource.Status.TableID, metav1.ConditionFalse, routeTableReasonReconcileFailed, err.Error()); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		if resolved != nil {
			statusRoutes = append(statusRoutes, *resolved)
		}
	}
	tableID := resource.Status.TableID
	if tableID == 0 {
		claim, err := r.ensureNumberClaim(ctx, &resource, allocationPoolRouteTableID, schema.GroupVersionKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Version: juneauloutresmev1alpha1.GroupVersion.Version, Kind: "RouteTable"}, "status.tableID")
		if err != nil {
			if updateErr := r.updateStatus(ctx, &resource, statusRoutes, tableID, metav1.ConditionFalse, routeTableReasonReconcileFailed, fmt.Sprintf("failed to ensure table ID allocation claim: %v", err)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		if claim.Status.Phase != juneauloutresmev1alpha1.AllocationClaimPhaseAllocated || claim.Status.Value.Number == 0 {
			if err := r.updateStatus(ctx, &resource, statusRoutes, tableID, metav1.ConditionFalse, routeTableReasonNotReady, "waiting for table ID allocation"); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 100 * time.Millisecond}, nil
		}
		if claim.Status.Value.Number > uint64(^uint32(0)) {
			if err := r.updateStatus(ctx, &resource, statusRoutes, tableID, metav1.ConditionFalse, routeTableReasonReconcileFailed, fmt.Sprintf("allocated table ID %d exceeds supported range", claim.Status.Value.Number)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}

		tableID = uint32(claim.Status.Value.Number)
	}

	if err := r.updateStatus(ctx, &resource, statusRoutes, tableID, metav1.ConditionTrue, routeTableReasonReconcileSucceeded, ""); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *RouteTableReconciler) updateStatus(ctx context.Context, resource *juneauloutresmev1alpha1.RouteTable, routes []juneauloutresmev1alpha1.ResolvedRoute, tableID uint32, ready metav1.ConditionStatus, reason, message string) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.Routes = routes
	updated.Status.TableID = tableID
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:               juneauloutresmev1alpha1.RouteTableStatusReady,
		Status:             ready,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: updated.Generation,
	})

	if updated.Status.ObservedGeneration == resource.Status.ObservedGeneration &&
		updated.Status.TableID == resource.Status.TableID &&
		reflect.DeepEqual(updated.Status.Routes, resource.Status.Routes) &&
		reflect.DeepEqual(updated.Status.Conditions, resource.Status.Conditions) {
		return nil
	}

	resource.Status = updated.Status
	return r.Status().Update(ctx, resource)
}

func getRoute(routes []juneauloutresmev1alpha1.ResolvedRoute, dst string) *juneauloutresmev1alpha1.ResolvedRoute {
	for i := range routes {
		if routes[i].Dst == dst {
			return &routes[i]
		}
	}
	return nil
}

// routeNotReadyError stops the whole RouteTable: a referenced object is
// missing or not ready yet, and the table waits for it.
type routeNotReadyError struct {
	message string
}

func (e *routeNotReadyError) Error() string { return e.message }

func routeNotReady(format string, args ...any) error {
	return &routeNotReadyError{message: fmt.Sprintf(format, args...)}
}

// resolveSpecRoute turns one entry of spec.routes into the route the data
// plane programs. It returns nil for a route type the controller already
// writes on its own. A *routeNotReadyError makes the whole table wait;
// any other error is a failure to read the cluster.
//
// An endpoint route never makes the table wait. Its endpoint comes and
// goes with the Pods of a workload, so while it cannot be used the route
// drops traffic and the other routes keep working.
func (r *RouteTableReconciler) resolveSpecRoute(ctx context.Context, rt *juneauloutresmev1alpha1.RouteTable, route juneauloutresmev1alpha1.Route, vpcSubnets []string) (*juneauloutresmev1alpha1.ResolvedRoute, error) {
	switch route.Via.Type {
	case juneauloutresmev1alpha1.ViaConnected,
		juneauloutresmev1alpha1.ViaService,
		juneauloutresmev1alpha1.ViaVpcEndpoint:
		return nil, nil
	case juneauloutresmev1alpha1.ViaInternetGateway:
		return activeRoute(route), nil
	case juneauloutresmev1alpha1.ViaBlackhole:
		resolved := blackholeRoute(route, "")
		return &resolved, nil
	case juneauloutresmev1alpha1.ViaEndpoint:
		resolved, err := r.resolveEndpointRoute(ctx, rt, route, vpcSubnets)
		if err != nil {
			return nil, err
		}
		return &resolved, nil
	case juneauloutresmev1alpha1.ViaNATGateway:
		return r.resolveNATGatewayRoute(ctx, rt, route)
	case juneauloutresmev1alpha1.ViaVpcPeering:
		return r.resolveVpcPeeringRoute(ctx, rt, route)
	case juneauloutresmev1alpha1.ViaTransitGateway:
		return r.resolveTransitGatewayRoute(ctx, rt, route)
	default:
		return nil, routeNotReady("route to %q has unsupported type %q", route.Dst, route.Via.Type)
	}
}

func activeRoute(route juneauloutresmev1alpha1.Route) *juneauloutresmev1alpha1.ResolvedRoute {
	return &juneauloutresmev1alpha1.ResolvedRoute{
		Dst:   route.Dst,
		Via:   route.Via,
		State: juneauloutresmev1alpha1.RouteStateActive,
	}
}

func (r *RouteTableReconciler) resolveNATGatewayRoute(ctx context.Context, rt *juneauloutresmev1alpha1.RouteTable, route juneauloutresmev1alpha1.Route) (*juneauloutresmev1alpha1.ResolvedRoute, error) {
	var natGateway juneauloutresmev1alpha1.NATGateway
	if err := r.Get(ctx, client.ObjectKey{Name: route.Via.NATGateway}, &natGateway); err != nil {
		if errors.IsNotFound(err) {
			return nil, routeNotReady("NATGateway %q not found", route.Via.NATGateway)
		}
		return nil, fmt.Errorf("failed to get NATGateway %q: %w", route.Via.NATGateway, err)
	}
	if natGateway.Spec.Vpc != rt.Spec.Vpc {
		return nil, routeNotReady("NATGateway %q belongs to Vpc %q, not %q", natGateway.Name, natGateway.Spec.Vpc, rt.Spec.Vpc)
	}
	if natGateway.Status.GatewayID == 0 {
		return nil, routeNotReady("NATGateway %q has not yet been assigned a gatewayID", natGateway.Name)
	}
	return activeRoute(route), nil
}

func (r *RouteTableReconciler) resolveVpcPeeringRoute(ctx context.Context, rt *juneauloutresmev1alpha1.RouteTable, route juneauloutresmev1alpha1.Route) (*juneauloutresmev1alpha1.ResolvedRoute, error) {
	var peering juneauloutresmev1alpha1.VpcPeering
	if err := r.Get(ctx, client.ObjectKey{Name: route.Via.VpcPeering}, &peering); err != nil {
		if errors.IsNotFound(err) {
			return nil, routeNotReady("VpcPeering %q not found", route.Via.VpcPeering)
		}
		return nil, fmt.Errorf("failed to get VpcPeering %q: %w", route.Via.VpcPeering, err)
	}
	if !meta.IsStatusConditionTrue(peering.Status.Conditions, juneauloutresmev1alpha1.VpcPeeringStatusReady) {
		return nil, routeNotReady("VpcPeering %q is not ready", peering.Name)
	}
	peerVpc, ok := peering.Spec.PeerOf(rt.Spec.Vpc)
	if !ok {
		return nil, routeNotReady("RouteTable belongs to Vpc %q which is not part of VpcPeering %q", rt.Spec.Vpc, peering.Name)
	}
	peerSubnet, err := r.findSubnetByCIDR(ctx, peerVpc, route.Dst)
	if err != nil {
		return nil, fmt.Errorf("failed to list subnets for VPC %q: %w", peerVpc, err)
	}
	if peerSubnet == "" {
		return nil, routeNotReady("no Subnet in Vpc %q has CIDR %q", peerVpc, route.Dst)
	}
	resolved := activeRoute(route)
	resolved.Subnet = peerSubnet
	return resolved, nil
}

func (r *RouteTableReconciler) resolveTransitGatewayRoute(ctx context.Context, rt *juneauloutresmev1alpha1.RouteTable, route juneauloutresmev1alpha1.Route) (*juneauloutresmev1alpha1.ResolvedRoute, error) {
	var transitGateway juneauloutresmev1alpha1.TransitGateway
	if err := r.Get(ctx, client.ObjectKey{Name: route.Via.TransitGateway}, &transitGateway); err != nil {
		if errors.IsNotFound(err) {
			return nil, routeNotReady("TransitGateway %q not found", route.Via.TransitGateway)
		}
		return nil, fmt.Errorf("failed to get TransitGateway %q: %w", route.Via.TransitGateway, err)
	}
	if !meta.IsStatusConditionTrue(transitGateway.Status.Conditions, juneauloutresmev1alpha1.TransitGatewayStatusReady) {
		return nil, routeNotReady("TransitGateway %q is not ready", transitGateway.Name)
	}
	attachment, err := r.findTransitGatewayAttachment(ctx, transitGateway.Name, rt.Spec.Vpc)
	if err != nil {
		return nil, fmt.Errorf("failed to list transit gateway attachments: %w", err)
	}
	if attachment == nil {
		return nil, routeNotReady("Vpc %q has no attachment to TransitGateway %q", rt.Spec.Vpc, transitGateway.Name)
	}
	var association juneauloutresmev1alpha1.TransitGatewayRouteTable
	if err := r.Get(ctx, client.ObjectKey{Name: attachment.Spec.Association}, &association); err != nil {
		if errors.IsNotFound(err) {
			return nil, routeNotReady("TransitGatewayRouteTable %q not found", attachment.Spec.Association)
		}
		return nil, fmt.Errorf("failed to get TransitGatewayRouteTable %q: %w", attachment.Spec.Association, err)
	}
	if association.Status.TableID == 0 {
		return nil, routeNotReady("TransitGatewayRouteTable %q has not yet been assigned a tableID", association.Name)
	}
	resolved := activeRoute(route)
	resolved.TransitGatewayRouteTable = association.Name
	return resolved, nil
}

// findSubnetByCIDR returns the Subnet of vpcName whose CIDR is exactly
// cidr, or "" when no Subnet matches. A peering route resolves to one
// destination Subnet VNI, so a supernet spanning several Subnets has no
// single answer and is reported as unresolved instead.
func (r *RouteTableReconciler) findSubnetByCIDR(ctx context.Context, vpcName, cidr string) (string, error) {
	var subnets juneauloutresmev1alpha1.SubnetList
	if err := r.List(ctx, &subnets, client.MatchingFields{"spec.vpc": vpcName}); err != nil {
		return "", err
	}

	for i := range subnets.Items {
		if subnets.Items[i].Spec.CIDR == cidr {
			return subnets.Items[i].Name, nil
		}
	}

	return "", nil
}

// findTransitGatewayAttachment returns the attachment that connects
// vpcName to transitGateway, or nil when the Vpc is not attached. The
// webhook keeps the pair unique, so the first match is the only match.
func (r *RouteTableReconciler) findTransitGatewayAttachment(ctx context.Context, transitGateway, vpcName string) (*juneauloutresmev1alpha1.TransitGatewayAttachment, error) {
	var attachmentList juneauloutresmev1alpha1.TransitGatewayAttachmentList
	if err := r.List(ctx, &attachmentList); err != nil {
		return nil, err
	}

	for i := range attachmentList.Items {
		attachment := &attachmentList.Items[i]
		if attachment.Spec.TransitGateway == transitGateway && attachment.Spec.Vpc == vpcName {
			return attachment, nil
		}
	}

	return nil, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RouteTableReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()
	if err := indexNetworkInterfaceByAllocationIdentity(ctx, mgr.GetFieldIndexer()); err != nil {
		return err
	}
	if err := indexRouteTableByEndpointNamespace(ctx, mgr.GetFieldIndexer()); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.RouteTable{}).
		Watches(&juneauloutresmev1alpha1.Subnet{}, handler.EnqueueRequestsFromMapFunc(r.mapSubnetToRouteTables)).
		Watches(&juneauloutresmev1alpha1.L2Network{}, handler.EnqueueRequestsFromMapFunc(r.mapL2NetworkToRouteTables)).
		Watches(&juneauloutresmev1alpha1.NetworkEndpoint{}, handler.EnqueueRequestsFromMapFunc(r.mapNetworkEndpointToRouteTables)).
		Watches(&juneauloutresmev1alpha1.NetworkInterface{}, handler.EnqueueRequestsFromMapFunc(r.mapNetworkInterfaceToRouteTables)).
		Watches(&juneauloutresmev1alpha1.Vpc{}, handler.EnqueueRequestsFromMapFunc(r.mapVpcToRouteTables)).
		Watches(&juneauloutresmev1alpha1.AllocationClaim{}, handler.EnqueueRequestsFromMapFunc(r.mapClaimToRouteTables)).
		Watches(&juneauloutresmev1alpha1.AllocationLease{}, handler.EnqueueRequestsFromMapFunc(r.mapLeaseToRouteTables)).
		Watches(&juneauloutresmev1alpha1.NATGateway{}, handler.EnqueueRequestsFromMapFunc(r.mapNATGatewayToRouteTables)).
		Watches(&juneauloutresmev1alpha1.VpcPeering{}, handler.EnqueueRequestsFromMapFunc(r.mapVpcPeeringToRouteTables)).
		Watches(&juneauloutresmev1alpha1.TransitGateway{}, handler.EnqueueRequestsFromMapFunc(r.mapTransitGatewayToRouteTables)).
		Watches(&juneauloutresmev1alpha1.TransitGatewayAttachment{}, handler.EnqueueRequestsFromMapFunc(r.mapTransitGatewayAttachmentToRouteTables)).
		Watches(&juneauloutresmev1alpha1.TransitGatewayRouteTable{}, handler.EnqueueRequestsFromMapFunc(r.mapTransitGatewayRouteTableToRouteTables)).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.mapServiceToRouteTables)).
		Named("routetable").
		Complete(r)
}

// vpcEndpointPoolRoutes returns one route per endpoint pool CIDR of the Vpc.
// The pool covers every VpcEndpoint VIP, so one route per CIDR replaces the
// /32 per endpoint the table used to carry. Unlike the Service CIDR route
// this is not gated on ServiceEnabled(): a VpcEndpoint exists so that a Vpc
// which has not enabled Service routing can still reach one chosen Service.
// The result is sorted by Dst for stable Status.Routes ordering across
// reconciles.
func vpcEndpointPoolRoutes(vpc *juneauloutresmev1alpha1.Vpc) []juneauloutresmev1alpha1.ResolvedRoute {
	cidrs := vpc.Spec.EndpointPool.Cidrs()
	routes := make([]juneauloutresmev1alpha1.ResolvedRoute, 0, len(cidrs))
	for _, cidr := range cidrs {
		routes = append(routes, juneauloutresmev1alpha1.ResolvedRoute{
			State: juneauloutresmev1alpha1.RouteStateActive,
			Dst:   cidr,
			Via: juneauloutresmev1alpha1.RouteVia{
				Type: juneauloutresmev1alpha1.ViaVpcEndpoint,
			},
		})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Dst < routes[j].Dst })
	return routes
}

func (r *RouteTableReconciler) ensureNumberClaim(ctx context.Context, resource *juneauloutresmev1alpha1.RouteTable, poolName string, gvk schema.GroupVersionKind, attribute string) (*juneauloutresmev1alpha1.AllocationClaim, error) {
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

// mapL2NetworkToRouteTables wakes every RouteTable of the Vpc a
// segment belongs to. A connected route for the segment goes into all
// of them, and whether there is one at all follows spec.gateway, which
// the user may add or remove at any time.
func (r *RouteTableReconciler) mapL2NetworkToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	l2, ok := obj.(*juneauloutresmev1alpha1.L2Network)
	if !ok || l2.Spec.Vpc == "" {
		return nil
	}

	var routeTableList juneauloutresmev1alpha1.RouteTableList
	if err := r.List(ctx, &routeTableList); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(routeTableList.Items))
	for i := range routeTableList.Items {
		rt := &routeTableList.Items[i]
		if rt.Spec.Vpc != l2.Spec.Vpc {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: rt.Name}})
	}
	return requests
}

func (r *RouteTableReconciler) mapSubnetToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	subnet, ok := obj.(*juneauloutresmev1alpha1.Subnet)
	if !ok || subnet.Spec.Vpc == "" {
		return nil
	}

	// CONNECTED routes for every Subnet are injected into every
	// RouteTable in the same Vpc. A Subnet event therefore must wake
	// every Vpc-local RouteTable, not just the main one. RouteTables in
	// a peered Vpc also care: their vpcPeering routes resolve against
	// this Subnet's CIDR, so its arrival or removal flips them between
	// Ready and NotReady.
	vpcs := map[string]struct{}{subnet.Spec.Vpc: {}}
	var peeringList juneauloutresmev1alpha1.VpcPeeringList
	if err := r.List(ctx, &peeringList); err != nil {
		return nil
	}
	for i := range peeringList.Items {
		if peer, ok := peeringList.Items[i].Spec.PeerOf(subnet.Spec.Vpc); ok {
			vpcs[peer] = struct{}{}
		}
	}

	var routeTableList juneauloutresmev1alpha1.RouteTableList
	if err := r.List(ctx, &routeTableList); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(routeTableList.Items))
	for i := range routeTableList.Items {
		rt := &routeTableList.Items[i]
		if _, ok := vpcs[rt.Spec.Vpc]; !ok {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: rt.Name}})
	}
	return requests
}

func (r *RouteTableReconciler) mapVpcPeeringToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	peering, ok := obj.(*juneauloutresmev1alpha1.VpcPeering)
	if !ok {
		return nil
	}

	var routeTableList juneauloutresmev1alpha1.RouteTableList
	if err := r.List(ctx, &routeTableList); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0)
	for i := range routeTableList.Items {
		rt := &routeTableList.Items[i]
		for _, route := range rt.Spec.Routes {
			if route.Via.Type == juneauloutresmev1alpha1.ViaVpcPeering && route.Via.VpcPeering == peering.Name {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: rt.Name}})
				break
			}
		}
	}
	return requests
}

func (r *RouteTableReconciler) mapTransitGatewayToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	transitGateway, ok := obj.(*juneauloutresmev1alpha1.TransitGateway)
	if !ok {
		return nil
	}
	return r.routeTablesUsingTransitGateway(ctx, transitGateway.Name)
}

func (r *RouteTableReconciler) mapTransitGatewayAttachmentToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	attachment, ok := obj.(*juneauloutresmev1alpha1.TransitGatewayAttachment)
	if !ok || attachment.Spec.TransitGateway == "" {
		return nil
	}
	return r.routeTablesUsingTransitGateway(ctx, attachment.Spec.TransitGateway)
}

func (r *RouteTableReconciler) mapTransitGatewayRouteTableToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	routeTable, ok := obj.(*juneauloutresmev1alpha1.TransitGatewayRouteTable)
	if !ok || routeTable.Spec.TransitGateway == "" {
		return nil
	}
	return r.routeTablesUsingTransitGateway(ctx, routeTable.Spec.TransitGateway)
}

func (r *RouteTableReconciler) routeTablesUsingTransitGateway(ctx context.Context, transitGateway string) []reconcile.Request {
	var routeTableList juneauloutresmev1alpha1.RouteTableList
	if err := r.List(ctx, &routeTableList); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0)
	for i := range routeTableList.Items {
		rt := &routeTableList.Items[i]
		for _, route := range rt.Spec.Routes {
			if route.Via.Type == juneauloutresmev1alpha1.ViaTransitGateway && route.Via.TransitGateway == transitGateway {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: rt.Name}})
				break
			}
		}
	}
	return requests
}

func (r *RouteTableReconciler) mapVpcToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	vpc, ok := obj.(*juneauloutresmev1alpha1.Vpc)
	if !ok {
		return nil
	}

	var routeTableList juneauloutresmev1alpha1.RouteTableList
	if err := r.List(ctx, &routeTableList); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(routeTableList.Items))
	for _, rt := range routeTableList.Items {
		if rt.Spec.Vpc != vpc.Name {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: rt.Name}})
	}
	return requests
}

func (r *RouteTableReconciler) mapNATGatewayToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	natGateway, ok := obj.(*juneauloutresmev1alpha1.NATGateway)
	if !ok {
		return nil
	}

	var routeTableList juneauloutresmev1alpha1.RouteTableList
	if err := r.List(ctx, &routeTableList); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0)
	enqueued := map[string]bool{}
	for _, rt := range routeTableList.Items {
		for _, route := range rt.Spec.Routes {
			if route.Via.Type == juneauloutresmev1alpha1.ViaNATGateway && route.Via.NATGateway == natGateway.Name {
				if !enqueued[rt.Name] {
					requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: rt.Name}})
					enqueued[rt.Name] = true
				}
				break
			}
		}
	}
	// The default-VPC main RouteTable receives a 0/0 auto-injection
	// when a NATGateway named "default" exists. That dependency lives
	// only in status.routes (not spec), so the loop above never picks
	// it up; enqueue it explicitly here.
	if natGateway.Name == defaultVpcName {
		for _, rt := range routeTableList.Items {
			if rt.Name == defaultVpcName && rt.Spec.Vpc == defaultVpcName && !enqueued[rt.Name] {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: rt.Name}})
				enqueued[rt.Name] = true
				break
			}
		}
	}
	return requests
}

// owningVpcOfService returns the Vpc that the Service is anchored to.
// Mirrors svcpolicy.OwningVpc / webhook.serviceVpc; duplicated here so
// the controller package does not pull either side into its imports.
func owningVpcOfService(svc *corev1.Service) string {
	if v := svc.Annotations[serviceVpcAnnotation]; v != "" {
		return v
	}
	return defaultVpcName
}

// collectExternalIPRoutes returns one /32 via.type=service route per
// IPv4 entry in spec.externalIPs across every Service owned by vpc.
// ExternalName Services have no backends and are skipped. Non-IPv4
// entries are dropped silently here; the daemon-side reconciler emits
// a per-Service warning for those, so a duplicate log here would just
// be noise. The result is sorted by Dst for stable Status.Routes
// ordering across reconciles.
func (r *RouteTableReconciler) collectExternalIPRoutes(ctx context.Context, vpc *juneauloutresmev1alpha1.Vpc) ([]juneauloutresmev1alpha1.ResolvedRoute, error) {
	var svcs corev1.ServiceList
	if err := r.List(ctx, &svcs); err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}

	seen := make(map[string]struct{})
	var routes []juneauloutresmev1alpha1.ResolvedRoute
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		if owningVpcOfService(svc) != vpc.Name {
			continue
		}
		if svc.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		for _, raw := range svc.Spec.ExternalIPs {
			ip := net.ParseIP(raw)
			if ip == nil || ip.To4() == nil {
				continue
			}
			cidr := ip.To4().String() + "/32"
			if _, dup := seen[cidr]; dup {
				continue
			}
			seen[cidr] = struct{}{}
			routes = append(routes, juneauloutresmev1alpha1.ResolvedRoute{
				State: juneauloutresmev1alpha1.RouteStateActive,
				Dst:   cidr,
				Via: juneauloutresmev1alpha1.RouteVia{
					Type: juneauloutresmev1alpha1.ViaService,
				},
			})
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Dst < routes[j].Dst })
	return routes, nil
}

// mapServiceToRouteTables re-enqueues every RouteTable in the cluster
// when a Service changes. A finer-grained mapping (only the owner
// Vpc's RouteTables) would mishandle ownership transitions: when a
// Service's juneau.loutres.me/vpc annotation changes we need to
// refresh both the old and the new owner's RouteTables. Service
// events are infrequent compared to Subnet/Pod churn, so the broader
// fan-out is acceptable.
func (r *RouteTableReconciler) mapServiceToRouteTables(ctx context.Context, _ client.Object) []reconcile.Request {
	var routeTableList juneauloutresmev1alpha1.RouteTableList
	if err := r.List(ctx, &routeTableList); err != nil {
		log.FromContext(ctx).Error(err, "list RouteTables for Service fan-out")
		return nil
	}
	requests := make([]reconcile.Request, 0, len(routeTableList.Items))
	for i := range routeTableList.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{Name: routeTableList.Items[i].Name},
		})
	}
	return requests
}
