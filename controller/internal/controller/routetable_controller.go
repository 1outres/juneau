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
	"net"
	"reflect"
	"slices"
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
	// When the owning VPC has spec.enableService=true, the reconciler
	// injects a route for this CIDR with via.type=service into the
	// RouteTable's status.routes.
	ServiceCIDR *net.IPNet
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=routetables,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=routetables/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=routetables/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims/status,verbs=get;update;patch

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

	if !resource.ObjectMeta.DeletionTimestamp.IsZero() {
		if err := r.updateStatus(ctx, &resource, resource.Status.Routes, resource.Status.TableID, metav1.ConditionFalse, routeTableReasonDeleting, "route table is being deleted"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	var statusRoutes []juneauloutresmev1alpha1.Route
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
		statusRoutes = append(statusRoutes, juneauloutresmev1alpha1.Route{
			Dst:    subnet.Spec.CIDR,
			Subnet: subnet.Name,
			Via: juneauloutresmev1alpha1.RouteVia{
				Type: juneauloutresmev1alpha1.ViaConnected,
			},
		})
		subnetNames = append(subnetNames, subnet.Name)
	}

	if vpc.Spec.EnableService && r.ServiceCIDR != nil {
		statusRoutes = append(statusRoutes, juneauloutresmev1alpha1.Route{
			Dst: r.ServiceCIDR.String(),
			Via: juneauloutresmev1alpha1.RouteVia{
				Type: juneauloutresmev1alpha1.ViaService,
			},
		})
	}

	// The default VPC's main RouteTable carries an additional default
	// route that delegates internet egress to the host network stack
	// via cni_host (and the host's iptables MASQUERADE). This is a
	// transitional path until proper in-eBPF NAPT is implemented; only
	// the "default" VPC's main RouteTable receives it.
	if resource.Name == defaultVpcName && resource.Spec.Vpc == defaultVpcName {
		statusRoutes = append(statusRoutes, juneauloutresmev1alpha1.Route{
			Dst: "0.0.0.0/0",
			Via: juneauloutresmev1alpha1.RouteVia{
				Type: juneauloutresmev1alpha1.ViaHostGateway,
			},
		})
	}

	for _, route := range resource.Spec.Routes {
		if rt := getRoute(statusRoutes, route.Dst); rt == nil {
			var subnet string
			if route.Via.Type == juneauloutresmev1alpha1.ViaConnected ||
				route.Via.Type == juneauloutresmev1alpha1.ViaService ||
				route.Via.Type == juneauloutresmev1alpha1.ViaHostGateway {
				continue
			} else if route.Via.Type == juneauloutresmev1alpha1.ViaEndpoint {
				nwep, err := r.getNetworkEndpoint(ctx, route.Via.Endpoint)
				if err != nil {
					if errors.IsNotFound(err) {
						if err := r.updateStatus(ctx, &resource, statusRoutes, resource.Status.TableID, metav1.ConditionFalse, routeTableReasonNotReady, fmt.Sprintf("network endpoint %q not found", route.Via.Endpoint)); err != nil {
							return ctrl.Result{}, err
						}
						return ctrl.Result{}, nil
					}
					if updateErr := r.updateStatus(ctx, &resource, statusRoutes, resource.Status.TableID, metav1.ConditionFalse, routeTableReasonReconcileFailed, fmt.Sprintf("failed to get network endpoint %q", route.Via.Endpoint)); updateErr != nil {
						return ctrl.Result{}, updateErr
					}
					return ctrl.Result{}, err
				}
				if !slices.Contains(subnetNames, nwep.Spec.Subnet) {
					if err := r.updateStatus(ctx, &resource, statusRoutes, resource.Status.TableID, metav1.ConditionFalse, routeTableReasonNotReady, fmt.Sprintf("network endpoint %q is in subnet %q outside VPC %q", route.Via.Endpoint, nwep.Spec.Subnet, resource.Spec.Vpc)); err != nil {
						return ctrl.Result{}, err
					}
					return ctrl.Result{}, nil
				}
				subnet = nwep.Spec.Subnet
			}
			route.Subnet = subnet
			statusRoutes = append(statusRoutes, route)
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

func (r *RouteTableReconciler) updateStatus(ctx context.Context, resource *juneauloutresmev1alpha1.RouteTable, routes []juneauloutresmev1alpha1.Route, tableID uint32, ready metav1.ConditionStatus, reason, message string) error {
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

func getRoute(routes []juneauloutresmev1alpha1.Route, dst string) *juneauloutresmev1alpha1.Route {
	for i := range routes {
		if routes[i].Dst == dst {
			return &routes[i]
		}
	}
	return nil
}

func (r *RouteTableReconciler) getNetworkEndpoint(ctx context.Context, name string) (*juneauloutresmev1alpha1.NetworkEndpoint, error) {
	var networkEndpointList juneauloutresmev1alpha1.NetworkEndpointList
	if err := r.List(ctx, &networkEndpointList); err != nil {
		return nil, err
	}

	var match *juneauloutresmev1alpha1.NetworkEndpoint
	for i := range networkEndpointList.Items {
		if networkEndpointList.Items[i].Name != name {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("multiple network endpoints named %q found", name)
		}
		match = &networkEndpointList.Items[i]
	}

	if match == nil {
		return nil, errors.NewNotFound(schema.GroupResource{Group: juneauloutresmev1alpha1.GroupVersion.Group, Resource: "networkendpoints"}, name)
	}

	return match, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RouteTableReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.RouteTable{}).
		Watches(&juneauloutresmev1alpha1.Subnet{}, handler.EnqueueRequestsFromMapFunc(r.mapSubnetToRouteTables)).
		Watches(&juneauloutresmev1alpha1.NetworkEndpoint{}, handler.EnqueueRequestsFromMapFunc(r.mapNetworkEndpointToRouteTables)).
		Watches(&juneauloutresmev1alpha1.Vpc{}, handler.EnqueueRequestsFromMapFunc(r.mapVpcToRouteTables)).
		Watches(&juneauloutresmev1alpha1.AllocationClaim{}, handler.EnqueueRequestsFromMapFunc(r.mapClaimToRouteTables)).
		Named("routetable").
		Complete(r)
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

func (r *RouteTableReconciler) mapSubnetToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	subnet, ok := obj.(*juneauloutresmev1alpha1.Subnet)
	if !ok || subnet.Spec.Vpc == "" {
		return nil
	}

	// CONNECTED routes for every Subnet are injected into every
	// RouteTable in the same Vpc. A Subnet event therefore must wake
	// every Vpc-local RouteTable, not just the main one.
	var routeTableList juneauloutresmev1alpha1.RouteTableList
	if err := r.List(ctx, &routeTableList); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(routeTableList.Items))
	for i := range routeTableList.Items {
		rt := &routeTableList.Items[i]
		if rt.Spec.Vpc != subnet.Spec.Vpc {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: rt.Name}})
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

func (r *RouteTableReconciler) mapClaimToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	_ = ctx
	claim, ok := obj.(*juneauloutresmev1alpha1.AllocationClaim)
	if !ok || claim.Spec.ResourceRef.Kind != "RouteTable" || claim.Spec.ResourceRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.ResourceRef.Name}}}
}

func (r *RouteTableReconciler) mapNetworkEndpointToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	nwep, ok := obj.(*juneauloutresmev1alpha1.NetworkEndpoint)
	if !ok || nwep.Spec.Subnet == "" {
		return nil
	}

	var subnet juneauloutresmev1alpha1.Subnet
	if err := r.Get(ctx, client.ObjectKey{Name: nwep.Spec.Subnet}, &subnet); err != nil {
		return nil
	}

	if subnet.Spec.Vpc == "" {
		return nil
	}

	var vpc juneauloutresmev1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: subnet.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: subnet.Spec.Vpc}}}
		}
		return nil
	}

	routeTableName := vpc.Status.MainRouteTable
	if routeTableName == "" {
		routeTableName = vpc.Name
	}

	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: routeTableName}}}
}
