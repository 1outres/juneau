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
	"math"
	"reflect"
	"slices"
	"strconv"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=routetables,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=routetables/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=routetables/finalizers,verbs=update

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

	for _, route := range resource.Spec.Routes {
		if rt := getRoute(statusRoutes, route.Dst); rt == nil {
			var subnet string
			if route.Via.Type == juneauloutresmev1alpha1.ViaConnected {
				continue
			} else if route.Via.Type == juneauloutresmev1alpha1.ViaEndpoint {
				var nwep juneauloutresmev1alpha1.NetworkEndpoint
				if err := r.Get(ctx, client.ObjectKey{Name: route.Via.Endpoint}, &nwep); err != nil {
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
		var id uint32 = 1
		for {
			if id == math.MaxUint32 {
				if err := r.updateStatus(ctx, &resource, statusRoutes, tableID, metav1.ConditionFalse, routeTableReasonReconcileFailed, "route table ID limit reached"); err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, nil
			}
			id++

			var tableList juneauloutresmev1alpha1.RouteTableList
			if err := r.List(ctx, &tableList, client.MatchingFields{"status.tableID": strconv.FormatUint(uint64(id), 10)}); err != nil {
				if updateErr := r.updateStatus(ctx, &resource, statusRoutes, tableID, metav1.ConditionFalse, routeTableReasonReconcileFailed, "failed to list existing route tables"); updateErr != nil {
					return ctrl.Result{}, updateErr
				}
				return ctrl.Result{}, err
			}

			if len(tableList.Items) == 0 {
				break
			}
		}

		tableID = id
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
		Type:    juneauloutresmev1alpha1.RouteTableStatusReady,
		Status:  ready,
		Reason:  reason,
		Message: message,
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
	for _, route := range routes {
		if route.Dst == dst {
			return &route
		}
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RouteTableReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauloutresmev1alpha1.RouteTable{},
		"status.tableID",
		func(obj client.Object) []string {
			table := obj.(*juneauloutresmev1alpha1.RouteTable)
			if table.Status.TableID == 0 {
				return nil
			}
			return []string{strconv.FormatUint(uint64(table.Status.TableID), 10)}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for RouteTable.status.tableID: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.RouteTable{}).
		Watches(&juneauloutresmev1alpha1.Subnet{}, handler.EnqueueRequestsFromMapFunc(r.mapSubnetToRouteTables)).
		Watches(&juneauloutresmev1alpha1.NetworkEndpoint{}, handler.EnqueueRequestsFromMapFunc(r.mapNetworkEndpointToRouteTables)).
		Named("routetable").
		Complete(r)
}

func (r *RouteTableReconciler) mapSubnetToRouteTables(ctx context.Context, obj client.Object) []reconcile.Request {
	subnet, ok := obj.(*juneauloutresmev1alpha1.Subnet)
	if !ok || subnet.Spec.Vpc == "" {
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
