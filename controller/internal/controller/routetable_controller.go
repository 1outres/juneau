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
	"slices"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
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
		return ctrl.Result{}, nil
	}

	var statusRoutes []juneauloutresmev1alpha1.Route
	var subnetNames []string

	var subnets juneauloutresmev1alpha1.SubnetList
	if err := r.List(ctx, &subnets, client.MatchingFields{"spec.vpc": resource.Spec.Vpc}); err != nil {
		return ctrl.Result{}, err
	}
	for _, subnet := range subnets.Items {
		statusRoutes = append(statusRoutes, juneauloutresmev1alpha1.Route{
			Dst:    subnet.Spec.CIDR,
			Subnet: subnet.Name,
			Via: juneauloutresmev1alpha1.RouteVia{
				Type: juneauloutresmev1alpha1.ViaConnnected,
			},
		})
		subnetNames = append(subnetNames, subnet.Name)
	}

	for _, route := range resource.Spec.Routes {
		if rt := getRoute(statusRoutes, route.Dst); rt == nil {
			var subnet string
			if route.Via.Type == juneauloutresmev1alpha1.ViaConnnected {
				continue
			} else if route.Via.Type == juneauloutresmev1alpha1.ViaEndpoint {
				var nwep juneauloutresmev1alpha1.NetworkEndpoint
				if err := r.Get(ctx, client.ObjectKey{Name: route.Via.Endpoint}, &nwep); err != nil {
					if errors.IsNotFound(err) {
						// TODO: set condition
						continue
					}
					return ctrl.Result{}, err
				}
				if !slices.Contains(subnetNames, nwep.Spec.Subnet) {
					// TODO: set condition
					continue
				}
				subnet = nwep.Spec.Subnet
			}
			route.Subnet = subnet
			statusRoutes = append(statusRoutes, route)
		}
	}

	resource.Status.Routes = statusRoutes
	if err := r.Status().Update(ctx, &resource); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
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
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.RouteTable{}).
		Named("routetable").
		Complete(r)
}
