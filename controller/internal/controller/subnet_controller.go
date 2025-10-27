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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/internal/pkg/netutil"
)

// SubnetReconciler reconciles a Subnet object
type SubnetReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Subnet object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile
func (r *SubnetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var subnet juneauv1alpha1.Subnet
	if err := r.Get(ctx, req.NamespacedName, &subnet); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get Subnet", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !subnet.ObjectMeta.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	capacity, err := netutil.V4CapacityHosts(subnet.Spec.CIDR)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to calculate capacity for subnet %s: %w", subnet.Name, err)
	}

	gateway, err := netutil.NthIPv4InSubnet(subnet.Spec.CIDR, 1)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to calculate gateway for subnet %s: %w", subnet.Name, err)
	}

	defaultNextCursor, err := netutil.NthIPv4InSubnet(subnet.Spec.CIDR, 5)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to calculate default next cursor for subnet %s: %w", subnet.Name, err)
	}

	var subnetLeases juneauv1alpha1.SubnetLeaseList
	if err := r.List(ctx, &subnetLeases, client.MatchingFields{"spec.subnet": subnet.Name}); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list subnetleases for subnet %s: %w", subnet.Name, err)
	}

	subnet.Status.Gateway = gateway.String()
	subnet.Status.Capacity = capacity
	subnet.Status.Used = uint64(len(subnetLeases.Items))

	if subnet.Status.NextCursor == "" {
		subnet.Status.NextCursor = defaultNextCursor.String()
	}

	if err := r.Status().Update(ctx, &subnet); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update status for subnet %s: %w", subnet.Name, err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SubnetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.Subnet{},
		"spec.vpc",
		func(obj client.Object) []string {
			subnet := obj.(*juneauv1alpha1.Subnet)
			if subnet.Spec.Vpc == "" {
				return nil
			}
			return []string{subnet.Spec.Vpc}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for Subnet.spec.vpc: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.Subnet{}).
		Named("subnet").
		Watches(
			&juneauv1alpha1.SubnetLease{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
				lease := object.(*juneauv1alpha1.SubnetLease)
				return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: lease.Spec.Subnet}}}
			}),
		).
		Complete(r)
}
