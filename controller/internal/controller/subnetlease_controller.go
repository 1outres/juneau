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
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// SubnetLeaseReconciler reconciles a SubnetLease object
type SubnetLeaseReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnetleases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnetleases/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnetleases/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *SubnetLeaseReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var subnetLease juneauv1alpha1.SubnetLease
	if err := r.Get(ctx, req.NamespacedName, &subnetLease); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get SubnetLease", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !subnetLease.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	var address juneauv1alpha1.Address
	err := r.Get(ctx, client.ObjectKey{Namespace: subnetLease.Spec.Owner.Namespace, Name: subnetLease.Spec.Owner.Name}, &address)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(err, "unable to get Address for SubnetLease", "subnetLease", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if errors.IsNotFound(err) || string(address.UID) != subnetLease.Spec.Owner.UID {
		logger.Info("Deleting stale SubnetLease as its owner Address does not exist", "subnetLease", req.NamespacedName)
		if err := r.Delete(ctx, &subnetLease); err != nil {
			logger.Error(err, "unable to delete stale SubnetLease", "subnetLease", req.NamespacedName)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SubnetLeaseReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.SubnetLease{},
		"spec.subnet",
		func(obj client.Object) []string {
			subnetlease := obj.(*juneauv1alpha1.SubnetLease)
			if subnetlease.Spec.Subnet == "" {
				return nil
			}
			return []string{subnetlease.Spec.Subnet}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for SubnetLease.spec.subnet: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.SubnetLease{}).
		Named("subnetlease").
		Complete(r)
}
