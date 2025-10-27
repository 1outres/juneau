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

	juneauv1alpha1 "github.com/1outres/juneau/api/v1alpha1"
)

// AddressReconciler reconciles a Address object
type AddressReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresses/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *AddressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var address juneauv1alpha1.Address
	if err := r.Get(ctx, req.NamespacedName, &address); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get Address", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !address.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if address.Spec.Address != "" {

	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AddressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.Address{},
		"spec.subnet",
		func(obj client.Object) []string {
			address := obj.(*juneauv1alpha1.Address)
			if address.Spec.Subnet == "" {
				return nil
			}
			return []string{address.Spec.Subnet}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for Address.spec.subnet: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.Address{}).
		Named("address").
		Complete(r)
}
