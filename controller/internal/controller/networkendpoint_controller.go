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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// NetworkEndpointReconciler reconciles a NetworkEndpoint object
type NetworkEndpointReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkendpoints,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkendpoints/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkendpoints/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NetworkEndpointReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauv1alpha1.NetworkEndpoint
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get NetworkEndpoint", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.ObjectMeta.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	var node corev1.Node
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.NodeName}, &node); err != nil {
		return ctrl.Result{}, err
	}

	var address string
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			address = addr.Address
		}
	}

	if resource.Status.NodeIP == address {
		return ctrl.Result{}, nil
	}

	resource.Status.NodeIP = address

	if err := r.Status().Update(ctx, &resource); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkEndpointReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.NetworkEndpoint{},
		"spec.podRef.name",
		func(obj client.Object) []string {
			nwep := obj.(*juneauv1alpha1.NetworkEndpoint)
			if nwep.Spec.PodRef.Name == "" {
				return nil
			}
			return []string{nwep.Spec.PodRef.Name}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for NetworkEndpoint.spec.podRef.name: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.NetworkEndpoint{},
		"spec.podRef.interface",
		func(obj client.Object) []string {
			nwep := obj.(*juneauv1alpha1.NetworkEndpoint)
			if nwep.Spec.PodRef.Interface == "" {
				return nil
			}
			return []string{nwep.Spec.PodRef.Interface}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for NetworkEndpoint.spec.podRef.interface: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.NetworkEndpoint{},
		"spec.podRef.uid",
		func(obj client.Object) []string {
			nwep := obj.(*juneauv1alpha1.NetworkEndpoint)
			if nwep.Spec.PodRef.UID == "" {
				return nil
			}
			return []string{nwep.Spec.PodRef.UID}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for NetworkEndpoint.spec.podRef.uid: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.NetworkEndpoint{}).
		Named("networkendpoint").
		Complete(r)
}
