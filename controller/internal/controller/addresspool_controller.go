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
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// AddressPoolReconciler reconciles AddressPool resources.
//
// AddressPool is the user-facing CRD that declares an advertise mode (BGP /
// ARP) and a set of CIDRs. Behind the scenes the reconciler maintains a
// 1:1 AllocationPool (`addr-<name>`) so that ElasticIP, NATGateway and
// future consumers can allocate addresses through the shared
// AllocationClaim framework. The advertise mode itself is consumed by
// other components (BGP speaker, future ARP responder); this reconciler
// only mirrors the CIDR list into the allocation framework.
type AddressPoolReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

const (
	// addressPoolAllocationPoolPrefix prefixes the auto-generated
	// AllocationPool name. Distinct from subnet-derived AllocationPool
	// names ("subnet-ip-…") so the two namespaces never collide.
	addressPoolAllocationPoolPrefix = "addr-"
)

// AddressPoolAllocationPoolName returns the AllocationPool name that backs
// the given AddressPool. Exported for use by ElasticIP and other consumers
// that need to reference the underlying allocation pool.
func AddressPoolAllocationPoolName(addressPoolName string) string {
	return addressPoolAllocationPoolPrefix + addressPoolName
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresspools,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresspools/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresspools/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationpools,verbs=get;list;watch;create;update;patch;delete

// Reconcile keeps the AllocationPool that backs an AddressPool in sync
// with the user-declared CIDR list.
func (r *AddressPoolReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var addressPool juneauv1alpha1.AddressPool
	if err := r.Get(ctx, req.NamespacedName, &addressPool); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// AddressPool deletion is handled by the AllocationPool's OwnerRef GC,
	// so no finalizer is required here.
	if !addressPool.ObjectMeta.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if err := r.ensureAllocationPool(ctx, &addressPool); err != nil {
		logger.Error(err, "unable to ensure backing AllocationPool", "addressPool", req.Name)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *AddressPoolReconciler) ensureAllocationPool(ctx context.Context, addressPool *juneauv1alpha1.AddressPool) error {
	name := AddressPoolAllocationPoolName(addressPool.Name)

	desiredSpec := juneauv1alpha1.AllocationPoolSpec{
		Type:     juneauv1alpha1.AllocationTypeIP,
		Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
		IP: &juneauv1alpha1.AllocationPoolIPSpec{
			CIDRs: append([]string(nil), addressPool.Spec.Addresses...),
		},
	}

	var existing juneauv1alpha1.AllocationPool
	err := r.Get(ctx, client.ObjectKey{Name: name}, &existing)
	switch {
	case apierrors.IsNotFound(err):
		pool := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       desiredSpec,
		}
		if err := controllerutil.SetControllerReference(addressPool, pool, r.Scheme); err != nil {
			return fmt.Errorf("set owner reference: %w", err)
		}
		if err := r.Create(ctx, pool); err != nil {
			if apierrors.IsAlreadyExists(err) {
				// Lost a race with another reconcile pass; re-run.
				return nil
			}
			return fmt.Errorf("create AllocationPool: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("get AllocationPool: %w", err)
	}

	// Update path: confirm the OwnerRef and CIDR set are aligned with the
	// current AddressPool state.
	updated := existing.DeepCopy()
	if err := controllerutil.SetControllerReference(addressPool, updated, r.Scheme); err != nil {
		return fmt.Errorf("set owner reference: %w", err)
	}
	updated.Spec = desiredSpec

	if reflect.DeepEqual(existing.Spec, updated.Spec) &&
		reflect.DeepEqual(existing.OwnerReferences, updated.OwnerReferences) {
		return nil
	}
	return r.Update(ctx, updated)
}

// SetupWithManager sets up the controller with the Manager.
func (r *AddressPoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.AddressPool{}).
		Owns(&juneauv1alpha1.AllocationPool{}).
		Named("addresspool").
		Complete(r)
}
