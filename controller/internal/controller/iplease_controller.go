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
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	ipLeaseReasonBound      = "Bound"
	ipLeaseReasonActive     = "IPLeaseActive"
	ipLeaseReasonReleased   = "Released"
	ipLeaseReasonExpired    = "Expired"
	ipLeaseReasonNotExpired = "NotExpired"
	ipLeaseAllocationFailed = "AllocationFailed"
	ipLeaseConditionBound   = juneauv1alpha1.IPLeaseStatusBound
	ipLeaseConditionExpired = juneauv1alpha1.IPLeaseStatusExpired
	defaultLeaseTTL         = time.Hour
	requeueCheckWindow      = time.Hour
	requeueSafetyBuffer     = time.Second
)

// IPLeaseReconciler reconciles a IPLease object
type IPLeaseReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=ipleases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=ipleases/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=ipleases/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *IPLeaseReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	now := time.Now()

	var resource juneauv1alpha1.IPLease
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get IPLease", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.ObjectMeta.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if !resource.Status.ExpiresAt.IsZero() && now.After(resource.Status.ExpiresAt.Time) {
		if err := r.Delete(ctx, &resource); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("deleted expired IPLease", "name", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	resource.Status.PodDisplayName = resource.Spec.PodRef.Interface + "." + resource.Spec.PodRef.Name + "." + resource.Spec.PodRef.Namespace

	if resource.Spec.OwnerDeletionTimeStamp.IsZero() {
		if err := r.updateStatus(ctx, &resource, juneauv1alpha1.IPLeasePhaseActive, nil,
			metav1.Condition{
				Type:   ipLeaseConditionBound,
				Status: metav1.ConditionTrue,
				Reason: ipLeaseReasonBound,
			},
			metav1.Condition{
				Type:    ipLeaseConditionExpired,
				Status:  metav1.ConditionFalse,
				Reason:  ipLeaseReasonActive,
				Message: "",
			},
		); err != nil {
			logger.Error(err, "unable to update IPLease status", "name", req.NamespacedName)
			return ctrl.Result{}, err
		}
	} else {
		ttl := defaultLeaseTTL
		if resource.Spec.TTLSeconds != nil {
			ttl = time.Duration(*resource.Spec.TTLSeconds) * time.Second
		}

		expirationTime := resource.Spec.OwnerDeletionTimeStamp.Add(ttl)
		expiresAt := metav1.NewTime(expirationTime)

		if now.After(expirationTime) {
			if err := r.updateStatus(ctx, &resource, juneauv1alpha1.IPLeasePhaseExpired, &expiresAt,
				metav1.Condition{
					Type:   ipLeaseConditionBound,
					Status: metav1.ConditionFalse,
					Reason: ipLeaseReasonReleased,
				},
				metav1.Condition{
					Type:   ipLeaseConditionExpired,
					Status: metav1.ConditionTrue,
					Reason: ipLeaseReasonExpired,
				},
			); err != nil {
				logger.Error(err, "unable to update IPLease status", "name", req.NamespacedName)
				return ctrl.Result{}, err
			}

			return ctrl.Result{Requeue: true}, nil
		}

		if err := r.updateStatus(ctx, &resource, juneauv1alpha1.IPLeasePhaseReleased, &expiresAt,
			metav1.Condition{
				Type:   ipLeaseConditionBound,
				Status: metav1.ConditionFalse,
				Reason: ipLeaseReasonReleased,
			},
			metav1.Condition{
				Type:    ipLeaseConditionExpired,
				Status:  metav1.ConditionFalse,
				Reason:  ipLeaseReasonNotExpired,
				Message: "Will be expired at " + expiresAt.String(),
			},
		); err != nil {
			logger.Error(err, "unable to update IPLease status", "name", req.NamespacedName)
			return ctrl.Result{}, err
		}

		if now.Add(requeueCheckWindow).After(expirationTime) {
			remaining := expirationTime.Sub(now)
			return ctrl.Result{RequeueAfter: remaining + requeueSafetyBuffer}, nil
		}
		return ctrl.Result{RequeueAfter: requeueCheckWindow}, nil
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IPLeaseReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.IPLease{},
		"spec.subnet",
		func(obj client.Object) []string {
			lease := obj.(*juneauv1alpha1.IPLease)
			if lease.Spec.Subnet == "" {
				return nil
			}
			return []string{lease.Spec.Subnet}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for IPLease.spec.subnet: %w", err)
	}

	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.IPLease{},
		"spec.podRef.namespace",
		func(obj client.Object) []string {
			lease := obj.(*juneauv1alpha1.IPLease)
			if lease.Spec.PodRef.Namespace == "" {
				return nil
			}
			return []string{lease.Spec.PodRef.Namespace}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for IPLease.spec.podRef.namespace: %w", err)
	}

	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.IPLease{},
		"spec.podRef.name",
		func(obj client.Object) []string {
			lease := obj.(*juneauv1alpha1.IPLease)
			if lease.Spec.PodRef.Name == "" {
				return nil
			}
			return []string{lease.Spec.PodRef.Name}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for IPLease.spec.podRef.name: %w", err)
	}

	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.IPLease{},
		"spec.podRef.interface",
		func(obj client.Object) []string {
			lease := obj.(*juneauv1alpha1.IPLease)
			if lease.Spec.PodRef.Interface == "" {
				return nil
			}
			return []string{lease.Spec.PodRef.Interface}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for IPLease.spec.podRef.interface: %w", err)
	}

	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.IPLease{},
		"spec.address",
		func(obj client.Object) []string {
			lease := obj.(*juneauv1alpha1.IPLease)
			if lease.Spec.Address == "" {
				return nil
			}
			return []string{lease.Spec.Address}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for IPLease.spec.address: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.IPLease{}).
		Named("iplease").
		Complete(r)
}

func (r *IPLeaseReconciler) updateStatus(
	ctx context.Context,
	resource *juneauv1alpha1.IPLease,
	phase juneauv1alpha1.IPLeasePhase,
	expiresAt *metav1.Time,
	boundCondition metav1.Condition,
	expiredCondition metav1.Condition,
) error {
	resource.Status.ObservedGeneration = resource.Generation
	resource.Status.ExpiresAt = expiresAt
	resource.Status.Phase = phase
	meta.SetStatusCondition(&resource.Status.Conditions, boundCondition)
	meta.SetStatusCondition(&resource.Status.Conditions, expiredCondition)
	return r.Status().Update(ctx, resource)
}
