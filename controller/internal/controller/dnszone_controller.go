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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	dnsZoneVpcIndex = "spec.vpc"

	dnsZoneReasonReady       = "Ready"
	dnsZoneReasonVpcNotFound = "VpcNotFound"
	dnsZoneReasonDuplicate   = "DuplicateZone"
)

// DNSZoneReconciler projects DNSZone readiness.
type DNSZoneReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=dnszones,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=dnszones/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcs,verbs=get;list;watch

// Reconcile projects the current Vpc and uniqueness state into DNSZone status.
func (r *DNSZoneReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var zone juneauv1alpha1.DNSZone
	if err := r.Get(ctx, req.NamespacedName, &zone); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !zone.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	condition, err := r.desiredCondition(ctx, &zone)
	if err != nil {
		log.FromContext(ctx).Error(err, "unable to determine DNSZone readiness", "name", zone.Name)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.updateStatus(ctx, &zone, condition)
}

func (r *DNSZoneReconciler) desiredCondition(ctx context.Context, zone *juneauv1alpha1.DNSZone) (metav1.Condition, error) {
	var zones juneauv1alpha1.DNSZoneList
	if err := r.List(ctx, &zones, client.MatchingFields{dnsZoneVpcIndex: zone.Spec.Vpc}); err != nil {
		return metav1.Condition{}, fmt.Errorf("list DNSZones in Vpc %q: %w", zone.Spec.Vpc, err)
	}
	for i := range zones.Items {
		other := &zones.Items[i]
		if other.Name != zone.Name && other.Spec.Domain == zone.Spec.Domain {
			return dnsZoneCondition(metav1.ConditionFalse, dnsZoneReasonDuplicate,
				fmt.Sprintf("DNSZone %q also defines domain %q in Vpc %q", other.Name, zone.Spec.Domain, zone.Spec.Vpc)), nil
		}
	}

	var vpc juneauv1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: zone.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			return dnsZoneCondition(metav1.ConditionFalse, dnsZoneReasonVpcNotFound,
				fmt.Sprintf("Vpc %q does not exist", zone.Spec.Vpc)), nil
		}
		return metav1.Condition{}, fmt.Errorf("get Vpc %q: %w", zone.Spec.Vpc, err)
	}
	return dnsZoneCondition(metav1.ConditionTrue, dnsZoneReasonReady,
		fmt.Sprintf("domain %q is ready in Vpc %q", zone.Spec.Domain, zone.Spec.Vpc)), nil
}

func dnsZoneCondition(status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{Type: juneauv1alpha1.DNSZoneConditionReady, Status: status, Reason: reason, Message: message}
}

func (r *DNSZoneReconciler) updateStatus(ctx context.Context, zone *juneauv1alpha1.DNSZone, desired metav1.Condition) error {
	updated := zone.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	desired.ObservedGeneration = updated.Generation
	meta.SetStatusCondition(&updated.Status.Conditions, desired)
	if updated.Status.ObservedGeneration == zone.Status.ObservedGeneration && reflect.DeepEqual(updated.Status.Conditions, zone.Status.Conditions) {
		return nil
	}
	zone.Status = updated.Status
	return r.Status().Update(ctx, zone)
}

func (r *DNSZoneReconciler) mapVpc(ctx context.Context, obj client.Object) []reconcile.Request {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil
	}
	var zones juneauv1alpha1.DNSZoneList
	if err := r.List(ctx, &zones, client.MatchingFields{dnsZoneVpcIndex: vpc.Name}); err != nil {
		log.FromContext(ctx).Error(err, "unable to list DNSZones for Vpc", "vpc", vpc.Name)
		return nil
	}
	requests := make([]reconcile.Request, 0, len(zones.Items))
	for i := range zones.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: zones.Items[i].Name}})
	}
	return requests
}

func (r *DNSZoneReconciler) mapIdentityPeers(ctx context.Context, obj client.Object) []reconcile.Request {
	zone, ok := obj.(*juneauv1alpha1.DNSZone)
	if !ok {
		return nil
	}
	var zones juneauv1alpha1.DNSZoneList
	if err := r.List(ctx, &zones, client.MatchingFields{dnsZoneVpcIndex: zone.Spec.Vpc}); err != nil {
		log.FromContext(ctx).Error(err, "unable to list DNSZone conflict peers", "name", zone.Name)
		return nil
	}
	requests := make([]reconcile.Request, 0, len(zones.Items))
	for i := range zones.Items {
		if zones.Items[i].Spec.Domain == zone.Spec.Domain {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: zones.Items[i].Name}})
		}
	}
	return requests
}

// SetupWithManager sets up the DNSZone controller.
func (r *DNSZoneReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &juneauv1alpha1.DNSZone{}, dnsZoneVpcIndex, func(obj client.Object) []string {
		zone := obj.(*juneauv1alpha1.DNSZone)
		if zone.Spec.Vpc == "" {
			return nil
		}
		return []string{zone.Spec.Vpc}
	}); err != nil {
		return fmt.Errorf("index DNSZones by Vpc: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.DNSZone{}).
		Watches(&juneauv1alpha1.DNSZone{}, handler.EnqueueRequestsFromMapFunc(r.mapIdentityPeers)).
		Watches(&juneauv1alpha1.Vpc{}, handler.EnqueueRequestsFromMapFunc(r.mapVpc)).
		Named("dnszone").
		Complete(r)
}
