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

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
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

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const vpcEndpointAllocationAttribute = "status.address"

const vpcEndpointServiceVpcAnnotation = "juneau.loutres.me/vpc"

const (
	vpcEndpointReasonVpcUnavailable            = "VpcUnavailable"
	vpcEndpointReasonEndpointPoolNotConfigured = "EndpointPoolNotConfigured"
	vpcEndpointReasonAllocating                = "Allocating"
	vpcEndpointReasonAllocated                 = "Allocated"

	vpcEndpointReasonServiceNotFound        = "ServiceNotFound"
	vpcEndpointReasonClusterIPUnavailable   = "ClusterIPUnavailable"
	vpcEndpointReasonServiceVpcNotFound     = "ServiceVpcNotFound"
	vpcEndpointReasonServiceRoutingDisabled = "ServiceRoutingDisabled"
	vpcEndpointReasonNotAServiceProvider    = "NotAServiceProvider"
	vpcEndpointReasonAccepted               = "Accepted"

	vpcEndpointReasonAddressPending     = "AddressPending"
	vpcEndpointReasonServiceNotAccepted = "ServiceNotAccepted"
	vpcEndpointReasonBackendUnavailable = "BackendUnavailable"
	vpcEndpointReasonReady              = "Ready"
)

type VpcEndpointReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// vpcEndpointCondition carries the parts of a status condition that a
// reconcile pass decides. Type and ObservedGeneration are filled in by
// updateStatus.
type vpcEndpointCondition struct {
	Status  metav1.ConditionStatus
	Reason  string
	Message string
}

func vpcEndpointConditionTrue(reason, message string) vpcEndpointCondition {
	return vpcEndpointCondition{Status: metav1.ConditionTrue, Reason: reason, Message: message}
}

func vpcEndpointConditionFalse(reason, message string) vpcEndpointCondition {
	return vpcEndpointCondition{Status: metav1.ConditionFalse, Reason: reason, Message: message}
}

// vpcEndpointDesiredStatus is the whole status one reconcile pass intends to
// publish. Every field is mandatory, so a branch cannot decide one condition
// and leave another one holding a stale value.
type vpcEndpointDesiredStatus struct {
	Address         string
	AllocationClaim string

	AddressAllocated vpcEndpointCondition
	ServiceAccepted  vpcEndpointCondition
	Ready            vpcEndpointCondition
}

// vpcEndpointBlocked reports the same cause on all three conditions, for
// failures that stop the reconciler before it can judge them apart.
func vpcEndpointBlocked(reason, message string) vpcEndpointDesiredStatus {
	blocked := vpcEndpointConditionFalse(reason, message)
	return vpcEndpointDesiredStatus{AddressAllocated: blocked, ServiceAccepted: blocked, Ready: blocked}
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcendpoints,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcendpoints/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcendpoints/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcs,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch

func (r *VpcEndpointReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var endpoint juneauv1alpha1.VpcEndpoint
	if err := r.Get(ctx, req.NamespacedName, &endpoint); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !endpoint.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	desired, err := r.buildStatus(ctx, &endpoint)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.updateStatus(ctx, &endpoint, desired)
}

func (r *VpcEndpointReconciler) buildStatus(ctx context.Context, endpoint *juneauv1alpha1.VpcEndpoint) (vpcEndpointDesiredStatus, error) {
	var vpc juneauv1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: endpoint.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			return vpcEndpointBlocked(vpcEndpointReasonVpcUnavailable, fmt.Sprintf("Vpc %q does not exist", endpoint.Spec.Vpc)), nil
		}
		return vpcEndpointDesiredStatus{}, err
	}

	accepted, err := r.serviceAccepted(ctx, endpoint)
	if err != nil {
		return vpcEndpointDesiredStatus{}, err
	}
	desired := vpcEndpointDesiredStatus{ServiceAccepted: accepted}

	if !vpc.Spec.EndpointPool.Configured() {
		message := fmt.Sprintf("Vpc %q does not declare spec.endpointPool", vpc.Name)
		desired.AddressAllocated = vpcEndpointConditionFalse(vpcEndpointReasonEndpointPoolNotConfigured, message)
		desired.Ready = vpcEndpointConditionFalse(vpcEndpointReasonEndpointPoolNotConfigured, message)
		return desired, nil
	}

	claim, err := r.ensureClaim(ctx, endpoint)
	if err != nil {
		return vpcEndpointDesiredStatus{}, err
	}
	desired.AllocationClaim = claim.Name
	if claim.Status.Phase != juneauv1alpha1.AllocationClaimPhaseAllocated || claim.Status.Value.IP == "" {
		desired.AddressAllocated = vpcEndpointConditionFalse(vpcEndpointReasonAllocating, "endpoint address allocation is pending")
		desired.Ready = vpcEndpointConditionFalse(vpcEndpointReasonAddressPending, "endpoint address has not been allocated")
		return desired, nil
	}

	desired.Address = claim.Status.Value.IP
	desired.AddressAllocated = vpcEndpointConditionTrue(vpcEndpointReasonAllocated, fmt.Sprintf("allocated %s from the endpoint pool of Vpc %q", desired.Address, vpc.Name))

	if accepted.Status != metav1.ConditionTrue {
		desired.Ready = vpcEndpointConditionFalse(vpcEndpointReasonServiceNotAccepted, accepted.Message)
		return desired, nil
	}

	ready, message, err := r.backendsReady(ctx, endpoint)
	if err != nil {
		return vpcEndpointDesiredStatus{}, err
	}
	if !ready {
		desired.Ready = vpcEndpointConditionFalse(vpcEndpointReasonBackendUnavailable, message)
		return desired, nil
	}
	desired.Ready = vpcEndpointConditionTrue(vpcEndpointReasonReady, message)
	return desired, nil
}

func (r *VpcEndpointReconciler) ensureClaim(ctx context.Context, endpoint *juneauv1alpha1.VpcEndpoint) (*juneauv1alpha1.AllocationClaim, error) {
	gvk := schema.GroupVersionKind{Group: juneauv1alpha1.GroupVersion.Group, Version: juneauv1alpha1.GroupVersion.Version, Kind: "VpcEndpoint"}
	desired := newAllocationClaim(VpcEndpointIPAllocationPoolName(endpoint.Spec.Vpc), gvk, "", endpoint.Name, vpcEndpointAllocationAttribute)
	if len(endpoint.Spec.DNSNames) > 0 {
		desired.Spec.DNS = &juneauv1alpha1.AllocationDNSBinding{
			Vpc:   endpoint.Spec.Vpc,
			Names: append([]string(nil), endpoint.Spec.DNSNames...),
		}
	}
	claim := &juneauv1alpha1.AllocationClaim{ObjectMeta: metav1.ObjectMeta{Name: desired.Name}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, claim, func() error {
		claim.Spec = desired.Spec
		return controllerutil.SetControllerReference(endpoint, claim, r.Scheme)
	}); err != nil {
		return nil, fmt.Errorf("ensure endpoint AllocationClaim: %w", err)
	}
	return claim, nil
}

// serviceAccepted judges the configuration half of the binding: the Service
// exists, has a ClusterIP, and the Vpc that owns it lets this VpcEndpoint
// front it. The daemon gates its BPF map write on this condition rather than
// on Ready, because Ready also follows the backend EndpointSlices: keying the
// map on Ready would rewrite the entry every time a backend Pod comes or
// goes, while ServiceAccepted only moves when a user changes the Service or a
// Vpc.
func (r *VpcEndpointReconciler) serviceAccepted(ctx context.Context, endpoint *juneauv1alpha1.VpcEndpoint) (vpcEndpointCondition, error) {
	ref := endpoint.Spec.Service
	var svc corev1.Service
	if err := r.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &svc); err != nil {
		if errors.IsNotFound(err) {
			return vpcEndpointConditionFalse(vpcEndpointReasonServiceNotFound, fmt.Sprintf("Service %s/%s does not exist yet", ref.Namespace, ref.Name)), nil
		}
		return vpcEndpointCondition{}, err
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return vpcEndpointConditionFalse(vpcEndpointReasonClusterIPUnavailable, "backend Service has no ClusterIP"), nil
	}
	ownerVpcName := defaultVpcName
	if value := svc.Annotations[vpcEndpointServiceVpcAnnotation]; value != "" {
		ownerVpcName = value
	}
	var ownerVpc juneauv1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: ownerVpcName}, &ownerVpc); err != nil {
		if errors.IsNotFound(err) {
			return vpcEndpointConditionFalse(vpcEndpointReasonServiceVpcNotFound, fmt.Sprintf("backend Service Vpc %q does not exist", ownerVpcName)), nil
		}
		return vpcEndpointCondition{}, err
	}
	if !ownerVpc.Spec.ServiceEnabled() {
		return vpcEndpointConditionFalse(vpcEndpointReasonServiceRoutingDisabled, fmt.Sprintf("backend Service Vpc %q does not have Service routing enabled", ownerVpcName)), nil
	}
	if ownerVpcName != endpoint.Spec.Vpc && !ownerVpc.Spec.Service.IsProvider() {
		return vpcEndpointConditionFalse(vpcEndpointReasonNotAServiceProvider, fmt.Sprintf("backend Service Vpc %q is not a Service provider", ownerVpcName)), nil
	}
	return vpcEndpointConditionTrue(vpcEndpointReasonAccepted, fmt.Sprintf("backend Service %s/%s is accepted", ref.Namespace, ref.Name)), nil
}

func (r *VpcEndpointReconciler) backendsReady(ctx context.Context, endpoint *juneauv1alpha1.VpcEndpoint) (bool, string, error) {
	ref := endpoint.Spec.Service
	var slices discoveryv1.EndpointSliceList
	if err := r.List(ctx, &slices, client.InNamespace(ref.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: ref.Name}); err != nil {
		return false, "", err
	}
	for i := range slices.Items {
		for j := range slices.Items[i].Endpoints {
			ep := &slices.Items[i].Endpoints[j]
			if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
				return true, "endpoint address and backend Service are ready", nil
			}
		}
	}
	return false, "backend Service has no ready endpoints", nil
}

func (r *VpcEndpointReconciler) updateStatus(ctx context.Context, endpoint *juneauv1alpha1.VpcEndpoint, desired vpcEndpointDesiredStatus) error {
	updated := endpoint.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.Address = desired.Address
	updated.Status.AllocationClaim = desired.AllocationClaim
	setVpcEndpointCondition(&updated.Status.Conditions, juneauv1alpha1.VpcEndpointConditionAddressAllocated, desired.AddressAllocated, updated.Generation)
	setVpcEndpointCondition(&updated.Status.Conditions, juneauv1alpha1.VpcEndpointConditionServiceAccepted, desired.ServiceAccepted, updated.Generation)
	setVpcEndpointCondition(&updated.Status.Conditions, juneauv1alpha1.VpcEndpointConditionReady, desired.Ready, updated.Generation)

	if updated.Status.ObservedGeneration == endpoint.Status.ObservedGeneration &&
		updated.Status.Address == endpoint.Status.Address &&
		updated.Status.AllocationClaim == endpoint.Status.AllocationClaim &&
		reflect.DeepEqual(updated.Status.Conditions, endpoint.Status.Conditions) {
		return nil
	}

	endpoint.Status = updated.Status
	return r.Status().Update(ctx, endpoint)
}

func setVpcEndpointCondition(conditions *[]metav1.Condition, conditionType string, desired vpcEndpointCondition, generation int64) {
	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               conditionType,
		Status:             desired.Status,
		Reason:             desired.Reason,
		Message:            desired.Message,
		ObservedGeneration: generation,
	})
}

func (r *VpcEndpointReconciler) mapService(ctx context.Context, obj client.Object) []reconcile.Request {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return nil
	}
	return r.requestsForService(ctx, svc.Namespace, svc.Name)
}

func (r *VpcEndpointReconciler) mapEndpointSlice(ctx context.Context, obj client.Object) []reconcile.Request {
	slice, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return nil
	}
	return r.requestsForService(ctx, slice.Namespace, slice.Labels[discoveryv1.LabelServiceName])
}

// mapVpc wakes the VpcEndpoints of a Vpc. Both the endpoint pool and the
// VpcID the daemon needs live on the Vpc, so an endpoint created before its
// Vpc would otherwise wait forever with nothing to requeue it.
func (r *VpcEndpointReconciler) mapVpc(ctx context.Context, obj client.Object) []reconcile.Request {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil
	}
	var list juneauv1alpha1.VpcEndpointList
	if err := r.List(ctx, &list); err != nil {
		log.FromContext(ctx).Error(err, "list VpcEndpoints for Vpc fan-out")
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for i := range list.Items {
		if list.Items[i].Spec.Vpc == vpc.Name {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: list.Items[i].Name}})
		}
	}
	return requests
}

func (r *VpcEndpointReconciler) requestsForService(ctx context.Context, namespace, name string) []reconcile.Request {
	if namespace == "" || name == "" {
		return nil
	}
	var list juneauv1alpha1.VpcEndpointList
	if err := r.List(ctx, &list); err != nil {
		log.FromContext(ctx).Error(err, "list VpcEndpoints for Service fan-out")
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for i := range list.Items {
		if list.Items[i].Spec.Service.Namespace == namespace && list.Items[i].Spec.Service.Name == name {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: list.Items[i].Name}})
		}
	}
	return requests
}

func (r *VpcEndpointReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.VpcEndpoint{}).
		Owns(&juneauv1alpha1.AllocationClaim{}).
		Watches(&juneauv1alpha1.Vpc{}, handler.EnqueueRequestsFromMapFunc(r.mapVpc)).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.mapService)).
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(r.mapEndpointSlice)).
		Named("vpcendpoint").
		Complete(r)
}
