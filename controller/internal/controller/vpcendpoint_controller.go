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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const vpcEndpointAllocationAttribute = "status.address"

const vpcEndpointServiceVpcAnnotation = "juneau.loutres.me/vpc"

type VpcEndpointReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcendpoints,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcendpoints/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcendpoints/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
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
	before := endpoint.DeepCopy()
	endpoint.Status.ObservedGeneration = endpoint.Generation

	var subnet juneauv1alpha1.Subnet
	if err := r.Get(ctx, client.ObjectKey{Name: endpoint.Spec.Subnet}, &subnet); err != nil {
		meta.SetStatusCondition(&endpoint.Status.Conditions, metav1.Condition{Type: juneauv1alpha1.VpcEndpointConditionAddressAllocated, Status: metav1.ConditionFalse, Reason: "SubnetUnavailable", Message: fmt.Sprintf("Subnet %q is unavailable", endpoint.Spec.Subnet), ObservedGeneration: endpoint.Generation})
		return ctrl.Result{}, r.patchStatus(ctx, before, &endpoint)
	}
	if subnet.Spec.Vpc != endpoint.Spec.Vpc {
		meta.SetStatusCondition(&endpoint.Status.Conditions, metav1.Condition{Type: juneauv1alpha1.VpcEndpointConditionAddressAllocated, Status: metav1.ConditionFalse, Reason: "VpcMismatch", Message: fmt.Sprintf("Subnet %q belongs to Vpc %q", subnet.Name, subnet.Spec.Vpc), ObservedGeneration: endpoint.Generation})
		return ctrl.Result{}, r.patchStatus(ctx, before, &endpoint)
	}

	claim, err := r.ensureClaim(ctx, &endpoint)
	if err != nil {
		return ctrl.Result{}, err
	}
	endpoint.Status.AllocationClaim = claim.Name
	if claim.Status.Phase != juneauv1alpha1.AllocationClaimPhaseAllocated || claim.Status.Value.IP == "" {
		meta.SetStatusCondition(&endpoint.Status.Conditions, metav1.Condition{Type: juneauv1alpha1.VpcEndpointConditionAddressAllocated, Status: metav1.ConditionFalse, Reason: "Allocating", Message: "endpoint address allocation is pending", ObservedGeneration: endpoint.Generation})
		meta.SetStatusCondition(&endpoint.Status.Conditions, metav1.Condition{Type: juneauv1alpha1.VpcEndpointConditionReady, Status: metav1.ConditionFalse, Reason: "AddressPending", Message: "endpoint address has not been allocated", ObservedGeneration: endpoint.Generation})
		return ctrl.Result{}, r.patchStatus(ctx, before, &endpoint)
	}

	endpoint.Status.Address = claim.Status.Value.IP
	meta.SetStatusCondition(&endpoint.Status.Conditions, metav1.Condition{Type: juneauv1alpha1.VpcEndpointConditionAddressAllocated, Status: metav1.ConditionTrue, Reason: "Allocated", Message: fmt.Sprintf("allocated %s from Subnet %q", endpoint.Status.Address, subnet.Name), ObservedGeneration: endpoint.Generation})
	ready, message, err := r.backendReady(ctx, &endpoint)
	if err != nil {
		return ctrl.Result{}, err
	}
	condition := metav1.Condition{Type: juneauv1alpha1.VpcEndpointConditionReady, Status: metav1.ConditionFalse, Reason: "BackendUnavailable", Message: message, ObservedGeneration: endpoint.Generation}
	if ready {
		condition.Status, condition.Reason = metav1.ConditionTrue, "Ready"
	}
	meta.SetStatusCondition(&endpoint.Status.Conditions, condition)
	return ctrl.Result{}, r.patchStatus(ctx, before, &endpoint)
}

func (r *VpcEndpointReconciler) ensureClaim(ctx context.Context, endpoint *juneauv1alpha1.VpcEndpoint) (*juneauv1alpha1.AllocationClaim, error) {
	gvk := schema.GroupVersionKind{Group: juneauv1alpha1.GroupVersion.Group, Version: juneauv1alpha1.GroupVersion.Version, Kind: "VpcEndpoint"}
	desired := newAllocationClaim(SubnetIPAllocationPoolName(endpoint.Spec.Subnet), gvk, "", endpoint.Name, vpcEndpointAllocationAttribute)
	claim := &juneauv1alpha1.AllocationClaim{ObjectMeta: metav1.ObjectMeta{Name: desired.Name}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, claim, func() error {
		claim.Spec = desired.Spec
		return controllerutil.SetControllerReference(endpoint, claim, r.Scheme)
	}); err != nil {
		return nil, fmt.Errorf("ensure endpoint AllocationClaim: %w", err)
	}
	return claim, nil
}

func (r *VpcEndpointReconciler) backendReady(ctx context.Context, endpoint *juneauv1alpha1.VpcEndpoint) (bool, string, error) {
	ref := endpoint.Spec.Service
	var svc corev1.Service
	if err := r.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &svc); err != nil {
		if errors.IsNotFound(err) {
			return false, fmt.Sprintf("Service %s/%s does not exist yet", ref.Namespace, ref.Name), nil
		}
		return false, "", err
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return false, "backend Service has no ClusterIP", nil
	}
	ownerVpcName := defaultVpcName
	if value := svc.Annotations[vpcEndpointServiceVpcAnnotation]; value != "" {
		ownerVpcName = value
	}
	var ownerVpc juneauv1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: ownerVpcName}, &ownerVpc); err != nil {
		if errors.IsNotFound(err) {
			return false, fmt.Sprintf("backend Service Vpc %q does not exist", ownerVpcName), nil
		}
		return false, "", err
	}
	if !ownerVpc.Spec.ServiceEnabled() {
		return false, fmt.Sprintf("backend Service Vpc %q does not have Service routing enabled", ownerVpcName), nil
	}
	if ownerVpcName != endpoint.Spec.Vpc && (ownerVpc.Spec.Service == nil || ownerVpc.Spec.Service.Provider == nil) {
		return false, fmt.Sprintf("backend Service Vpc %q is not a Service provider", ownerVpcName), nil
	}
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

func (r *VpcEndpointReconciler) patchStatus(ctx context.Context, before, endpoint *juneauv1alpha1.VpcEndpoint) error {
	return r.Status().Patch(ctx, endpoint, client.MergeFrom(before))
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
func (r *VpcEndpointReconciler) requestsForService(ctx context.Context, namespace, name string) []reconcile.Request {
	if namespace == "" || name == "" {
		return nil
	}
	var list juneauv1alpha1.VpcEndpointList
	if err := r.List(ctx, &list); err != nil {
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
	return ctrl.NewControllerManagedBy(mgr).For(&juneauv1alpha1.VpcEndpoint{}).Owns(&juneauv1alpha1.AllocationClaim{}).Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.mapService)).Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(r.mapEndpointSlice)).Named("vpcendpoint").Complete(r)
}
