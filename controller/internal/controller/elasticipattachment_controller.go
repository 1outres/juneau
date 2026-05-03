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
	"net"
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

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	elasticIPAttachmentConditionReady = "Ready"

	elasticIPAttachmentReasonAttached                  = "Attached"
	elasticIPAttachmentReasonWaitingForElasticIP       = "WaitingForElasticIP"
	elasticIPAttachmentReasonWaitingForNetworkEndpoint = "WaitingForNetworkEndpoint"
	elasticIPAttachmentReasonReconcileFailed           = "ReconcileFailed"
)

// ElasticIPAttachmentReconciler reconciles a ElasticIPAttachment object
type ElasticIPAttachmentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=elasticipattachments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=elasticipattachments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=elasticipattachments/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=elasticips,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkinterfaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkendpoints,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ElasticIPAttachmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauloutresmev1alpha1.ElasticIPAttachment
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get ElasticIPAttachment", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	return r.reconcileNormal(ctx, &resource)
}

func (r *ElasticIPAttachmentReconciler) reconcileNormal(ctx context.Context, resource *juneauloutresmev1alpha1.ElasticIPAttachment) (ctrl.Result, error) {
	var elasticIP juneauloutresmev1alpha1.ElasticIP
	if err := r.Get(ctx, client.ObjectKey{Namespace: resource.Namespace, Name: resource.Spec.ElasticIPRef.Name}, &elasticIP); err != nil {
		if errors.IsNotFound(err) {
			if err := r.updateErrorStatus(ctx, resource, elasticIPAttachmentReasonReconcileFailed, fmt.Sprintf("ElasticIP %q not found", resource.Spec.ElasticIPRef.Name)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if elasticIP.DeletionTimestamp != nil {
		if err := r.updatePendingStatus(ctx, resource, "", "", "", elasticIPAttachmentReasonWaitingForElasticIP, fmt.Sprintf("ElasticIP %q is being deleted", elasticIP.Name)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if elasticIP.Status.Address == "" {
		if err := r.updatePendingStatus(ctx, resource, "", "", "", elasticIPAttachmentReasonWaitingForElasticIP, fmt.Sprintf("waiting for ElasticIP %q address allocation", elasticIP.Name)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	var networkInterface juneauloutresmev1alpha1.NetworkInterface
	if err := r.Get(ctx, client.ObjectKey{Namespace: resource.Namespace, Name: resource.Spec.TargetRef.NetworkInterfaceName}, &networkInterface); err != nil {
		if errors.IsNotFound(err) {
			if err := r.updateErrorStatus(ctx, resource, elasticIPAttachmentReasonReconcileFailed, fmt.Sprintf("NetworkInterface %q not found", resource.Spec.TargetRef.NetworkInterfaceName)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if networkInterface.DeletionTimestamp != nil {
		if err := r.updatePendingStatus(ctx, resource, elasticIP.Status.Address, "", "", elasticIPAttachmentReasonReconcileFailed, fmt.Sprintf("NetworkInterface %q is being deleted", networkInterface.Name)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if networkInterface.Status.Address == "" {
		if err := r.updatePendingStatus(ctx, resource, elasticIP.Status.Address, "", "", elasticIPAttachmentReasonReconcileFailed, fmt.Sprintf("waiting for NetworkInterface %q address allocation", networkInterface.Name)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if networkInterface.Spec.NodeName == "" {
		podIP, err := normalizeIPAddress(networkInterface.Status.Address)
		if err != nil {
			if err := r.updateErrorStatus(ctx, resource, elasticIPAttachmentReasonReconcileFailed, fmt.Sprintf("invalid NetworkInterface %q address %q", networkInterface.Name, networkInterface.Status.Address)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		if err := r.updatePendingStatus(ctx, resource, elasticIP.Status.Address, podIP, "", elasticIPAttachmentReasonReconcileFailed, fmt.Sprintf("waiting for NetworkInterface %q node assignment", networkInterface.Name)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	podIP, err := normalizeIPAddress(networkInterface.Status.Address)
	if err != nil {
		if err := r.updateErrorStatus(ctx, resource, elasticIPAttachmentReasonReconcileFailed, fmt.Sprintf("invalid NetworkInterface %q address %q", networkInterface.Name, networkInterface.Status.Address)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	matchingEndpoints, err := r.findMatchingNetworkEndpoints(ctx, resource.Namespace, networkInterface.Spec.PodRef)
	if err != nil {
		return ctrl.Result{}, err
	}

	switch len(matchingEndpoints) {
	case 0:
		if err := r.updatePendingStatus(ctx, resource, elasticIP.Status.Address, podIP, networkInterface.Spec.NodeName, elasticIPAttachmentReasonWaitingForNetworkEndpoint, fmt.Sprintf("waiting for NetworkEndpoint matching podRef uid=%q name=%q interface=%q", networkInterface.Spec.PodRef.UID, networkInterface.Spec.PodRef.Name, networkInterface.Spec.PodRef.Interface)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	case 1:
	default:
		if err := r.updateErrorStatus(ctx, resource, elasticIPAttachmentReasonReconcileFailed, fmt.Sprintf("multiple NetworkEndpoints match podRef uid=%q name=%q interface=%q", networkInterface.Spec.PodRef.UID, networkInterface.Spec.PodRef.Name, networkInterface.Spec.PodRef.Interface)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	networkEndpoint := matchingEndpoints[0]

	if networkEndpoint.DeletionTimestamp != nil {
		if err := r.updatePendingStatus(ctx, resource, elasticIP.Status.Address, podIP, networkInterface.Spec.NodeName, elasticIPAttachmentReasonWaitingForNetworkEndpoint, fmt.Sprintf("NetworkEndpoint %q is being deleted", networkEndpoint.Name)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if err := r.updateStatus(ctx, resource,
		juneauloutresmev1alpha1.ElasticIPAttachmentPhaseAttached,
		elasticIP.Status.Address,
		podIP,
		networkInterface.Spec.NodeName,
		metav1.Condition{
			Type:               elasticIPAttachmentConditionReady,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: resource.Generation,
			Reason:             elasticIPAttachmentReasonAttached,
			Message:            fmt.Sprintf("ElasticIP %q attached to NetworkInterface %q", elasticIP.Name, networkInterface.Name),
		},
	); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *ElasticIPAttachmentReconciler) updatePendingStatus(
	ctx context.Context,
	resource *juneauloutresmev1alpha1.ElasticIPAttachment,
	elasticIPAddress string,
	podIP string,
	nodeName string,
	reason string,
	message string,
) error {
	return r.updateStatus(ctx, resource,
		juneauloutresmev1alpha1.ElasticIPAttachmentPhasePending,
		elasticIPAddress,
		podIP,
		nodeName,
		metav1.Condition{
			Type:    elasticIPAttachmentConditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  reason,
			Message: message,
		},
	)
}

func (r *ElasticIPAttachmentReconciler) updateErrorStatus(
	ctx context.Context,
	resource *juneauloutresmev1alpha1.ElasticIPAttachment,
	reason string,
	message string,
) error {
	return r.updateStatus(ctx, resource,
		juneauloutresmev1alpha1.ElasticIPAttachmentPhaseError,
		"",
		"",
		"",
		metav1.Condition{
			Type:    elasticIPAttachmentConditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  reason,
			Message: message,
		},
	)
}

func (r *ElasticIPAttachmentReconciler) updateStatus(
	ctx context.Context,
	resource *juneauloutresmev1alpha1.ElasticIPAttachment,
	phase juneauloutresmev1alpha1.ElasticIPAttachmentPhase,
	elasticIPAddress string,
	podIP string,
	nodeName string,
	conditions ...metav1.Condition,
) error {
	updated := resource.Status
	updated.ObservedGeneration = resource.Generation
	updated.Phase = phase
	updated.ElasticIP = elasticIPAddress
	updated.PodIP = podIP
	updated.NodeName = nodeName
	for _, condition := range conditions {
		condition.ObservedGeneration = resource.Generation
		meta.SetStatusCondition(&updated.Conditions, condition)
	}

	if reflect.DeepEqual(resource.Status, updated) {
		return nil
	}

	resource.Status = updated
	return r.Status().Update(ctx, resource)
}

func (r *ElasticIPAttachmentReconciler) findMatchingNetworkEndpoints(
	ctx context.Context,
	namespace string,
	podRef juneauloutresmev1alpha1.NetworkInterfacePodReference,
) ([]juneauloutresmev1alpha1.NetworkEndpoint, error) {
	var networkEndpointList juneauloutresmev1alpha1.NetworkEndpointList
	if err := r.List(ctx, &networkEndpointList, client.InNamespace(namespace)); err != nil {
		return nil, err
	}

	matches := make([]juneauloutresmev1alpha1.NetworkEndpoint, 0, 1)
	for i := range networkEndpointList.Items {
		item := networkEndpointList.Items[i]
		if item.Spec.PodRef == nil {
			continue
		}
		if item.Spec.PodRef.UID != podRef.UID {
			continue
		}
		if item.Spec.PodRef.Name != podRef.Name {
			continue
		}
		if item.Spec.PodRef.Interface != podRef.Interface {
			continue
		}
		matches = append(matches, item)
	}

	return matches, nil
}

func normalizeIPAddress(address string) (string, error) {
	if address == "" {
		return "", nil
	}

	ip := net.ParseIP(address)
	if ip != nil {
		return ip.String(), nil
	}

	ip, _, err := net.ParseCIDR(address)
	if err != nil {
		return "", err
	}

	return ip.String(), nil
}

func (r *ElasticIPAttachmentReconciler) mapElasticIPToAttachments(ctx context.Context, obj client.Object) []reconcile.Request {
	elasticIP, ok := obj.(*juneauloutresmev1alpha1.ElasticIP)
	if !ok {
		return nil
	}

	var attachmentList juneauloutresmev1alpha1.ElasticIPAttachmentList
	if err := r.List(ctx, &attachmentList,
		client.InNamespace(elasticIP.Namespace),
		client.MatchingFields{"spec.elasticIPRef.name": elasticIP.Name},
	); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(attachmentList.Items))
	for i := range attachmentList.Items {
		item := attachmentList.Items[i]
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Namespace: item.Namespace, Name: item.Name}})
	}
	return requests
}

func (r *ElasticIPAttachmentReconciler) mapNetworkInterfaceToAttachments(ctx context.Context, obj client.Object) []reconcile.Request {
	networkInterface, ok := obj.(*juneauloutresmev1alpha1.NetworkInterface)
	if !ok {
		return nil
	}

	var attachmentList juneauloutresmev1alpha1.ElasticIPAttachmentList
	if err := r.List(ctx, &attachmentList,
		client.InNamespace(networkInterface.Namespace),
		client.MatchingFields{"spec.targetRef.networkInterfaceName": networkInterface.Name},
	); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(attachmentList.Items))
	for i := range attachmentList.Items {
		item := attachmentList.Items[i]
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Namespace: item.Namespace, Name: item.Name}})
	}
	return requests
}

func (r *ElasticIPAttachmentReconciler) mapNetworkEndpointToAttachments(ctx context.Context, obj client.Object) []reconcile.Request {
	networkEndpoint, ok := obj.(*juneauloutresmev1alpha1.NetworkEndpoint)
	if !ok {
		return nil
	}

	var networkInterfaceList juneauloutresmev1alpha1.NetworkInterfaceList
	if err := r.List(ctx, &networkInterfaceList, client.InNamespace(networkEndpoint.Namespace)); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0)
	seen := make(map[client.ObjectKey]struct{})
	if networkEndpoint.Spec.PodRef == nil {
		return nil
	}
	for i := range networkInterfaceList.Items {
		networkInterface := networkInterfaceList.Items[i]
		if networkInterface.Spec.PodRef.UID != networkEndpoint.Spec.PodRef.UID {
			continue
		}
		if networkInterface.Spec.PodRef.Name != networkEndpoint.Spec.PodRef.Name {
			continue
		}
		if networkInterface.Spec.PodRef.Interface != networkEndpoint.Spec.PodRef.Interface {
			continue
		}

		var attachmentList juneauloutresmev1alpha1.ElasticIPAttachmentList
		if err := r.List(ctx, &attachmentList,
			client.InNamespace(networkEndpoint.Namespace),
			client.MatchingFields{"spec.targetRef.networkInterfaceName": networkInterface.Name},
		); err != nil {
			return nil
		}

		for j := range attachmentList.Items {
			item := attachmentList.Items[j]
			key := client.ObjectKey{Namespace: item.Namespace, Name: item.Name}
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			requests = append(requests, reconcile.Request{NamespacedName: key})
		}
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *ElasticIPAttachmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.ElasticIPAttachment{}).
		Watches(&juneauloutresmev1alpha1.ElasticIP{}, handler.EnqueueRequestsFromMapFunc(r.mapElasticIPToAttachments)).
		Watches(&juneauloutresmev1alpha1.NetworkInterface{}, handler.EnqueueRequestsFromMapFunc(r.mapNetworkInterfaceToAttachments)).
		Watches(&juneauloutresmev1alpha1.NetworkEndpoint{}, handler.EnqueueRequestsFromMapFunc(r.mapNetworkEndpointToAttachments)).
		Named("elasticipattachment").
		Complete(r)
}
