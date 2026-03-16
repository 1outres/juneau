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

	if !resource.ObjectMeta.DeletionTimestamp.IsZero() {
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
		if err := r.updatePendingStatus(ctx, resource, elasticIP.Status.Address, networkInterface.Status.Address, "", elasticIPAttachmentReasonReconcileFailed, fmt.Sprintf("waiting for NetworkInterface %q node assignment", networkInterface.Name)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	var networkEndpoint juneauloutresmev1alpha1.NetworkEndpoint
	if err := r.Get(ctx, client.ObjectKey{Namespace: resource.Namespace, Name: networkInterface.Name}, &networkEndpoint); err != nil {
		if errors.IsNotFound(err) {
			if err := r.updatePendingStatus(ctx, resource, elasticIP.Status.Address, networkInterface.Status.Address, networkInterface.Spec.NodeName, elasticIPAttachmentReasonWaitingForNetworkEndpoint, fmt.Sprintf("waiting for NetworkEndpoint %q", networkInterface.Name)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if networkEndpoint.DeletionTimestamp != nil {
		if err := r.updatePendingStatus(ctx, resource, elasticIP.Status.Address, networkInterface.Status.Address, networkInterface.Spec.NodeName, elasticIPAttachmentReasonWaitingForNetworkEndpoint, fmt.Sprintf("NetworkEndpoint %q is being deleted", networkEndpoint.Name)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if err := r.updateStatus(ctx, resource,
		juneauloutresmev1alpha1.ElasticIPAttachmentPhaseAttached,
		elasticIP.Status.Address,
		networkInterface.Status.Address,
		networkInterface.Spec.NodeName,
		metav1.Condition{
			Type:    elasticIPAttachmentConditionReady,
			Status:  metav1.ConditionTrue,
			Reason:  elasticIPAttachmentReasonAttached,
			Message: fmt.Sprintf("ElasticIP %q attached to NetworkInterface %q", elasticIP.Name, networkInterface.Name),
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
	resource.Status.ObservedGeneration = resource.Generation
	resource.Status.Phase = phase
	resource.Status.ElasticIP = elasticIPAddress
	resource.Status.PodIP = podIP
	resource.Status.NodeName = nodeName
	for _, condition := range conditions {
		meta.SetStatusCondition(&resource.Status.Conditions, condition)
	}
	return r.Status().Update(ctx, resource)
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

	var attachmentList juneauloutresmev1alpha1.ElasticIPAttachmentList
	if err := r.List(ctx, &attachmentList,
		client.InNamespace(networkEndpoint.Namespace),
		client.MatchingFields{"spec.targetRef.networkInterfaceName": networkEndpoint.Name},
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

// SetupWithManager sets up the controller with the Manager.
func (r *ElasticIPAttachmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauloutresmev1alpha1.ElasticIPAttachment{},
		"spec.elasticIPRef.name",
		func(obj client.Object) []string {
			attachment := obj.(*juneauloutresmev1alpha1.ElasticIPAttachment)
			if attachment.Spec.ElasticIPRef.Name == "" {
				return nil
			}
			return []string{attachment.Spec.ElasticIPRef.Name}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for ElasticIPAttachment.spec.elasticIPRef.name: %w", err)
	}

	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauloutresmev1alpha1.ElasticIPAttachment{},
		"spec.targetRef.networkInterfaceName",
		func(obj client.Object) []string {
			attachment := obj.(*juneauloutresmev1alpha1.ElasticIPAttachment)
			if attachment.Spec.TargetRef.NetworkInterfaceName == "" {
				return nil
			}
			return []string{attachment.Spec.TargetRef.NetworkInterfaceName}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for ElasticIPAttachment.spec.targetRef.networkInterfaceName: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.ElasticIPAttachment{}).
		Watches(&juneauloutresmev1alpha1.ElasticIP{}, handler.EnqueueRequestsFromMapFunc(r.mapElasticIPToAttachments)).
		Watches(&juneauloutresmev1alpha1.NetworkInterface{}, handler.EnqueueRequestsFromMapFunc(r.mapNetworkInterfaceToAttachments)).
		Watches(&juneauloutresmev1alpha1.NetworkEndpoint{}, handler.EnqueueRequestsFromMapFunc(r.mapNetworkEndpointToAttachments)).
		Named("elasticipattachment").
		Complete(r)
}
