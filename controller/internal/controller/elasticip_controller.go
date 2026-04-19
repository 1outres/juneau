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
	stderrors "errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

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
	elasticIPConditionAllocated = "Allocated"
	elasticIPConditionAttached  = "Attached"

	elasticIPReasonReconcileSucceeded = "ReconcileSucceeded"
	elasticIPReasonAwaitingAttachment = "AwaitingAttachment"
	elasticIPReasonNoAddressAvailable = "NoAddressAvailable"
	elasticIPReasonMissingDependency  = "MissingDependency"
	elasticIPReasonInvalidAddressPool = "InvalidAddressPool"
	elasticIPReasonAttached           = "Attached"
	elasticIPReasonConflict           = "Conflict"

	elasticIPAddressRetryAfter = 10 * time.Second
)

type elasticIPReconcileError struct {
	reason  string
	message string
}

func (e *elasticIPReconcileError) Error() string {
	return e.message
}

// ElasticIPReconciler reconciles a ElasticIP object
type ElasticIPReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=elasticips,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=elasticips/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=elasticips/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=externalnetworks,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresspools,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=elasticipattachments,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ElasticIPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauv1alpha1.ElasticIP
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get ElasticIP", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.ObjectMeta.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	return r.reconcileNormal(ctx, &resource)
}

func (r *ElasticIPReconciler) reconcileNormal(ctx context.Context, resource *juneauv1alpha1.ElasticIP) (ctrl.Result, error) {
	address, requeue, err := r.resolveAddress(ctx, resource)
	if err != nil {
		var reconcileErr *elasticIPReconcileError
		if stderrors.As(err, &reconcileErr) {
			if err := r.updateErrorStatus(ctx, resource, reconcileErr.reason, reconcileErr.message); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if requeue {
		if err := r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhasePending, "", "",
			metav1.Condition{
				Type:    elasticIPConditionAllocated,
				Status:  metav1.ConditionFalse,
				Reason:  elasticIPReasonNoAddressAvailable,
				Message: "no available address in referenced AddressPools",
			},
			metav1.Condition{
				Type:    elasticIPConditionAttached,
				Status:  metav1.ConditionFalse,
				Reason:  elasticIPReasonAwaitingAttachment,
				Message: "ElasticIP is not attached",
			},
		); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: elasticIPAddressRetryAfter}, nil
	}

	attachments, err := r.listActiveAttachments(ctx, resource)
	if err != nil {
		return ctrl.Result{}, err
	}

	switch len(attachments) {
	case 0:
		if err := r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhaseAvailable, address, "",
			metav1.Condition{
				Type:    elasticIPConditionAllocated,
				Status:  metav1.ConditionTrue,
				Reason:  elasticIPReasonReconcileSucceeded,
				Message: "ElasticIP address allocated",
			},
			metav1.Condition{
				Type:    elasticIPConditionAttached,
				Status:  metav1.ConditionFalse,
				Reason:  elasticIPReasonAwaitingAttachment,
				Message: "ElasticIP is not attached",
			},
		); err != nil {
			return ctrl.Result{}, err
		}
	case 1:
		if err := r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhaseAttached, address, attachments[0].Name,
			metav1.Condition{
				Type:    elasticIPConditionAllocated,
				Status:  metav1.ConditionTrue,
				Reason:  elasticIPReasonReconcileSucceeded,
				Message: "ElasticIP address allocated",
			},
			metav1.Condition{
				Type:    elasticIPConditionAttached,
				Status:  metav1.ConditionTrue,
				Reason:  elasticIPReasonAttached,
				Message: fmt.Sprintf("ElasticIP is attached by %s", attachments[0].Name),
			},
		); err != nil {
			return ctrl.Result{}, err
		}
	default:
		if err := r.updateErrorStatus(ctx, resource, elasticIPReasonConflict, "multiple ElasticIPAttachments reference this ElasticIP"); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *ElasticIPReconciler) resolveAddress(ctx context.Context, resource *juneauv1alpha1.ElasticIP) (string, bool, error) {
	if resource.Status.Address != "" {
		return resource.Status.Address, false, nil
	}

	if strings.TrimSpace(resource.Spec.ExternalNetwork) == "" {
		return "", false, &elasticIPReconcileError{
			reason:  elasticIPReasonMissingDependency,
			message: "spec.externalNetwork is empty",
		}
	}

	var externalNetwork juneauv1alpha1.ExternalNetwork
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.ExternalNetwork}, &externalNetwork); err != nil {
		if errors.IsNotFound(err) {
			return "", false, &elasticIPReconcileError{
				reason:  elasticIPReasonMissingDependency,
				message: fmt.Sprintf("ExternalNetwork %q not found", resource.Spec.ExternalNetwork),
			}
		}
		return "", false, err
	}

	if len(externalNetwork.Spec.AddressPools) == 0 {
		return "", false, &elasticIPReconcileError{
			reason:  elasticIPReasonMissingDependency,
			message: fmt.Sprintf("ExternalNetwork %q has no AddressPools", externalNetwork.Name),
		}
	}

	usedAddresses, err := r.listUsedAddressesByExternalNetwork(ctx, externalNetwork.Name, resource.Namespace, resource.Name)
	if err != nil {
		return "", false, err
	}

	for _, poolName := range externalNetwork.Spec.AddressPools {
		poolName = strings.TrimSpace(poolName)
		if poolName == "" {
			continue
		}

		var pool juneauv1alpha1.AddressPool
		if err := r.Get(ctx, client.ObjectKey{Name: poolName}, &pool); err != nil {
			if errors.IsNotFound(err) {
				return "", false, &elasticIPReconcileError{
					reason:  elasticIPReasonMissingDependency,
					message: fmt.Sprintf("AddressPool %q not found", poolName),
				}
			}
			return "", false, err
		}

		if pool.Spec.AdvertiseMode != juneauv1alpha1.AddressPoolAdvertiseModeBGP {
			return "", false, &elasticIPReconcileError{
				reason:  elasticIPReasonInvalidAddressPool,
				message: fmt.Sprintf("AddressPool %q advertiseMode must be bgp", pool.Name),
			}
		}

		for _, addressRange := range pool.Spec.Addresses {
			candidate, found, err := firstFreeAddressInCIDR(addressRange, usedAddresses)
			if err != nil {
				return "", false, &elasticIPReconcileError{
					reason:  elasticIPReasonInvalidAddressPool,
					message: fmt.Sprintf("AddressPool %q has invalid address %q: %v", pool.Name, addressRange, err),
				}
			}
			if found {
				return candidate, false, nil
			}
		}
	}

	return "", true, nil
}

func (r *ElasticIPReconciler) listUsedAddressesByExternalNetwork(ctx context.Context, externalNetworkName, selfNamespace, selfName string) (map[string]struct{}, error) {
	var list juneauv1alpha1.ElasticIPList
	if err := r.List(ctx, &list); err != nil {
		return nil, err
	}

	used := make(map[string]struct{}, len(list.Items))
	for i := range list.Items {
		item := &list.Items[i]
		if item.Spec.ExternalNetwork != externalNetworkName {
			continue
		}
		if item.Name == selfName && item.Namespace == selfNamespace {
			continue
		}
		if item.DeletionTimestamp != nil || item.Status.Address == "" {
			continue
		}
		used[item.Status.Address] = struct{}{}
	}

	return used, nil
}

func (r *ElasticIPReconciler) listActiveAttachments(ctx context.Context, resource *juneauv1alpha1.ElasticIP) ([]juneauv1alpha1.ElasticIPAttachment, error) {
	var attachments juneauv1alpha1.ElasticIPAttachmentList
	if err := r.List(ctx, &attachments, client.InNamespace(resource.Namespace)); err != nil {
		return nil, err
	}

	active := make([]juneauv1alpha1.ElasticIPAttachment, 0, len(attachments.Items))
	for i := range attachments.Items {
		attachment := attachments.Items[i]
		if attachment.Spec.ElasticIPRef.Name != resource.Name {
			continue
		}
		if attachment.DeletionTimestamp != nil {
			continue
		}
		active = append(active, attachment)
	}

	return active, nil
}

func (r *ElasticIPReconciler) updateErrorStatus(ctx context.Context, resource *juneauv1alpha1.ElasticIP, reason, message string) error {
	return r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhaseError, resource.Status.Address, "",
		metav1.Condition{
			Type:    elasticIPConditionAllocated,
			Status:  metav1.ConditionFalse,
			Reason:  reason,
			Message: message,
		},
		metav1.Condition{
			Type:    elasticIPConditionAttached,
			Status:  metav1.ConditionFalse,
			Reason:  reason,
			Message: message,
		},
	)
}

func (r *ElasticIPReconciler) updateStatus(
	ctx context.Context,
	resource *juneauv1alpha1.ElasticIP,
	phase juneauv1alpha1.ElasticIPPhase,
	address string,
	attachmentName string,
	conditions ...metav1.Condition,
) error {
	updated := resource.Status
	updated.ObservedGeneration = resource.Generation
	updated.Phase = phase
	updated.Address = address
	updated.AttachmentName = attachmentName

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

// SetupWithManager sets up the controller with the Manager.
func (r *ElasticIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.ElasticIP{},
		"spec.externalNetwork",
		func(obj client.Object) []string {
			resource := obj.(*juneauv1alpha1.ElasticIP)
			if resource.Spec.ExternalNetwork == "" {
				return nil
			}
			return []string{resource.Spec.ExternalNetwork}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for ElasticIP.spec.externalNetwork: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.ElasticIP{}).
		Watches(
			&juneauv1alpha1.ElasticIPAttachment{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
				attachment, ok := obj.(*juneauv1alpha1.ElasticIPAttachment)
				if !ok {
					return nil
				}

				elasticIPName := strings.TrimSpace(attachment.Spec.ElasticIPRef.Name)
				if elasticIPName == "" {
					return nil
				}

				return []reconcile.Request{{
					NamespacedName: client.ObjectKey{Namespace: attachment.Namespace, Name: elasticIPName},
				}}
			}),
		).
		Named("elasticip").
		Complete(r)
}

func firstFreeAddressInCIDR(raw string, used map[string]struct{}) (string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, nil
	}

	start, ipnet, err := net.ParseCIDR(raw)
	if err != nil {
		return "", false, fmt.Errorf("invalid CIDR")
	}

	start = start.To4()
	if start == nil {
		return "", false, fmt.Errorf("only IPv4 CIDR is supported")
	}

	prefixLen, bits := ipnet.Mask.Size()
	if bits != 32 {
		return "", false, fmt.Errorf("only IPv4 CIDR is supported")
	}

	ip := append(net.IP(nil), start...)
	broadcast := broadcastIP(ipnet).To4()

	if prefixLen < 31 {
		incIP(&ip)
	}

	for {
		if prefixLen < 31 && ip.Equal(broadcast) {
			return "", false, nil
		}

		candidate := ip.String()
		if _, exists := used[candidate]; !exists {
			return candidate, true, nil
		}

		if ip.Equal(broadcast) {
			return "", false, nil
		}

		incIP(&ip)
	}
}
