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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// ExternalNetworkReconciler reconciles ExternalNetwork resources.
//
// When at least one NATGateway references this ExternalNetwork, the
// reconciler fans out an ExternalNetworkAttachment per Node × this
// ExternalNetwork (preallocate). The attachments are owned by the
// ExternalNetwork itself so that NATGateway lifecycle does not GC them
// — only deleting the ExternalNetwork drops the attachments.
type ExternalNetworkReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=externalnetworks,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=externalnetworks/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=externalnetworks/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=natgateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=externalnetworkattachments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch

// Reconcile reconciles ExternalNetwork by fanning out
// ExternalNetworkAttachments when needed.
func (r *ExternalNetworkReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var externalNetwork juneauv1alpha1.ExternalNetwork
	if err := r.Get(ctx, req.NamespacedName, &externalNetwork); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get ExternalNetwork", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !externalNetwork.ObjectMeta.DeletionTimestamp.IsZero() {
		// Owned attachments are GC'd by Kubernetes once the
		// ExternalNetwork is removed.
		return ctrl.Result{}, nil
	}

	// Skip fan-out when the ExternalNetwork is not BGP-typed: NAT
	// Gateways only support BGP-mode ExternalNetworks today.
	if externalNetwork.Spec.Type != juneauv1alpha1.ExternalNetworkTypeBGP {
		return ctrl.Result{}, nil
	}

	referenced, err := r.hasReferencingNATGateway(ctx, &externalNetwork)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !referenced {
		return ctrl.Result{}, nil
	}

	var nodeList corev1.NodeList
	if err := r.List(ctx, &nodeList); err != nil {
		return ctrl.Result{}, err
	}

	for i := range nodeList.Items {
		node := &nodeList.Items[i]
		if err := r.ensureAttachment(ctx, &externalNetwork, node.Name); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *ExternalNetworkReconciler) hasReferencingNATGateway(ctx context.Context, externalNetwork *juneauv1alpha1.ExternalNetwork) (bool, error) {
	var natGatewayList juneauv1alpha1.NATGatewayList
	if err := r.List(ctx, &natGatewayList); err != nil {
		return false, err
	}
	for i := range natGatewayList.Items {
		if natGatewayList.Items[i].Spec.ExternalNetwork == externalNetwork.Name {
			return true, nil
		}
	}
	return false, nil
}

func (r *ExternalNetworkReconciler) ensureAttachment(ctx context.Context, externalNetwork *juneauv1alpha1.ExternalNetwork, nodeName string) error {
	name := externalNetworkAttachmentName(externalNetwork.Name, nodeName)
	attachment := &juneauv1alpha1.ExternalNetworkAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, attachment, func() error {
		// Spec is immutable per the webhook, so only set on create
		// (when the resource has no UID yet).
		if attachment.ObjectMeta.UID == "" {
			attachment.Spec = juneauv1alpha1.ExternalNetworkAttachmentSpec{
				ExternalNetwork: externalNetwork.Name,
				NodeName:        nodeName,
			}
		}
		return controllerutil.SetControllerReference(externalNetwork, attachment, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("ensure ExternalNetworkAttachment %q: %w", name, err)
	}
	return nil
}

func externalNetworkAttachmentName(externalNetworkName, nodeName string) string {
	return fmt.Sprintf("%s--%s", externalNetworkName, nodeName)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ExternalNetworkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.ExternalNetwork{}).
		Owns(&juneauv1alpha1.ExternalNetworkAttachment{}).
		Watches(&juneauv1alpha1.NATGateway{}, handler.EnqueueRequestsFromMapFunc(r.mapNATGatewayToExternalNetworks)).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(r.mapNodeToExternalNetworks)).
		Named("externalnetwork").
		Complete(r)
}

func (r *ExternalNetworkReconciler) mapNATGatewayToExternalNetworks(_ context.Context, obj client.Object) []reconcile.Request {
	natGateway, ok := obj.(*juneauv1alpha1.NATGateway)
	if !ok || natGateway.Spec.ExternalNetwork == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: natGateway.Spec.ExternalNetwork}}}
}

func (r *ExternalNetworkReconciler) mapNodeToExternalNetworks(ctx context.Context, _ client.Object) []reconcile.Request {
	var externalNetworkList juneauv1alpha1.ExternalNetworkList
	if err := r.List(ctx, &externalNetworkList); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(externalNetworkList.Items))
	for i := range externalNetworkList.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: externalNetworkList.Items[i].Name}})
	}
	return requests
}
