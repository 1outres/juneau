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
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	serviceNATAttachmentReasonReady             = "Ready"
	serviceNATAttachmentReasonAllocating        = "Allocating"
	serviceNATAttachmentReasonNoAddress         = "NoAddressAvailable"
	serviceNATAttachmentReasonMissingDependency = "MissingDependency"
	serviceNATAttachmentReasonReconcileFailed   = "ReconcileFailed"

	serviceNATAttachmentAttribute = "serviceNATAttachment.assignedIP"

	serviceNATAttachmentRequeueAfter = 10 * time.Second

	// serviceNATEndpointSuffix is the suffix appended to the
	// attachment name when forming the derived NetworkEndpoint name.
	// The juneau_node Node-kind endpoint already uses the Node name
	// directly, so we suffix to disambiguate.
	serviceNATEndpointSuffix = ".servicenat"

	// serviceNATAttachmentNameSeparator joins the Node and Vpc parts
	// of a ServiceNATAttachment's metadata.name. Mirrored by the
	// webhook so the two stay in lockstep.
	serviceNATAttachmentNameSeparator = "."
)

// ServiceNATAttachmentReconciler reconciles ServiceNATAttachment resources.
//
// For each attachment the reconciler ensures:
//
//  1. an AllocationClaim against the provider Vpc's NAT-source Subnet
//     IP pool (Vpc.Spec.Service.Provider.NATSourceSubnet), claiming a
//     /32 to use as the per-Node SNAT source IP for shared-Service
//     flows owned by that Vpc;
//  2. a derived NetworkEndpoint of kind=ServiceNAT in the same Subnet
//     so the data plane's arp/fdb reconcilers route reply traffic
//     back to the originating Node;
//  3. status.assignedIP / assignedMAC / subnet and the Ready condition
//     mirroring the underlying claim and NetworkEndpoint state.
type ServiceNATAttachmentReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// EndpointNamespace is the namespace used for derived
	// NetworkEndpoint resources. NetworkEndpoint is namespaced and
	// cannot reference a cluster-scoped owner directly, so the
	// namespace must match the daemon's pod-namespace flag for the
	// per-Node endpoint to be picked up by the daemon-side
	// reconcilers.
	EndpointNamespace string
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=servicenatattachments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=servicenatattachments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=servicenatattachments/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkendpoints,verbs=get;list;watch;create;update;patch;delete

func (r *ServiceNATAttachmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauv1alpha1.ServiceNATAttachment
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get ServiceNATAttachment", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		// AllocationClaim is owned by this attachment and gets GC'd
		// automatically. NetworkEndpoint is namespace-scoped and
		// cannot declare a cluster-scoped owner, so it is removed
		// explicitly.
		if err := r.deleteEndpoint(ctx, &resource); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	subnetName, requeue, err := r.resolveProviderSubnet(ctx, &resource)
	if err != nil {
		return ctrl.Result{}, err
	}
	if subnetName == "" {
		// Provider Vpc is missing or no longer configured as a
		// provider. Tear down the endpoint and requeue so the
		// attachment is cleaned up shortly after the Vpc reconciler
		// removes it.
		if err := r.deleteEndpoint(ctx, &resource); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.commitStatus(ctx, &resource, "", "", "", metav1.Condition{
			Type:    juneauv1alpha1.ServiceNATAttachmentStatusReady,
			Status:  metav1.ConditionFalse,
			Reason:  serviceNATAttachmentReasonMissingDependency,
			Message: fmt.Sprintf("provider Vpc %q has no spec.service.provider.natSourceSubnet", resource.Spec.Vpc),
		}); err != nil {
			return ctrl.Result{}, err
		}
		if requeue {
			return ctrl.Result{RequeueAfter: serviceNATAttachmentRequeueAfter}, nil
		}
		return ctrl.Result{}, nil
	}

	address, exhausted, err := r.ensureClaim(ctx, &resource, subnetName)
	if err != nil {
		return ctrl.Result{}, err
	}
	if exhausted {
		if err := r.updatePendingStatus(ctx, &resource, "", "", subnetName, serviceNATAttachmentReasonNoAddress, fmt.Sprintf("no available address in Subnet %q IP pool", subnetName)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: serviceNATAttachmentRequeueAfter}, nil
	}
	if address == "" {
		if err := r.updatePendingStatus(ctx, &resource, "", "", subnetName, serviceNATAttachmentReasonAllocating, "AllocationClaim is still allocating an address"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	mac, err := endpointMAC(net.ParseIP(address))
	if err != nil {
		message := fmt.Errorf("assigned address %q: %w", address, err).Error()
		if updateErr := r.updateErrorStatus(ctx, &resource, subnetName, serviceNATAttachmentReasonReconcileFailed, message); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	if err := r.ensureEndpoint(ctx, &resource, subnetName, address, mac); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.updateReadyStatus(ctx, &resource, subnetName, address, mac); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// resolveProviderSubnet looks up the provider Vpc that backs this
// attachment and returns the configured NAT source Subnet name. The
// second return value is true when the caller should requeue (e.g.
// the Vpc has not yet been reconciled). subnetName is empty when the
// Vpc is missing or no longer opts in to the provider role.
func (r *ServiceNATAttachmentReconciler) resolveProviderSubnet(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment) (string, bool, error) {
	if resource.Spec.Vpc == "" {
		return "", false, nil
	}
	var vpc juneauv1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			return "", true, nil
		}
		return "", false, fmt.Errorf("get provider Vpc %q: %w", resource.Spec.Vpc, err)
	}
	return vpc.Spec.Service.ProviderSubnet(), false, nil
}

func (r *ServiceNATAttachmentReconciler) ensureClaim(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment, subnetName string) (string, bool, error) {
	gvk := schema.GroupVersionKind{
		Group:   juneauv1alpha1.GroupVersion.Group,
		Version: juneauv1alpha1.GroupVersion.Version,
		Kind:    "ServiceNATAttachment",
	}
	poolName := SubnetIPAllocationPoolName(subnetName)
	desired := newAllocationClaim(poolName, gvk, "", resource.Name, serviceNATAttachmentAttribute)

	claim := &juneauv1alpha1.AllocationClaim{ObjectMeta: metav1.ObjectMeta{Name: desired.Name}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, claim, func() error {
		claim.Spec = desired.Spec
		return controllerutil.SetControllerReference(resource, claim, r.Scheme)
	}); err != nil {
		return "", false, fmt.Errorf("ensure AllocationClaim %q: %w", desired.Name, err)
	}

	if claim.Status.Phase == juneauv1alpha1.AllocationClaimPhaseAllocated && claim.Status.Value.IP != "" {
		return claim.Status.Value.IP, false, nil
	}

	ready := meta.FindStatusCondition(claim.Status.Conditions, juneauv1alpha1.AllocationClaimStatusReady)
	if ready != nil && ready.Reason == allocationClaimReasonPending {
		// Pool is exhausted. Ask the controller to retry on a backoff
		// so the user sees an explicit signal rather than a silent
		// stall.
		return "", true, nil
	}

	return "", false, nil
}

func (r *ServiceNATAttachmentReconciler) ensureEndpoint(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment, subnetName, address, mac string) error {
	if r.EndpointNamespace == "" {
		return stderrors.New("ServiceNATAttachmentReconciler.EndpointNamespace must be set")
	}

	cidr, err := r.serviceNATEndpointAddress(ctx, subnetName, address)
	if err != nil {
		return err
	}

	endpointName := serviceNATEndpointName(resource.Name)
	endpoint := &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      endpointName,
			Namespace: r.EndpointNamespace,
		},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, endpoint, func() error {
		// NetworkEndpoint webhook makes the identity fields immutable, so
		// only set them on first creation. Updates after that point are
		// no-ops at the spec level.
		if endpoint.UID == "" {
			endpoint.Spec = juneauv1alpha1.NetworkEndpointSpec{
				Kind:       juneauv1alpha1.EndpointKindServiceNAT,
				NodeName:   resource.Spec.NodeName,
				Subnet:     subnetName,
				Address:    cidr,
				MACAddress: mac,
			}
		}
		// NetworkEndpoint is namespace-scoped and cannot declare a
		// cluster-scoped owner. We drop the OwnerReference and rely on
		// the deletion path of this reconciler to clean it up.
		return nil
	}); err != nil {
		return fmt.Errorf("ensure NetworkEndpoint %q: %w", endpointName, err)
	}

	return nil
}

func (r *ServiceNATAttachmentReconciler) deleteEndpoint(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment) error {
	if r.EndpointNamespace == "" {
		return nil
	}
	endpoint := &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceNATEndpointName(resource.Name),
			Namespace: r.EndpointNamespace,
		},
	}
	if err := r.Delete(ctx, endpoint); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("delete NetworkEndpoint %q: %w", endpoint.Name, err)
	}
	return nil
}

// serviceNATEndpointAddress combines the assigned /32 with the
// NAT-source Subnet's prefix length so the data plane can install a
// connected route covering the SNAT IP within the Subnet's L2 segment.
func (r *ServiceNATAttachmentReconciler) serviceNATEndpointAddress(ctx context.Context, subnetName, address string) (string, error) {
	var subnet juneauv1alpha1.Subnet
	if err := r.Get(ctx, client.ObjectKey{Name: subnetName}, &subnet); err != nil {
		return "", fmt.Errorf("get NAT source Subnet %q: %w", subnetName, err)
	}

	_, cidr, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		return "", fmt.Errorf("parse Subnet %q CIDR %q: %w", subnetName, subnet.Spec.CIDR, err)
	}
	prefixLen, _ := cidr.Mask.Size()

	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("assigned address %q is not a valid IPv4", address)
	}
	return fmt.Sprintf("%s/%d", ip.String(), prefixLen), nil
}

func (r *ServiceNATAttachmentReconciler) updateReadyStatus(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment, subnetName, address, mac string) error {
	return r.commitStatus(ctx, resource, address, mac, subnetName, metav1.Condition{
		Type:    juneauv1alpha1.ServiceNATAttachmentStatusReady,
		Status:  metav1.ConditionTrue,
		Reason:  serviceNATAttachmentReasonReady,
		Message: "Service NAT attachment is ready",
	})
}

func (r *ServiceNATAttachmentReconciler) updatePendingStatus(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment, address, mac, subnetName, reason, message string) error {
	return r.commitStatus(ctx, resource, address, mac, subnetName, metav1.Condition{
		Type:    juneauv1alpha1.ServiceNATAttachmentStatusReady,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	})
}

func (r *ServiceNATAttachmentReconciler) updateErrorStatus(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment, subnetName, reason, message string) error {
	// Preserve any previously assigned IP/MAC on the resource so the
	// transient error doesn't blank them out.
	return r.commitStatus(ctx, resource, resource.Status.AssignedIP, resource.Status.AssignedMAC, subnetName, metav1.Condition{
		Type:    juneauv1alpha1.ServiceNATAttachmentStatusReady,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	})
}

func (r *ServiceNATAttachmentReconciler) commitStatus(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment, address, mac, subnetName string, condition metav1.Condition) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.AssignedIP = address
	updated.Status.AssignedMAC = mac
	updated.Status.Subnet = subnetName
	condition.ObservedGeneration = updated.Generation
	meta.SetStatusCondition(&updated.Status.Conditions, condition)

	if updated.Status.ObservedGeneration == resource.Status.ObservedGeneration &&
		updated.Status.AssignedIP == resource.Status.AssignedIP &&
		updated.Status.AssignedMAC == resource.Status.AssignedMAC &&
		updated.Status.Subnet == resource.Status.Subnet &&
		reflect.DeepEqual(updated.Status.Conditions, resource.Status.Conditions) {
		return nil
	}

	resource.Status = updated.Status
	return r.Status().Update(ctx, resource)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ServiceNATAttachmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.ServiceNATAttachment{}).
		Owns(&juneauv1alpha1.AllocationClaim{}).
		Watches(
			&juneauv1alpha1.NetworkEndpoint{},
			handler.EnqueueRequestsFromMapFunc(r.mapEndpointToServiceNATAttachment),
		).
		Watches(
			&juneauv1alpha1.Vpc{},
			handler.EnqueueRequestsFromMapFunc(r.mapVpcToAttachments),
		).
		Named("servicenatattachment").
		Complete(r)
}

func (r *ServiceNATAttachmentReconciler) mapEndpointToServiceNATAttachment(_ context.Context, obj client.Object) []reconcile.Request {
	endpoint, ok := obj.(*juneauv1alpha1.NetworkEndpoint)
	if !ok || endpoint.Spec.Kind != juneauv1alpha1.EndpointKindServiceNAT {
		return nil
	}
	attachmentName := strings.TrimSuffix(endpoint.Name, serviceNATEndpointSuffix)
	if attachmentName == endpoint.Name {
		// Endpoint is not one of ours.
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: attachmentName}}}
}

// mapVpcToAttachments enqueues every ServiceNATAttachment whose
// spec.vpc names the changed Vpc, so a flip of
// spec.service.provider.natSourceSubnet (or removal of the provider
// role) propagates to the attachments without needing an explicit
// notification.
func (r *ServiceNATAttachmentReconciler) mapVpcToAttachments(ctx context.Context, obj client.Object) []reconcile.Request {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil
	}
	var list juneauv1alpha1.ServiceNATAttachmentList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		if list.Items[i].Spec.Vpc == vpc.Name {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Name: list.Items[i].Name}})
		}
	}
	return reqs
}

// serviceNATAttachmentName returns the deterministic
// ServiceNATAttachment metadata.name for a (Node, provider Vpc) pair.
// The webhook validates this concatenation matches metadata.name.
func serviceNATAttachmentName(nodeName, vpcName string) string {
	return nodeName + serviceNATAttachmentNameSeparator + vpcName
}

// serviceNATEndpointName returns the deterministic NetworkEndpoint
// name for the SNAT endpoint backing the given attachment.
func serviceNATEndpointName(attachmentName string) string {
	return attachmentName + serviceNATEndpointSuffix
}
