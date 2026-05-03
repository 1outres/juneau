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

	// serviceNATAttachmentSubnet anchors every per-Node SNAT IP into the
	// default Subnet's L2 segment. Using a constant keeps the address
	// space and route reachability symmetric across all Nodes.
	serviceNATAttachmentSubnet = JuneauNodeDefaultSubnet

	serviceNATAttachmentAttribute = "serviceNATAttachment.assignedIP"

	serviceNATAttachmentRequeueAfter = 10 * time.Second

	// serviceNATEndpointSuffix is the suffix appended to the Node name
	// when forming the derived NetworkEndpoint name. Suffixing keeps the
	// name distinct from the per-Node juneau_node NetworkEndpoint, which
	// is keyed by the Node name itself.
	serviceNATEndpointSuffix = ".servicenat"
)

// ServiceNATAttachmentReconciler reconciles ServiceNATAttachment resources.
//
// For each attachment the reconciler ensures:
//
//  1. an AllocationClaim against the default Subnet's IP pool, claiming a
//     /32 to use as the per-Node SNAT source IP for shared-Service flows;
//  2. a derived NetworkEndpoint of kind=ServiceNAT in the default Subnet
//     so the data plane's arp/fdb reconcilers route reply traffic back to
//     the originating Node;
//  3. status.assignedIP / assignedMAC and the Ready condition mirroring
//     the underlying claim and NetworkEndpoint state.
type ServiceNATAttachmentReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// EndpointNamespace is the namespace used for derived NetworkEndpoint
	// resources. NetworkEndpoint is namespaced and cannot reference a
	// cluster-scoped owner directly, so the namespace must match the
	// daemon's pod-namespace flag for the per-Node endpoint to be picked
	// up by the daemon-side reconcilers.
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
		// automatically. NetworkEndpoint is namespace-scoped and cannot
		// declare a cluster-scoped owner, so it is removed explicitly.
		if err := r.deleteEndpoint(ctx, &resource); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	address, requeue, err := r.ensureClaim(ctx, &resource)
	if err != nil {
		return ctrl.Result{}, err
	}
	if requeue {
		if err := r.updatePendingStatus(ctx, &resource, "", "", serviceNATAttachmentReasonNoAddress, "no available address in default Subnet IP pool"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: serviceNATAttachmentRequeueAfter}, nil
	}
	if address == "" {
		if err := r.updatePendingStatus(ctx, &resource, "", "", serviceNATAttachmentReasonAllocating, "AllocationClaim is still allocating an address"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	mac, err := serviceNATMAC(address)
	if err != nil {
		if updateErr := r.updateErrorStatus(ctx, &resource, serviceNATAttachmentReasonReconcileFailed, err.Error()); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	if err := r.ensureEndpoint(ctx, &resource, address, mac); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.updateReadyStatus(ctx, &resource, address, mac); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *ServiceNATAttachmentReconciler) ensureClaim(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment) (string, bool, error) {
	gvk := schema.GroupVersionKind{
		Group:   juneauv1alpha1.GroupVersion.Group,
		Version: juneauv1alpha1.GroupVersion.Version,
		Kind:    "ServiceNATAttachment",
	}
	poolName := SubnetIPAllocationPoolName(serviceNATAttachmentSubnet)
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
		// Pool is exhausted. Ask the controller to retry on a backoff so
		// the user sees an explicit signal rather than a silent stall.
		return "", true, nil
	}

	return "", false, nil
}

func (r *ServiceNATAttachmentReconciler) ensureEndpoint(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment, address, mac string) error {
	if r.EndpointNamespace == "" {
		return stderrors.New("ServiceNATAttachmentReconciler.EndpointNamespace must be set")
	}

	cidr, err := r.serviceNATEndpointAddress(ctx, address)
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
				Subnet:     serviceNATAttachmentSubnet,
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

// serviceNATEndpointAddress combines the assigned /32 with the default
// Subnet's prefix length so the data plane can install a connected route
// covering the SNAT IP within the Subnet's L2 segment.
func (r *ServiceNATAttachmentReconciler) serviceNATEndpointAddress(ctx context.Context, address string) (string, error) {
	var subnet juneauv1alpha1.Subnet
	if err := r.Get(ctx, client.ObjectKey{Name: serviceNATAttachmentSubnet}, &subnet); err != nil {
		return "", fmt.Errorf("get default Subnet: %w", err)
	}

	_, cidr, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		return "", fmt.Errorf("parse default Subnet CIDR %q: %w", subnet.Spec.CIDR, err)
	}
	prefixLen, _ := cidr.Mask.Size()

	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("assigned address %q is not a valid IPv4", address)
	}
	return fmt.Sprintf("%s/%d", ip.String(), prefixLen), nil
}

func (r *ServiceNATAttachmentReconciler) updateReadyStatus(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment, address, mac string) error {
	return r.commitStatus(ctx, resource, address, mac, metav1.Condition{
		Type:    juneauv1alpha1.ServiceNATAttachmentStatusReady,
		Status:  metav1.ConditionTrue,
		Reason:  serviceNATAttachmentReasonReady,
		Message: "Service NAT attachment is ready",
	})
}

func (r *ServiceNATAttachmentReconciler) updatePendingStatus(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment, address, mac, reason, message string) error {
	return r.commitStatus(ctx, resource, address, mac, metav1.Condition{
		Type:    juneauv1alpha1.ServiceNATAttachmentStatusReady,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	})
}

func (r *ServiceNATAttachmentReconciler) updateErrorStatus(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment, reason, message string) error {
	// Preserve any previously assigned IP/MAC on the resource so the
	// transient error doesn't blank them out.
	return r.commitStatus(ctx, resource, resource.Status.AssignedIP, resource.Status.AssignedMAC, metav1.Condition{
		Type:    juneauv1alpha1.ServiceNATAttachmentStatusReady,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	})
}

func (r *ServiceNATAttachmentReconciler) commitStatus(ctx context.Context, resource *juneauv1alpha1.ServiceNATAttachment, address, mac string, condition metav1.Condition) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.AssignedIP = address
	updated.Status.AssignedMAC = mac
	condition.ObservedGeneration = updated.Generation
	meta.SetStatusCondition(&updated.Status.Conditions, condition)

	if updated.Status.ObservedGeneration == resource.Status.ObservedGeneration &&
		updated.Status.AssignedIP == resource.Status.AssignedIP &&
		updated.Status.AssignedMAC == resource.Status.AssignedMAC &&
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

// serviceNATEndpointName returns the deterministic NetworkEndpoint name
// for the SNAT endpoint backing the given attachment. The Node name is
// already used for the juneau_node endpoint, so we suffix to disambiguate.
func serviceNATEndpointName(attachmentName string) string {
	return attachmentName + serviceNATEndpointSuffix
}

// serviceNATMAC derives a stable MAC for the per-Node SNAT IP. The MAC
// is in the IPv4-multicast LAA range (02:xx:xx:xx:xx:xx with the lower
// 4 octets taken from the IP), the same convention used elsewhere in
// the codebase for synthetic gateway / endpoint MACs.
func serviceNATMAC(address string) (string, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return "", fmt.Errorf("invalid address %q", address)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("address %q is not IPv4", address)
	}
	return fmt.Sprintf("02:00:%02x:%02x:%02x:%02x", ip4[0], ip4[1], ip4[2], ip4[3]), nil
}
