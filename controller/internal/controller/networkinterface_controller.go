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
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	conditionReasonAllocationFailed    = "AllocationFailed"
	conditionReasonSubnetNotFound      = "SubnetNotFound"
	conditionReasonInvalidSubnetCIDR   = "InvalidSubnetCIDR"
	conditionReasonWaitingForIface     = "WaitingForInterface"
	conditionReasonAllocationSucceeded = "AllocationSucceeded"
	conditionReasonInvalidRequestedIP  = "InvalidRequestedIP"
	conditionReasonRequestedIPInUse    = "RequestedIPInUse"
	conditionReasonSubnetExhausted     = "SubnetExhausted"
	conditionReasonDeleting            = "Deleting"
)

// NetworkInterfaceReconciler reconciles a NetworkInterface object
type NetworkInterfaceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkinterfaces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkinterfaces/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkinterfaces/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NetworkInterfaceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	finalizer := "networkinterface.juneau.loutres.me/finalizer"
	logger := log.FromContext(ctx)

	var resource juneauv1alpha1.NetworkInterface
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get NetworkInterface", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if done, err := r.handleDeletion(ctx, &resource, finalizer); done || err != nil {
		return ctrl.Result{}, err
	}

	if err := r.ensureFinalizer(ctx, &resource, finalizer); err != nil {
		return ctrl.Result{}, err
	}

	subnet, err := r.fetchSubnet(ctx, &resource)
	if err != nil {
		return ctrl.Result{}, err
	}
	if subnet == nil {
		return ctrl.Result{Requeue: true}, nil
	}

	_, cidr, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		if err := r.updateAllocationFailureStatus(ctx, &resource, conditionReasonInvalidSubnetCIDR, err.Error()); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if done, err := r.reuseExistingLease(ctx, logger, &resource, subnet, cidr); done || err != nil {
		return ctrl.Result{}, err
	}

	if done, err := r.allocateRequestedIP(ctx, logger, &resource, subnet, cidr); done || err != nil {
		return ctrl.Result{}, err
	}

	return r.allocateNextAvailableIP(ctx, logger, &resource, subnet, cidr)
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkInterfaceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.NetworkInterface{}).
		Owns(&juneauv1alpha1.NetworkEndpoint{}).
		Named("networkinterface").
		Complete(r)
}

func (r *NetworkInterfaceReconciler) handleDeletion(ctx context.Context, resource *juneauv1alpha1.NetworkInterface, finalizer string) (bool, error) {
	if resource.ObjectMeta.DeletionTimestamp.IsZero() {
		return false, nil
	}

	if err := r.updateStatus(ctx, resource, juneauv1alpha1.NetworkInterfacePhasePending,
		metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusReady,
			Status:  metav1.ConditionFalse,
			Reason:  conditionReasonDeleting,
			Message: "NetworkInterface is being deleted",
		},
		metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusAllocated,
			Status:  metav1.ConditionFalse,
			Reason:  conditionReasonDeleting,
			Message: "NetworkInterface is being deleted",
		},
	); err != nil {
		return true, err
	}

	if controllerutil.ContainsFinalizer(resource, finalizer) {
		var ipLease juneauv1alpha1.IPLease
		if err := r.Get(ctx, client.ObjectKey{Name: resource.Status.IPLease}, &ipLease); err == nil {
			ipLease.Spec.OwnerDeletionTimeStamp = &metav1.Time{Time: time.Now()}
			if err := r.Update(ctx, &ipLease); err != nil {
				return true, err
			}
		} else if !errors.IsNotFound(err) {
			return true, err
		}

		controllerutil.RemoveFinalizer(resource, finalizer)
		if err := r.Update(ctx, resource); err != nil {
			return true, err
		}
	}

	return true, nil
}

func (r *NetworkInterfaceReconciler) ensureFinalizer(ctx context.Context, resource *juneauv1alpha1.NetworkInterface, finalizer string) error {
	if controllerutil.ContainsFinalizer(resource, finalizer) {
		return nil
	}

	controllerutil.AddFinalizer(resource, finalizer)
	return r.Update(ctx, resource)
}

func (r *NetworkInterfaceReconciler) fetchSubnet(ctx context.Context, resource *juneauv1alpha1.NetworkInterface) (*juneauv1alpha1.Subnet, error) {
	var subnet juneauv1alpha1.Subnet
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.Subnet}, &subnet); err != nil {
		if errors.IsNotFound(err) {
			if err := r.updateStatus(ctx, resource, juneauv1alpha1.NetworkInterfacePhasePending,
				metav1.Condition{
					Type:    juneauv1alpha1.NetworkInterfaceStatusReady,
					Status:  metav1.ConditionFalse,
					Reason:  conditionReasonAllocationFailed,
					Message: "Failed to allocate IP",
				},
				metav1.Condition{
					Type:    juneauv1alpha1.NetworkInterfaceStatusAllocated,
					Status:  metav1.ConditionFalse,
					Reason:  conditionReasonSubnetNotFound,
					Message: err.Error(),
				},
			); err != nil {
				return nil, err
			}
			return nil, nil
		}

		_ = r.updateAllocationFailureStatus(ctx, resource, conditionReasonSubnetNotFound, err.Error())
		return nil, err
	}

	return &subnet, nil
}

func (r *NetworkInterfaceReconciler) reuseExistingLease(ctx context.Context, logger logr.Logger, resource *juneauv1alpha1.NetworkInterface, subnet *juneauv1alpha1.Subnet, cidr *net.IPNet) (bool, error) {
	var ipLeases juneauv1alpha1.IPLeaseList
	if err := r.List(ctx, &ipLeases, client.MatchingFields{
		"spec.subnet":           resource.Spec.Subnet,
		"spec.podRef.namespace": resource.Namespace,
		"spec.podRef.name":      resource.Spec.PodRef.Name,
		"spec.podRef.interface": resource.Spec.PodRef.Interface,
	}); err != nil {
		logger.Error(err, "unable to list IPLeases for NetworkInterface", "name", resource.Name)
		_ = r.updateAllocationFailureStatus(ctx, resource, conditionReasonAllocationFailed, err.Error())
		return false, err
	}

	if len(ipLeases.Items) == 0 {
		return false, nil
	}

	ipLease := ipLeases.Items[0]
	if ipLease.Spec.OwnerDeletionTimeStamp != nil {
		ipLease.Spec.OwnerDeletionTimeStamp = nil
		if err := r.Update(ctx, &ipLease); err != nil {
			return true, err
		}
	}

	if err := r.updateAllocatedStatus(ctx, resource, ipLease.Name, &net.IPNet{IP: net.ParseIP(ipLease.Spec.Address), Mask: cidr.Mask}, subnet.Status.Gateway); err != nil {
		return true, err
	}

	return true, nil
}

func (r *NetworkInterfaceReconciler) allocateRequestedIP(
	ctx context.Context,
	logger logr.Logger,
	resource *juneauv1alpha1.NetworkInterface,
	subnet *juneauv1alpha1.Subnet,
	cidr *net.IPNet,
) (bool, error) {
	if resource.Spec.Address == "" {
		return false, nil
	}

	requestedIP := net.ParseIP(resource.Spec.Address)
	if requestedIP == nil || requestedIP.To4() == nil || !cidr.Contains(requestedIP) {
		if err := r.updateAllocationFailureStatus(ctx, resource, conditionReasonInvalidRequestedIP, "Requested IP is not a valid IPv4 address in subnet"); err != nil {
			return true, err
		}
		return true, nil
	}

	var requestedLeases juneauv1alpha1.IPLeaseList
	if err := r.List(ctx, &requestedLeases, client.MatchingFields{
		"spec.subnet":  resource.Spec.Subnet,
		"spec.address": requestedIP.String(),
	}); err != nil {
		logger.Error(err, "unable to list IPLeases for requested IP", "address", requestedIP.String())
		_ = r.updateAllocationFailureStatus(ctx, resource, conditionReasonAllocationFailed, err.Error())
		return true, err
	}

	if len(requestedLeases.Items) > 0 {
		if err := r.updateAllocationFailureStatus(ctx, resource, conditionReasonRequestedIPInUse, "Requested IP already allocated: "+requestedIP.String()); err != nil {
			return true, err
		}
		return true, nil
	}

	ipLease := r.buildIPLease(resource, subnet, requestedIP.String())
	if err := r.Create(ctx, &ipLease); err != nil {
		logger.Error(err, "unable to create IPLease for NetworkInterface", "name", resource.Name)
		_ = r.updateAllocationFailureStatus(ctx, resource, conditionReasonAllocationFailed, err.Error())
		return true, err
	}

	if err := r.updateAllocatedStatus(ctx, resource, ipLease.Name, &net.IPNet{IP: requestedIP, Mask: cidr.Mask}, subnet.Status.Gateway); err != nil {
		return true, err
	}

	return true, nil
}

func (r *NetworkInterfaceReconciler) allocateNextAvailableIP(
	ctx context.Context,
	logger logr.Logger,
	resource *juneauv1alpha1.NetworkInterface,
	subnet *juneauv1alpha1.Subnet,
	cidr *net.IPNet,
) (ctrl.Result, error) {
	ip := cidr.IP.Mask(cidr.Mask).To4()
	broadcast := broadcastIP(cidr)

	incIP(&ip)
	incIP(&ip)
	incIP(&ip)
	incIP(&ip)

	for {
		if ip.Equal(broadcast) {
			if err := r.updateAllocationFailureStatus(ctx, resource, conditionReasonSubnetExhausted, "No available IPs in subnet"); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}

		var ipLeases juneauv1alpha1.IPLeaseList
		if err := r.List(ctx, &ipLeases, client.MatchingFields{
			"spec.subnet":  resource.Spec.Subnet,
			"spec.address": ip.String(),
		}); err != nil {
			logger.Error(err, "unable to list IPLeases for IP", "address", ip.String())
			_ = r.updateAllocationFailureStatus(ctx, resource, conditionReasonAllocationFailed, err.Error())
			return ctrl.Result{}, err
		}

		if len(ipLeases.Items) > 0 {
			incIP(&ip)
			continue
		}

		ipLease := r.buildIPLease(resource, subnet, ip.String())
		if err := r.Create(ctx, &ipLease); err != nil {
			logger.Error(err, "unable to create IPLease for NetworkInterface", "name", resource.Name)
			_ = r.updateAllocationFailureStatus(ctx, resource, conditionReasonAllocationFailed, err.Error())
			return ctrl.Result{}, err
		}

		if err := r.updateAllocatedStatus(ctx, resource, ipLease.Name, &net.IPNet{IP: ip, Mask: cidr.Mask}, subnet.Status.Gateway); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
}

func (r *NetworkInterfaceReconciler) buildIPLease(resource *juneauv1alpha1.NetworkInterface, subnet *juneauv1alpha1.Subnet, address string) juneauv1alpha1.IPLease {
	return juneauv1alpha1.IPLease{
		ObjectMeta: metav1.ObjectMeta{
			Name: resource.Spec.Subnet + "-" + strings.ReplaceAll(address, ".", "-"),
		},
		Spec: juneauv1alpha1.IPLeaseSpec{
			PodRef: juneauv1alpha1.IPLeasePodReference{
				Namespace: resource.Namespace,
				Name:      resource.Spec.PodRef.Name,
				Interface: resource.Spec.PodRef.Interface,
			},

			Vpc:     subnet.Spec.Vpc,
			Subnet:  resource.Spec.Subnet,
			Address: address,
		},
	}
}

func (r *NetworkInterfaceReconciler) updateAllocatedStatus(ctx context.Context, resource *juneauv1alpha1.NetworkInterface, ipLeaseName string, address *net.IPNet, gateway string) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.IPLease = ipLeaseName
	updated.Status.Address = address.String()
	updated.Status.Routes = buildDefaultRoutes(gateway)
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:               juneauv1alpha1.NetworkInterfaceStatusAllocated,
		Status:             metav1.ConditionTrue,
		Reason:             conditionReasonAllocationSucceeded,
		Message:            "IP allocated successfully: " + address.String(),
		ObservedGeneration: updated.Generation,
	})

	var nwepList juneauv1alpha1.NetworkEndpointList
	if err := r.List(ctx, &nwepList, client.InNamespace(resource.Namespace), client.MatchingFields{
		"spec.podRef.interface": resource.Spec.PodRef.Interface,
		"spec.podRef.name":      resource.Spec.PodRef.Name,
		"spec.podRef.uid":       resource.Spec.PodRef.UID,
	}); err != nil {
		_ = r.updateStatus(ctx, resource, juneauv1alpha1.NetworkInterfacePhaseAllocated,
			metav1.Condition{
				Type:               juneauv1alpha1.NetworkInterfaceStatusAllocated,
				Status:             metav1.ConditionTrue,
				Reason:             conditionReasonAllocationSucceeded,
				Message:            "IP allocated successfully: " + address.String(),
				ObservedGeneration: resource.Generation,
			},
			metav1.Condition{
				Type:               juneauv1alpha1.NetworkInterfaceStatusReady,
				Status:             metav1.ConditionFalse,
				Reason:             conditionReasonAllocationFailed,
				Message:            err.Error(),
				ObservedGeneration: resource.Generation,
			},
		)
		return err
	}

	if len(nwepList.Items) > 0 {
		updated.Status.Phase = juneauv1alpha1.NetworkInterfacePhaseReady
		meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
			Type:               juneauv1alpha1.NetworkInterfaceStatusReady,
			Status:             metav1.ConditionTrue,
			Reason:             conditionReasonWaitingForIface,
			Message:            "Interface is ready",
			ObservedGeneration: updated.Generation,
		})
	} else {
		updated.Status.Phase = juneauv1alpha1.NetworkInterfacePhaseAllocated
		meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
			Type:               juneauv1alpha1.NetworkInterfaceStatusReady,
			Status:             metav1.ConditionFalse,
			Reason:             conditionReasonWaitingForIface,
			Message:            "Waiting for interface",
			ObservedGeneration: updated.Generation,
		})
	}

	return r.commitStatus(ctx, resource, updated.Status)
}

func buildDefaultRoutes(gateway string) []juneauv1alpha1.NetworkRoute {
	if gateway == "" {
		return nil
	}
	return []juneauv1alpha1.NetworkRoute{
		{
			Dst: "0.0.0.0/0",
			GW:  gateway,
		},
	}
}

func (r *NetworkInterfaceReconciler) updateStatus(
	ctx context.Context,
	resource *juneauv1alpha1.NetworkInterface,
	phase juneauv1alpha1.NetworkInterfacePhase,
	conditions ...metav1.Condition,
) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.Phase = phase
	for _, condition := range conditions {
		condition.ObservedGeneration = updated.Generation
		meta.SetStatusCondition(&updated.Status.Conditions, condition)
	}
	return r.commitStatus(ctx, resource, updated.Status)
}

func (r *NetworkInterfaceReconciler) updateAllocationFailureStatus(ctx context.Context, resource *juneauv1alpha1.NetworkInterface, allocatedReason, allocatedMessage string) error {
	return r.updateStatus(ctx, resource, juneauv1alpha1.NetworkInterfacePhaseFailed,
		metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusReady,
			Status:  metav1.ConditionFalse,
			Reason:  conditionReasonAllocationFailed,
			Message: "Failed to allocate IP",
		},
		metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusAllocated,
			Status:  metav1.ConditionFalse,
			Reason:  allocatedReason,
			Message: allocatedMessage,
		},
	)
}

func (r *NetworkInterfaceReconciler) commitStatus(ctx context.Context, resource *juneauv1alpha1.NetworkInterface, status juneauv1alpha1.NetworkInterfaceStatus) error {
	if resource.Status.ObservedGeneration == status.ObservedGeneration &&
		resource.Status.Phase == status.Phase &&
		resource.Status.IPLease == status.IPLease &&
		resource.Status.Address == status.Address &&
		reflect.DeepEqual(resource.Status.Routes, status.Routes) &&
		reflect.DeepEqual(resource.Status.Conditions, status.Conditions) {
		return nil
	}

	resource.Status = status
	return r.Status().Update(ctx, resource)
}

func broadcastIP(n *net.IPNet) net.IP {
	ip := append(net.IP(nil), n.IP...)
	mask := n.Mask
	for i := range ip {
		ip[i] |= ^mask[i]
	}
	return ip
}

func incIP(ip *net.IP) {
	for i := len(*ip) - 1; i >= 0; i-- {
		(*ip)[i]++
		if (*ip)[i] != 0 {
			break
		}
	}
}
