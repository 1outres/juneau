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
	"strings"
	"time"

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

	if !resource.ObjectMeta.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&resource, finalizer) {

			var ipLease juneauv1alpha1.IPLease
			if err := r.Get(ctx, client.ObjectKey{Name: resource.Status.IPLease}, &ipLease); err == nil {
				ipLease.Spec.OwnerDeletionTimeStamp = metav1.Time{Time: time.Now()}
				if err := r.Update(ctx, &ipLease); err != nil {
					return ctrl.Result{}, err
				}
			} else if !errors.IsNotFound(err) {
				return ctrl.Result{}, err
			}

			controllerutil.RemoveFinalizer(&resource, finalizer)
			err := r.Update(ctx, &resource)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&resource, finalizer) {
		controllerutil.AddFinalizer(&resource, finalizer)
		err := r.Update(ctx, &resource)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	var subnet juneauv1alpha1.Subnet
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.Subnet}, &subnet); err != nil {
		resource.Status.ObservedGeneration = resource.Generation
		resource.Status.Phase = juneauv1alpha1.NetworkInterfacePhasePending
		meta.SetStatusCondition(&resource.Status.Conditions, metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusReady,
			Status:  metav1.ConditionFalse,
			Reason:  "AllocationFailed",
			Message: "Failed to allocate IP",
		})
		meta.SetStatusCondition(&resource.Status.Conditions, metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusAllocated,
			Status:  metav1.ConditionFalse,
			Reason:  "SubnetNotFound",
			Message: err.Error(),
		})
		if err := r.Status().Update(ctx, &resource); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	var ipLeases juneauv1alpha1.IPLeaseList
	if err := r.List(ctx, &ipLeases, client.MatchingFields{
		"spec.subnet":           resource.Spec.Subnet,
		"spec.podRef.namespace": resource.Namespace,
		"spec.podRef.name":      resource.Spec.PodRef.Name,
		"spec.podRef.interface": resource.Spec.PodRef.Interface,
	}); err != nil {
		logger.Error(err, "unable to list IPLeases for NetworkInterface", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if len(ipLeases.Items) > 0 {
		ipLease := ipLeases.Items[0]
		ipLease.Spec.OwnerDeletionTimeStamp = metav1.Time{}
		if err := r.Update(ctx, &ipLease); err != nil {
			return ctrl.Result{}, err
		}
		resource.Status.ObservedGeneration = resource.Generation
		resource.Status.Phase = juneauv1alpha1.NetworkInterfacePhaseAllocated
		resource.Status.IPLease = ipLease.Name
		meta.SetStatusCondition(&resource.Status.Conditions, metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusReady,
			Status:  metav1.ConditionFalse,
			Reason:  "WaitingForInterface",
			Message: "Waiting for interface",
		})
		meta.SetStatusCondition(&resource.Status.Conditions, metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusAllocated,
			Status:  metav1.ConditionTrue,
			Reason:  "AllocationSucceeded",
			Message: "IP already allocated to this interface: " + ipLease.Spec.Address,
		})
		// TODO: set address and routes in status
		if err := r.Status().Update(ctx, &resource); err != nil {
			return ctrl.Result{}, err
		}
	}

	_, cidr, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		resource.Status.ObservedGeneration = resource.Generation
		resource.Status.Phase = juneauv1alpha1.NetworkInterfacePhasePending
		meta.SetStatusCondition(&resource.Status.Conditions, metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusReady,
			Status:  metav1.ConditionFalse,
			Reason:  "AllocationFailed",
			Message: "Failed to allocate IP",
		})
		meta.SetStatusCondition(&resource.Status.Conditions, metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusAllocated,
			Status:  metav1.ConditionFalse,
			Reason:  "InvalidSubnetCIDR",
			Message: err.Error(),
		})
		if err := r.Status().Update(ctx, &resource); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	ip := cidr.IP.Mask(cidr.Mask).To4()

	broadcast := func(n *net.IPNet) net.IP {
		ip := append(net.IP(nil), n.IP...)
		mask := n.Mask
		for i := range ip {
			ip[i] |= ^mask[i]
		}
		return ip
	}(cidr)

	inc := func(ip *net.IP) {
		for i := len(*ip) - 1; i >= 0; i-- {
			(*ip)[i]++
			if (*ip)[i] != 0 {
				break
			}
		}
	}
	inc(&ip)
	inc(&ip)
	inc(&ip)
	inc(&ip)

	for {
		if ip.Equal(broadcast) {
			resource.Status.ObservedGeneration = resource.Generation
			resource.Status.Phase = juneauv1alpha1.NetworkInterfacePhasePending
			meta.SetStatusCondition(&resource.Status.Conditions, metav1.Condition{
				Type:    juneauv1alpha1.NetworkInterfaceStatusReady,
				Status:  metav1.ConditionFalse,
				Reason:  "AllocationFailed",
				Message: "Failed to allocate IP",
			})
			meta.SetStatusCondition(&resource.Status.Conditions, metav1.Condition{
				Type:    juneauv1alpha1.NetworkInterfaceStatusAllocated,
				Status:  metav1.ConditionFalse,
				Reason:  "SubnetExhausted",
				Message: "No available IPs in subnet",
			})
			if err := r.Status().Update(ctx, &resource); err != nil {
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
			return ctrl.Result{}, err
		}

		if len(ipLeases.Items) > 0 {
			inc(&ip)
			continue
		}

		ipLease := juneauv1alpha1.IPLease{
			ObjectMeta: metav1.ObjectMeta{
				Name: resource.Spec.Subnet + "-" + strings.ReplaceAll(ip.String(), ".", "-"),
			},
			Spec: juneauv1alpha1.IPLeaseSpec{
				PodRef: juneauv1alpha1.IPLeasePodReference{
					Namespace: resource.Namespace,
					Name:      resource.Spec.PodRef.Name,
					Interface: resource.Spec.PodRef.Interface,
				},

				Vpc:     subnet.Spec.Vpc,
				Subnet:  resource.Spec.Subnet,
				Address: ip.String(),
			},
		}
		if err := r.Create(ctx, &ipLease); err != nil {
			logger.Error(err, "unable to create IPLease for NetworkInterface", "name", req.NamespacedName)
			return ctrl.Result{}, err
		}

		resource.Status.ObservedGeneration = resource.Generation
		resource.Status.IPLease = ipLease.Name
		resource.Status.Phase = juneauv1alpha1.NetworkInterfacePhaseAllocated
		meta.SetStatusCondition(&resource.Status.Conditions, metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusReady,
			Status:  metav1.ConditionFalse,
			Reason:  "WaitingForInterface",
			Message: "Waiting for interface",
		})
		meta.SetStatusCondition(&resource.Status.Conditions, metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusAllocated,
			Status:  metav1.ConditionTrue,
			Reason:  "AllocationSucceeded",
			Message: "IP allocated successfully: " + ipLease.Spec.Address,
		})
		// TODO: set address and routes in status
		if err := r.Status().Update(ctx, &resource); err != nil {
			return ctrl.Result{}, err
		}
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkInterfaceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.NetworkInterface{}).
		Named("networkinterface").
		Complete(r)
}
