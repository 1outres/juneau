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
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/internal/pkg/netutil"
)

// AddressReconciler reconciles a Address object
type AddressReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresses/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *AddressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var address juneauv1alpha1.Address
	if err := r.Get(ctx, req.NamespacedName, &address); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get Address", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !address.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if address.Status.LeaseName != "" {
		var subnetLease juneauv1alpha1.SubnetLease
		if err := r.Get(ctx, client.ObjectKey{Name: address.Status.LeaseName}, &subnetLease); err != nil {
			if !errors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("unable to get SubnetLease %s: %w", address.Status.LeaseName, err)
			}
		} else if subnetLease.Spec.Owner.UID == string(address.UID) {
			return ctrl.Result{}, nil
		}

		address.Status.LeaseName = ""
		address.Status.Address = ""
		if err := r.Status().Update(ctx, &address); err != nil {
			return ctrl.Result{}, fmt.Errorf("unable to clear Address %s status after missing SubnetLease %s: %w", address.Name, address.Status.LeaseName, err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	var allocatedAddress string

	if address.Spec.Address != "" {
		leaseName := netutil.LeaseNameFor(address.Spec.Subnet, address.Spec.Address)

		var subnetLease juneauv1alpha1.SubnetLease
		if err := r.Get(ctx, client.ObjectKey{Name: leaseName}, &subnetLease); err != nil {
			if !errors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("unable to get SubnetLease %s: %w", leaseName, err)
			}
		} else {
			// Address is requesting an address that is already leased to another Address.
		  // TODO: Handle AlreadyInUse
		  return ctrl.Result{RequeueAfter: time.Minute}, nil
		}

		allocatedAddress = address.Spec.Address
	} else {
		var subnet juneauv1alpha1.Subnet
		if err := r.Get(ctx, client.ObjectKey{Name: address.Spec.Subnet}, &subnet); err != nil {
			return ctrl.Result{}, fmt.Errorf("unable to get Subnet %s: %w", address.Spec.Subnet, err)
		}

		if subnet.Spec.AllocationStrategy == juneauv1alpha1.SubnetAllocationStrategyFirstFit {
			firstCursor := subnet.Status.NextCursor
			var cursor net.IP = net.ParseIP(firstCursor)

			for ;; {
				leaseName := netutil.LeaseNameFor(address.Spec.Subnet, cursor.String())
				var subnetLease juneauv1alpha1.SubnetLease
				if err := r.Get(ctx, client.ObjectKey{Name: leaseName}, &subnetLease); err != nil {
					if !errors.IsNotFound(err) {
						return ctrl.Result{}, fmt.Errorf("unable to get SubnetLease %s: %w", leaseName, err)
					}
					allocatedAddress = cursor.String()
					break
				}

				var found bool
				var err error
				cursor, found, err = netutil.NextUsableIPv4InSubnet(subnet.Spec.CIDR, cursor)
				if err != nil {
					return ctrl.Result{}, fmt.Errorf("unable to find next usable IP in Subnet %s: %w", subnet.Name, err)
				}
				if !found {
					cursor, err = netutil.NthIPv4InSubnet(subnet.Spec.CIDR, 5)
					if err != nil {
						return ctrl.Result{}, fmt.Errorf("unable to reset cursor for Subnet %s: %w", subnet.Name, err)
					}
				}
				if cursor.String() == firstCursor {
					// TODO: Handle SubnetExhausted
		      return ctrl.Result{RequeueAfter: time.Hour}, nil
				}
			}
		}
	}

	subnetLease := &juneauv1alpha1.SubnetLease{
		ObjectMeta: v1.ObjectMeta{
			Name: netutil.LeaseNameFor(address.Spec.Subnet, allocatedAddress),
		},
		Spec: juneauv1alpha1.SubnetLeaseSpec{
			Subnet: address.Spec.Subnet,
			IP: allocatedAddress,
			MAC: address.Spec.MAC,
			Owner: juneauv1alpha1.OwnerRef{
				Namespace: address.Namespace,
				Name:      address.Name,
				UID:       string(address.UID),
			},
		},
	}
	if err := r.Create(ctx, subnetLease); err != nil {
		if !errors.IsAlreadyExists(err) {
			logger.Error(err, "unable to create SubnetLease", "name", subnetLease.Name)
			return ctrl.Result{}, fmt.Errorf("unable to create SubnetLease %s: %w", subnetLease.Name, err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	address.Status.LeaseName = subnetLease.Name
	address.Status.Address = allocatedAddress
	if err := r.Status().Update(ctx, &address); err != nil {
		logger.Error(err, "unable to update Address status", "name", address.Name)
		if err := r.Delete(ctx, subnetLease); err != nil {
			logger.Error(err, "unable to delete SubnetLease after Address status update failure", "name", subnetLease.Name)
		}
		return ctrl.Result{}, fmt.Errorf("unable to update Address %s status after creating SubnetLease %s: %w", address.Name, subnetLease.Name, err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AddressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.Address{},
		"spec.subnet",
		func(obj client.Object) []string {
			address := obj.(*juneauv1alpha1.Address)
			if address.Spec.Subnet == "" {
				return nil
			}
			return []string{address.Spec.Subnet}
		},
		); err != nil {
		return fmt.Errorf("failed to set up field indexer for Address.spec.subnet: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.Address{}).
		Named("address").
		Complete(r)
}
