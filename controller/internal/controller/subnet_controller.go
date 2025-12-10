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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	subnetReasonReconcileFailed  = "ReconcileFailed"
	subnetReasonNotImplemented   = "NotImplemented"
	subnetReasonReconcileSuccess = "ReconcileSucceeded"
)

// SubnetReconciler reconciles a Subnet object
type SubnetReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *SubnetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauv1alpha1.Subnet
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get Subnet", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.ObjectMeta.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	var vpc juneauv1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.Vpc}, &vpc); err != nil {
		if err := r.updateReadyCondition(ctx, &resource, metav1.ConditionFalse, subnetReasonReconcileFailed, "VPC not found"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	var vni uint32 = 1
	if resource.Name != "default" {
		if err := r.updateReadyCondition(ctx, &resource, metav1.ConditionFalse, subnetReasonNotImplemented, ""); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	_, cidr, err := net.ParseCIDR(resource.Spec.CIDR)
	if err != nil {
		if err := r.updateReadyCondition(ctx, &resource, metav1.ConditionFalse, subnetReasonReconcileFailed, "CIDR parse error"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	resource.Status.VNI = vni
	resource.Status.Gateway = nextGateway(cidr)

	if resource.Name != "default" {
		// TODO: generate a MAC address
	}

	if err := r.updateReadyCondition(ctx, &resource, metav1.ConditionTrue, subnetReasonReconcileSuccess, ""); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SubnetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.Subnet{}).
		Named("subnet").
		Complete(r)
}

func (r *SubnetReconciler) updateReadyCondition(ctx context.Context, subnet *juneauv1alpha1.Subnet, status metav1.ConditionStatus, reason, message string) error {
	subnet.Status.ObservedGeneration = subnet.Generation
	meta.SetStatusCondition(&subnet.Status.Conditions, metav1.Condition{
		Type:    juneauv1alpha1.SubnetStatusReady,
		Status:  status,
		Reason:  reason,
		Message: message,
	})
	return r.Status().Update(ctx, subnet)
}

func nextGateway(cidr *net.IPNet) string {
	ip := cidr.IP.Mask(cidr.Mask).To4()
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
	return ip.String()
}
