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
	"crypto/rand"
	"fmt"
	"net"
	"reflect"
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
	subnetReasonDeleting           = "Deleting"
	subnetReasonVpcNotFound        = "VpcNotFound"
	subnetReasonVpcNotReady        = "VpcNotReady"
	subnetReasonNotReady           = "NotReady"
	subnetReasonReconcileFailed    = "ReconcileFailed"
	subnetReasonNotImplemented     = "NotImplemented"
	subnetReasonReconcileSucceeded = "ReconcileSucceeded"
)

// SubnetReconciler reconciles a Subnet object
type SubnetReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims/status,verbs=get;update;patch

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
		if err := r.updateStatus(ctx, &resource, resource.Status.VNI, resource.Status.Gateway, resource.Status.GatewayMAC, metav1.ConditionFalse, subnetReasonDeleting, "subnet is being deleted"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	var vpc juneauv1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			if updateErr := r.updateStatus(ctx, &resource, resource.Status.VNI, resource.Status.Gateway, resource.Status.GatewayMAC, metav1.ConditionFalse, subnetReasonVpcNotFound, fmt.Sprintf("referenced VPC %q not found", resource.Spec.Vpc)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
		if updateErr := r.updateStatus(ctx, &resource, resource.Status.VNI, resource.Status.Gateway, resource.Status.GatewayMAC, metav1.ConditionFalse, subnetReasonReconcileFailed, fmt.Sprintf("failed to fetch referenced VPC %q", resource.Spec.Vpc)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	vpcReady := meta.FindStatusCondition(vpc.Status.Conditions, juneauv1alpha1.VpcStatusReady)
	if vpcReady == nil {
		if err := r.updateStatus(ctx, &resource, resource.Status.VNI, resource.Status.Gateway, resource.Status.GatewayMAC, metav1.ConditionFalse, subnetReasonVpcNotReady, fmt.Sprintf("referenced VPC %q has no Ready condition", resource.Spec.Vpc)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if vpcReady.Status != metav1.ConditionTrue {
		message := vpcReady.Message
		if message == "" {
			message = fmt.Sprintf("reason=%s status=%s", vpcReady.Reason, vpcReady.Status)
		}
		if err := r.updateStatus(ctx, &resource, resource.Status.VNI, resource.Status.Gateway, resource.Status.GatewayMAC, metav1.ConditionFalse, subnetReasonVpcNotReady, fmt.Sprintf("referenced VPC %q is not ready: %s", resource.Spec.Vpc, message)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	updated := resource.DeepCopy()

	if updated.Name == "default" {
		updated.Status.VNI = 1
	} else if updated.Status.VNI == 0 {
		claim, err := r.ensureNumberClaim(ctx, &resource, allocationPoolSubnetVNI, schema.GroupVersionKind{Group: juneauv1alpha1.GroupVersion.Group, Version: juneauv1alpha1.GroupVersion.Version, Kind: "Subnet"}, "status.vni")
		if err != nil {
			if updateErr := r.updateStatus(ctx, &resource, resource.Status.VNI, resource.Status.Gateway, resource.Status.GatewayMAC, metav1.ConditionFalse, subnetReasonReconcileFailed, fmt.Sprintf("failed to ensure VNI allocation claim: %v", err)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		if claim.Status.Phase != juneauv1alpha1.AllocationClaimPhaseAllocated || claim.Status.Value.Number == 0 {
			if err := r.updateStatus(ctx, &resource, resource.Status.VNI, resource.Status.Gateway, resource.Status.GatewayMAC, metav1.ConditionFalse, subnetReasonNotReady, "waiting for VNI allocation"); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 100 * time.Millisecond}, nil
		}
		if claim.Status.Value.Number > 0xFFFFFF {
			if err := r.updateStatus(ctx, &resource, resource.Status.VNI, resource.Status.Gateway, resource.Status.GatewayMAC, metav1.ConditionFalse, subnetReasonNotImplemented, fmt.Sprintf("allocated VNI %d exceeds supported range", claim.Status.Value.Number)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		updated.Status.VNI = uint32(claim.Status.Value.Number)
	}

	_, cidr, err := net.ParseCIDR(updated.Spec.CIDR)
	if err != nil {
		if err := r.updateStatus(ctx, &resource, resource.Status.VNI, resource.Status.Gateway, resource.Status.GatewayMAC, metav1.ConditionFalse, subnetReasonReconcileFailed, fmt.Sprintf("failed to parse CIDR %q", updated.Spec.CIDR)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	updated.Status.Gateway = nextGateway(cidr)

	if updated.Status.GatewayMAC == "" {
		randMac, err := newLAA()
		if err != nil {
			if updateErr := r.updateStatus(ctx, &resource, resource.Status.VNI, resource.Status.Gateway, resource.Status.GatewayMAC, metav1.ConditionFalse, subnetReasonReconcileFailed, "failed to generate gateway MAC address"); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}

		updated.Status.GatewayMAC = randMac.String()
	}

	if err := r.updateStatus(ctx, &resource, updated.Status.VNI, updated.Status.Gateway, updated.Status.GatewayMAC, metav1.ConditionTrue, subnetReasonReconcileSucceeded, ""); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SubnetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.Subnet{},
		"spec.vpc",
		func(obj client.Object) []string {
			subnet := obj.(*juneauv1alpha1.Subnet)
			if subnet.Spec.Vpc == "" {
				return nil
			}
			return []string{subnet.Spec.Vpc}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for Subnet.spec.vpc: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.Subnet{}).
		Watches(&juneauv1alpha1.Vpc{}, handler.EnqueueRequestsFromMapFunc(r.mapVpcToSubnets)).
		Watches(&juneauv1alpha1.AllocationClaim{}, handler.EnqueueRequestsFromMapFunc(r.mapClaimToSubnets)).
		Named("subnet").
		Complete(r)
}

func (r *SubnetReconciler) ensureNumberClaim(ctx context.Context, subnet *juneauv1alpha1.Subnet, poolName string, gvk schema.GroupVersionKind, attribute string) (*juneauv1alpha1.AllocationClaim, error) {
	claim := newAllocationClaim(poolName, gvk, subnet.Name, attribute)
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, claim, func() error {
		claim.Spec = newAllocationClaim(poolName, gvk, subnet.Name, attribute).Spec
		return controllerutil.SetControllerReference(subnet, claim, r.Scheme)
	})
	if err != nil {
		return nil, err
	}
	return claim, nil
}

func (r *SubnetReconciler) mapVpcToSubnets(ctx context.Context, obj client.Object) []reconcile.Request {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil
	}

	var subnetList juneauv1alpha1.SubnetList
	if err := r.List(ctx, &subnetList, client.MatchingFields{"spec.vpc": vpc.Name}); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(subnetList.Items))
	for _, subnet := range subnetList.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: subnet.Name}})
	}
	return requests
}

func (r *SubnetReconciler) mapClaimToSubnets(ctx context.Context, obj client.Object) []reconcile.Request {
	_ = ctx
	claim, ok := obj.(*juneauv1alpha1.AllocationClaim)
	if !ok || claim.Spec.ResourceRef.Kind != "Subnet" || claim.Spec.ResourceRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.ResourceRef.Name}}}
}

func (r *SubnetReconciler) updateStatus(ctx context.Context, subnet *juneauv1alpha1.Subnet, vni uint32, gateway, gatewayMAC string, status metav1.ConditionStatus, reason, message string) error {
	updated := subnet.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.VNI = vni
	updated.Status.Gateway = gateway
	updated.Status.GatewayMAC = gatewayMAC
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:               juneauv1alpha1.SubnetStatusReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: updated.Generation,
	})

	if updated.Status.ObservedGeneration == subnet.Status.ObservedGeneration &&
		updated.Status.VNI == subnet.Status.VNI &&
		updated.Status.Gateway == subnet.Status.Gateway &&
		updated.Status.GatewayMAC == subnet.Status.GatewayMAC &&
		reflect.DeepEqual(updated.Status.Conditions, subnet.Status.Conditions) {
		return nil
	}

	subnet.Status = updated.Status
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

func newLAA() (net.HardwareAddr, error) {
	mac := make([]byte, 6)
	if _, err := rand.Read(mac); err != nil {
		return nil, err
	}

	// bit0: I/G (0 = unicast)
	// bit1: U/L (1 = locally administered)
	mac[0] &^= 0x01 // clear I/G
	mac[0] |= 0x02  // set U/L

	return net.HardwareAddr(mac), nil
}
