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

package v1alpha1

import (
	"context"
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var vpcpeeringlog = logf.Log.WithName("vpcpeering-resource")

// SetupVpcPeeringWebhookWithManager registers the webhook for VpcPeering in the manager.
func SetupVpcPeeringWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.VpcPeering{}).
		WithValidator(&VpcPeeringCustomValidator{Reader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-vpcpeering,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=vpcpeerings,verbs=create;update;delete,versions=v1alpha1,name=vvpcpeering-v1alpha1.kb.io,admissionReviewVersions=v1

// VpcPeeringCustomValidator validates VpcPeering resources.
//
// +kubebuilder:object:generate=false
type VpcPeeringCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &VpcPeeringCustomValidator{}

func (v *VpcPeeringCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	peering, ok := obj.(*juneauv1alpha1.VpcPeering)
	if !ok {
		return nil, fmt.Errorf("expected a VpcPeering object but got %T", obj)
	}
	vpcpeeringlog.Info("Validation for VpcPeering upon creation", "name", peering.GetName())

	errs, err := v.validateVpcPeeringSpec(ctx, peering)
	if err != nil {
		return nil, err
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "VpcPeering"}, peering.Name, errs)
		vpcpeeringlog.Info("Validation failed for VpcPeering", "name", peering.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateUpdate only enforces immutability. Both sides are immutable,
// so nothing the create path checked can have changed in the spec, and
// re-running the Subnet scan on every unrelated update would reject
// edits for a conflict the user cannot fix from this object.
func (v *VpcPeeringCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	_ = ctx

	peering, ok := newObj.(*juneauv1alpha1.VpcPeering)
	if !ok {
		return nil, fmt.Errorf("expected a VpcPeering object for the newObj but got %T", newObj)
	}
	oldPeering, ok := oldObj.(*juneauv1alpha1.VpcPeering)
	if !ok {
		return nil, fmt.Errorf("expected a VpcPeering object for the oldObj but got %T", oldObj)
	}
	vpcpeeringlog.Info("Validation for VpcPeering upon update", "name", peering.GetName())

	var errs field.ErrorList
	specPath := field.NewPath("spec")
	if peering.Spec.Requester != oldPeering.Spec.Requester {
		errs = append(errs, field.Invalid(specPath.Child("requester"), peering.Spec.Requester, "spec.requester is immutable"))
	}
	if peering.Spec.Accepter != oldPeering.Spec.Accepter {
		errs = append(errs, field.Invalid(specPath.Child("accepter"), peering.Spec.Accepter, "spec.accepter is immutable"))
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "VpcPeering"}, peering.Name, errs)
		vpcpeeringlog.Info("Validation failed for VpcPeering", "name", peering.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

func (v *VpcPeeringCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	peering, ok := obj.(*juneauv1alpha1.VpcPeering)
	if !ok {
		return nil, fmt.Errorf("expected a VpcPeering object but got %T", obj)
	}
	vpcpeeringlog.Info("Validation for VpcPeering upon deletion", "name", peering.GetName())

	// Block deletion while a RouteTable still routes through this
	// peering. Without the guard those routes would silently stop
	// resolving and the data plane would drop the traffic instead of
	// telling the operator why.
	var routeTableList juneauv1alpha1.RouteTableList
	if err := v.List(ctx, &routeTableList); err != nil {
		return nil, fmt.Errorf("list RouteTables: %w", err)
	}
	var refs []string
	for _, routeTable := range routeTableList.Items {
		for _, route := range routeTable.Spec.Routes {
			if route.Via.Type == juneauv1alpha1.ViaVpcPeering && route.Via.VpcPeering == peering.Name {
				refs = append(refs, routeTable.Name)
				break
			}
		}
	}
	if len(refs) > 0 {
		return nil, errors.NewForbidden(
			schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "vpcpeerings"},
			peering.Name,
			fmt.Errorf("RouteTable(s) %v still references this VpcPeering via spec.routes[].via.vpcPeering", refs),
		)
	}

	return nil, nil
}

func (v *VpcPeeringCustomValidator) validateVpcPeeringSpec(ctx context.Context, peering *juneauv1alpha1.VpcPeering) (field.ErrorList, error) {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	requester := peering.Spec.Requester.Vpc
	accepter := peering.Spec.Accepter.Vpc

	if requester == accepter {
		errs = append(errs, field.Invalid(specPath.Child("accepter", "vpc"), accepter, "spec.accepter.vpc must not equal spec.requester.vpc"))
		return errs, nil
	}

	endpoints := []struct {
		path *field.Path
		name string
	}{
		{specPath.Child("requester", "vpc"), requester},
		{specPath.Child("accepter", "vpc"), accepter},
	}
	for _, endpoint := range endpoints {
		var vpc juneauv1alpha1.Vpc
		if err := v.Get(ctx, client.ObjectKey{Name: endpoint.name}, &vpc); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, field.Invalid(endpoint.path, endpoint.name, "referenced Vpc does not exist"))
				continue
			}
			return nil, err
		}
	}
	if len(errs) > 0 {
		return errs, nil
	}

	duplicateErrs, err := v.validateVpcPeeringUnique(ctx, peering, specPath)
	if err != nil {
		return nil, err
	}
	errs = append(errs, duplicateErrs...)
	if len(errs) > 0 {
		return errs, nil
	}

	overlapErrs, err := v.validateVpcPeeringCIDROverlap(ctx, requester, accepter, specPath)
	if err != nil {
		return nil, err
	}
	errs = append(errs, overlapErrs...)

	return errs, nil
}

func (v *VpcPeeringCustomValidator) validateVpcPeeringUnique(ctx context.Context, peering *juneauv1alpha1.VpcPeering, path *field.Path) (field.ErrorList, error) {
	var peeringList juneauv1alpha1.VpcPeeringList
	if err := v.List(ctx, &peeringList); err != nil {
		return nil, err
	}

	for i := range peeringList.Items {
		existing := &peeringList.Items[i]
		if existing.Name == peering.Name {
			continue
		}
		if !existing.Spec.Connects(peering.Spec.Requester.Vpc) || !existing.Spec.Connects(peering.Spec.Accepter.Vpc) {
			continue
		}
		return field.ErrorList{field.Invalid(path.Child("accepter", "vpc"), peering.Spec.Accepter.Vpc,
			fmt.Sprintf("Vpcs %q and %q are already connected by VpcPeering %q",
				peering.Spec.Requester.Vpc, peering.Spec.Accepter.Vpc, existing.Name))}, nil
	}

	return nil, nil
}

// validateVpcPeeringCIDROverlap rejects a peering whose two sides host
// overlapping Subnet CIDRs. The data plane resolves a peering route to a
// single destination Subnet VNI, so an address that exists on both sides
// has no single correct answer.
func (v *VpcPeeringCustomValidator) validateVpcPeeringCIDROverlap(ctx context.Context, requester, accepter string, path *field.Path) (field.ErrorList, error) {
	var subnetList juneauv1alpha1.SubnetList
	if err := v.List(ctx, &subnetList); err != nil {
		return nil, err
	}

	var requesterSubnets, accepterSubnets []juneauv1alpha1.Subnet
	for _, subnet := range subnetList.Items {
		switch subnet.Spec.Vpc {
		case requester:
			requesterSubnets = append(requesterSubnets, subnet)
		case accepter:
			accepterSubnets = append(accepterSubnets, subnet)
		}
	}

	var errs field.ErrorList
	for _, a := range requesterSubnets {
		_, aCIDR, err := net.ParseCIDR(a.Spec.CIDR)
		if err != nil {
			continue
		}
		for _, b := range accepterSubnets {
			_, bCIDR, err := net.ParseCIDR(b.Spec.CIDR)
			if err != nil {
				continue
			}
			if !cidrsOverlap(aCIDR, bCIDR) {
				continue
			}
			errs = append(errs, field.Invalid(path, fmt.Sprintf("%s <-> %s", requester, accepter),
				fmt.Sprintf("Subnet %q (CIDR %q) in Vpc %q overlaps with Subnet %q (CIDR %q) in Vpc %q",
					a.Name, a.Spec.CIDR, requester, b.Name, b.Spec.CIDR, accepter)))
		}
	}

	return errs, nil
}
