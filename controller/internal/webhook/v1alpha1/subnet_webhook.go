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
var subnetlog = logf.Log.WithName("subnet-resource")

// SetupSubnetWebhookWithManager registers the webhook for Subnet in the manager.
func SetupSubnetWebhookWithManager(mgr ctrl.Manager, serviceCIDR *net.IPNet) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.Subnet{}).
		WithValidator(&SubnetCustomValidator{Reader: mgr.GetAPIReader(), ServiceCIDR: serviceCIDR}).
		WithDefaulter(&SubnetCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-subnet,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=subnets,verbs=create;update,versions=v1alpha1,name=msubnet-v1alpha1.kb.io,admissionReviewVersions=v1

// SubnetCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind Subnet when those are created or updated.
type SubnetCustomDefaulter struct {
}

var _ webhook.CustomDefaulter = &SubnetCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind Subnet.
func (d *SubnetCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	_ = ctx

	subnet, ok := obj.(*juneauv1alpha1.Subnet)

	if !ok {
		return fmt.Errorf("expected an Subnet object but got %T", obj)
	}
	subnetlog.Info("Defaulting for Subnet", "name", subnet.GetName())

	_, cidr, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err == nil {
		subnet.Spec.CIDR = cidr.String()
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-subnet,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=subnets,verbs=create;update;delete,versions=v1alpha1,name=vsubnet-v1alpha1.kb.io,admissionReviewVersions=v1

// SubnetCustomValidator struct is responsible for validating the Subnet resource
// when it is created, updated, or deleted.
type SubnetCustomValidator struct {
	client.Reader
	ServiceCIDR *net.IPNet
}

var _ webhook.CustomValidator = &SubnetCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type Subnet.
func (v *SubnetCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	subnet, ok := obj.(*juneauv1alpha1.Subnet)
	if !ok {
		return nil, fmt.Errorf("expected a Subnet object but got %T", obj)
	}
	subnetlog.Info("Validation for Subnet upon creation", "name", subnet.GetName())

	var errs field.ErrorList

	errPath := field.NewPath("spec")
	vpcErrs, err := validateSubnetVpcReference(ctx, v.Reader, subnet, errPath)
	if err != nil {
		return nil, err
	}
	errs = append(errs, vpcErrs...)
	errs = append(errs, validateSubnetCIDR(subnet.Spec.CIDR, errPath.Child("cidr"))...)
	overlapErrs, err := validateSubnetCIDROverlap(ctx, v.Reader, subnet, errPath.Child("cidr"))
	if err != nil {
		return nil, err
	}
	errs = append(errs, overlapErrs...)
	peeredErrs, err := validateSubnetPeeredCIDROverlap(ctx, v.Reader, subnet, errPath.Child("cidr"))
	if err != nil {
		return nil, err
	}
	errs = append(errs, peeredErrs...)
	serviceErrs, err := validateSubnetServiceCIDROverlap(ctx, v.Reader, subnet, v.ServiceCIDR, errPath.Child("cidr"))
	if err != nil {
		return nil, err
	}
	errs = append(errs, serviceErrs...)
	rtErrs, err := validateSubnetRouteTable(ctx, v.Reader, subnet, errPath.Child("routeTable"))
	if err != nil {
		return nil, err
	}
	errs = append(errs, rtErrs...)
	aclErrs, err := validateSubnetNetworkACL(ctx, v.Reader, subnet, errPath.Child("networkACL"))
	if err != nil {
		return nil, err
	}
	errs = append(errs, aclErrs...)

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "Subnet"}, subnet.Name, errs)
		subnetlog.Info("Validation failed for Subnet", "name", subnet.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type Subnet.
func (v *SubnetCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	subnet, ok := newObj.(*juneauv1alpha1.Subnet)
	if !ok {
		return nil, fmt.Errorf("expected a Subnet object for the newObj but got %T", newObj)
	}
	oldSubnet, ok := oldObj.(*juneauv1alpha1.Subnet)
	if !ok {
		return nil, fmt.Errorf("expected a Subnet object for the oldObj but got %T", oldObj)
	}
	subnetlog.Info("Validation for Subnet upon update", "name", subnet.GetName())

	var errs field.ErrorList
	errPath := field.NewPath("spec")

	if subnet.Spec.Vpc != oldSubnet.Spec.Vpc {
		errs = append(errs, field.Invalid(errPath.Child("vpc"), subnet.Spec.Vpc, "spec.vpc is immutable"))
	}

	if subnet.Spec.CIDR != oldSubnet.Spec.CIDR {
		errs = append(errs, field.Invalid(errPath.Child("cidr"), subnet.Spec.CIDR, "spec.cidr is immutable"))
	}

	rtErrs, err := validateSubnetRouteTable(ctx, v.Reader, subnet, errPath.Child("routeTable"))
	if err != nil {
		return nil, err
	}
	errs = append(errs, rtErrs...)

	// Re-validate spec.networkACL only when its name changed. This
	// avoids forcing a webhook lookup on every status-driven finalizer
	// update and prevents a delete-ordering deadlock if the referenced
	// ACL is being torn down concurrently with an unrelated Subnet
	// edit.
	if subnet.Spec.NetworkACL != oldSubnet.Spec.NetworkACL {
		aclErrs, err := validateSubnetNetworkACL(ctx, v.Reader, subnet, errPath.Child("networkACL"))
		if err != nil {
			return nil, err
		}
		errs = append(errs, aclErrs...)
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "Subnet"}, subnet.Name, errs)
		subnetlog.Info("Validation failed for Subnet", "name", subnet.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type Subnet.
func (v *SubnetCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	_ = ctx

	subnet, ok := obj.(*juneauv1alpha1.Subnet)
	if !ok {
		return nil, fmt.Errorf("expected a Subnet object but got %T", obj)
	}
	subnetlog.Info("Validation for Subnet upon deletion", "name", subnet.GetName())

	if subnet.Name == "default" {
		return nil, fmt.Errorf("the default Subnet cannot be deleted")
	}

	return nil, nil
}

func validateSubnetVpcReference(ctx context.Context, c client.Reader, subnet *juneauv1alpha1.Subnet, path *field.Path) (field.ErrorList, error) {
	var errs field.ErrorList

	var vpc juneauv1alpha1.Vpc
	if err := c.Get(ctx, client.ObjectKey{Name: subnet.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			errs = append(errs, field.Invalid(path.Child("vpc"), subnet.Spec.Vpc, "referenced Vpc does not exist"))
			return errs, nil
		}
		return nil, err
	}

	if subnet.Name == "default" && subnet.Spec.Vpc != "default" {
		errs = append(errs, field.Invalid(path.Child("vpc"), subnet.Spec.Vpc, "the default Subnet must reference the default Vpc"))
	}
	if subnet.Spec.Vpc == "default" && subnet.Name != "default" {
		errs = append(errs, field.Invalid(path.Child("vpc"), subnet.Spec.Vpc, "only the default Subnet can reference the default Vpc"))
	}

	return errs, nil
}

func validateSubnetCIDR(cidr string, path *field.Path) field.ErrorList {
	var errs field.ErrorList

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return field.ErrorList{field.Invalid(path, cidr, "must be a valid IPv4 CIDR")}
	}

	if ipnet.IP.To4() == nil {
		return field.ErrorList{field.Invalid(path, cidr, "only IPv4 CIDR blocks are supported")}
	}

	ones, _ := ipnet.Mask.Size()
	if ones < 16 || ones > 28 {
		errs = append(errs, field.Invalid(path, cidr, "CIDR prefix length must be between /16 and /28"))
	}

	return errs
}

func validateSubnetCIDROverlap(ctx context.Context, c client.Reader, subnet *juneauv1alpha1.Subnet, path *field.Path) (field.ErrorList, error) {
	_, subnetCIDR, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		return nil, nil
	}

	var subnetList juneauv1alpha1.SubnetList
	if err := c.List(ctx, &subnetList); err != nil {
		return nil, err
	}

	for _, existingSubnet := range subnetList.Items {
		if existingSubnet.Spec.Vpc != subnet.Spec.Vpc {
			continue
		}

		_, existingCIDR, err := net.ParseCIDR(existingSubnet.Spec.CIDR)
		if err != nil {
			continue
		}

		if cidrsOverlap(subnetCIDR, existingCIDR) {
			return field.ErrorList{field.Invalid(path, subnet.Spec.CIDR, fmt.Sprintf("overlaps with existing Subnet %q CIDR %q in Vpc %q", existingSubnet.Name, existingSubnet.Spec.CIDR, subnet.Spec.Vpc))}, nil
		}
	}

	return nil, nil
}

// validateSubnetPeeredCIDROverlap rejects a Subnet whose CIDR overlaps
// a Subnet of a Vpc this Subnet's Vpc is peered with. A peering route
// resolves to exactly one destination Subnet VNI, so an address that
// exists on both sides of a peering has no single correct answer.
func validateSubnetPeeredCIDROverlap(ctx context.Context, c client.Reader, subnet *juneauv1alpha1.Subnet, path *field.Path) (field.ErrorList, error) {
	_, subnetCIDR, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		return nil, nil
	}

	var peeringList juneauv1alpha1.VpcPeeringList
	if err := c.List(ctx, &peeringList); err != nil {
		return nil, err
	}

	peerings := map[string]string{}
	for i := range peeringList.Items {
		peering := &peeringList.Items[i]
		peer, ok := peering.Spec.PeerOf(subnet.Spec.Vpc)
		if !ok {
			continue
		}
		if _, seen := peerings[peer]; !seen {
			peerings[peer] = peering.Name
		}
	}
	if len(peerings) == 0 {
		return nil, nil
	}

	var subnetList juneauv1alpha1.SubnetList
	if err := c.List(ctx, &subnetList); err != nil {
		return nil, err
	}

	var errs field.ErrorList
	for _, existingSubnet := range subnetList.Items {
		peeringName, peered := peerings[existingSubnet.Spec.Vpc]
		if !peered {
			continue
		}

		_, existingCIDR, err := net.ParseCIDR(existingSubnet.Spec.CIDR)
		if err != nil {
			continue
		}

		if cidrsOverlap(subnetCIDR, existingCIDR) {
			errs = append(errs, field.Invalid(path, subnet.Spec.CIDR,
				fmt.Sprintf("overlaps with Subnet %q CIDR %q in Vpc %q, which is peered by VpcPeering %q",
					existingSubnet.Name, existingSubnet.Spec.CIDR, existingSubnet.Spec.Vpc, peeringName)))
		}
	}

	return errs, nil
}

func cidrsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// validateSubnetRouteTable rejects a Subnet whose spec.routeTable points
// to a non-existent RouteTable, an RT in a different Vpc, or whose name
// is "default" (the default Subnet must use the Vpc's main RouteTable so
// the controller-managed default route stays attached to it).
func validateSubnetRouteTable(ctx context.Context, c client.Reader, subnet *juneauv1alpha1.Subnet, path *field.Path) (field.ErrorList, error) {
	if subnet.Spec.RouteTable == "" {
		return nil, nil
	}

	if subnet.Name == "default" {
		return field.ErrorList{field.Forbidden(path, "default Subnet must use the Vpc's main RouteTable; leave spec.routeTable empty")}, nil
	}

	var rt juneauv1alpha1.RouteTable
	if err := c.Get(ctx, client.ObjectKey{Name: subnet.Spec.RouteTable}, &rt); err != nil {
		if errors.IsNotFound(err) {
			return field.ErrorList{field.Invalid(path, subnet.Spec.RouteTable, "referenced RouteTable does not exist")}, nil
		}
		return nil, err
	}

	if rt.Spec.Vpc != subnet.Spec.Vpc {
		return field.ErrorList{field.Invalid(path, subnet.Spec.RouteTable, fmt.Sprintf("RouteTable belongs to a different Vpc %q", rt.Spec.Vpc))}, nil
	}

	return nil, nil
}

// validateSubnetNetworkACL rejects a Subnet whose spec.networkACL
// names a NetworkACL that does not exist or that belongs to a
// different Vpc.
//
// We deliberately do NOT validate networkACL on every update — the
// caller in ValidateUpdate compares old/new and skips the lookup when
// the field is unchanged. Re-validating an immutable-ish field on
// every update tends to deadlock finalizer-driven updates if the
// referenced object is concurrently torn down.
func validateSubnetNetworkACL(ctx context.Context, c client.Reader, subnet *juneauv1alpha1.Subnet, path *field.Path) (field.ErrorList, error) {
	if subnet.Spec.NetworkACL == "" {
		return nil, nil
	}

	var acl juneauv1alpha1.NetworkACL
	if err := c.Get(ctx, client.ObjectKey{Name: subnet.Spec.NetworkACL}, &acl); err != nil {
		if errors.IsNotFound(err) {
			return field.ErrorList{field.Invalid(path, subnet.Spec.NetworkACL, "referenced NetworkACL does not exist")}, nil
		}
		return nil, err
	}

	if acl.Spec.Vpc != subnet.Spec.Vpc {
		return field.ErrorList{field.Invalid(path, subnet.Spec.NetworkACL,
			fmt.Sprintf("NetworkACL belongs to Vpc %q (expected %q)", acl.Spec.Vpc, subnet.Spec.Vpc))}, nil
	}

	return nil, nil
}

// validateSubnetServiceCIDROverlap rejects creating a Subnet whose CIDR
// overlaps with the cluster Service CIDR when the owning VPC has Service
// routing enabled. Without this check, Pod IPs could collide with
// ClusterIPs and the data plane would not be able to disambiguate.
func validateSubnetServiceCIDROverlap(ctx context.Context, c client.Reader, subnet *juneauv1alpha1.Subnet, serviceCIDR *net.IPNet, path *field.Path) (field.ErrorList, error) {
	if serviceCIDR == nil {
		return nil, nil
	}

	_, subnetCIDR, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		return nil, nil
	}

	var vpc juneauv1alpha1.Vpc
	if err := c.Get(ctx, client.ObjectKey{Name: subnet.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	if !vpc.Spec.ServiceEnabled() {
		return nil, nil
	}

	if cidrsOverlap(subnetCIDR, serviceCIDR) {
		return field.ErrorList{field.Invalid(path, subnet.Spec.CIDR, fmt.Sprintf("overlaps with Service CIDR %q while Vpc %q has Service routing enabled", serviceCIDR.String(), subnet.Spec.Vpc))}, nil
	}

	return nil, nil
}
