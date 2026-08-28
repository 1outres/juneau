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
	"net/netip"

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
	"github.com/1outres/juneau/controller/internal/addressrange"
)

// nolint:unused
// log is for logging in this package.
var l2networklog = logf.Log.WithName("l2network-resource")

// SetupL2NetworkWebhookWithManager registers the webhook for L2Network in the manager.
func SetupL2NetworkWebhookWithManager(mgr ctrl.Manager, serviceCIDR *net.IPNet) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.L2Network{}).
		WithValidator(&L2NetworkCustomValidator{Reader: mgr.GetAPIReader(), ServiceCIDR: serviceCIDR}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-l2network,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=l2networks,verbs=create;update,versions=v1alpha1,name=vl2network-v1alpha1.kb.io,admissionReviewVersions=v1

// L2NetworkCustomValidator validates the L2Network resource when it is
// created or updated.
//
// There is no defaulter on purpose. The gateway address an empty
// spec.gateway.address stands for is written to status by the
// controller, so the spec keeps saying what the user asked for.
type L2NetworkCustomValidator struct {
	client.Reader
	ServiceCIDR *net.IPNet
}

var _ webhook.CustomValidator = &L2NetworkCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type L2Network.
func (v *L2NetworkCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	l2, ok := obj.(*juneauv1alpha1.L2Network)
	if !ok {
		return nil, fmt.Errorf("expected a L2Network object but got %T", obj)
	}
	l2networklog.Info("Validation for L2Network upon creation", "name", l2.GetName())

	specPath := field.NewPath("spec")
	var errs field.ErrorList

	vpcErrs, err := v.validateVpcReference(ctx, l2, specPath.Child("vpc"))
	if err != nil {
		return nil, err
	}
	errs = append(errs, vpcErrs...)

	errs = append(errs, validateL2NetworkCIDR(l2.Spec.CIDR, specPath.Child("cidr"))...)
	overlapErrs, err := validateVpcPrefixOverlaps(ctx, v.Reader, v.ServiceCIDR, l2NetworkVpcPrefix(l2), specPath.Child("cidr"))
	if err != nil {
		return nil, err
	}
	errs = append(errs, overlapErrs...)

	errs = append(errs, validateL2NetworkGateway(l2, specPath)...)
	errs = append(errs, validateL2NetworkACLNeedsGateway(l2, specPath.Child("networkACL"))...)

	referenceErrs, err := v.validateReferences(ctx, l2, specPath)
	if err != nil {
		return nil, err
	}
	errs = append(errs, referenceErrs...)

	return nil, l2NetworkInvalid(l2, errs)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type L2Network.
func (v *L2NetworkCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	l2, ok := newObj.(*juneauv1alpha1.L2Network)
	if !ok {
		return nil, fmt.Errorf("expected a L2Network object for the newObj but got %T", newObj)
	}
	old, ok := oldObj.(*juneauv1alpha1.L2Network)
	if !ok {
		return nil, fmt.Errorf("expected a L2Network object for the oldObj but got %T", oldObj)
	}
	l2networklog.Info("Validation for L2Network upon update", "name", l2.GetName())

	specPath := field.NewPath("spec")
	var errs field.ErrorList

	if l2.Spec.Vpc != old.Spec.Vpc {
		errs = append(errs, field.Invalid(specPath.Child("vpc"), l2.Spec.Vpc, "spec.vpc is immutable"))
	}
	if l2.Spec.CIDR != old.Spec.CIDR {
		errs = append(errs, field.Invalid(specPath.Child("cidr"), l2.Spec.CIDR, "spec.cidr is immutable"))
	}

	errs = append(errs, validateL2NetworkGateway(l2, specPath)...)
	errs = append(errs, validateL2NetworkACLNeedsGateway(l2, specPath.Child("networkACL"))...)

	// Reference checks read other objects, so they are skipped once the
	// object is going away: removing a finalizer is an update too, and
	// deletion order across Kinds is not guaranteed.
	if shouldCheckReferences(l2) {
		rtErrs, err := v.validateGatewayRouteTable(ctx, l2, specPath.Child("gateway", "routeTable"))
		if err != nil {
			return nil, err
		}
		errs = append(errs, rtErrs...)

		// The ACL is re-read only when the reference itself changed, so
		// an unrelated edit never deadlocks on an ACL that is being torn
		// down at the same time.
		if l2.Spec.NetworkACL != old.Spec.NetworkACL {
			aclErrs, err := v.validateNetworkACL(ctx, l2, specPath.Child("networkACL"))
			if err != nil {
				return nil, err
			}
			errs = append(errs, aclErrs...)
		}
	}

	return nil, l2NetworkInvalid(l2, errs)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type L2Network.
//
// Deleting an L2Network always succeeds, even while NetworkInterfaces
// still sit on it. Whoever still points at the segment is stopped by the
// delete guard of the object they reference, not by this one.
func (v *L2NetworkCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	_ = ctx

	l2, ok := obj.(*juneauv1alpha1.L2Network)
	if !ok {
		return nil, fmt.Errorf("expected a L2Network object but got %T", obj)
	}
	l2networklog.Info("Validation for L2Network upon deletion", "name", l2.GetName())

	return nil, nil
}

// validateReferences runs the checks that read other objects.
func (v *L2NetworkCustomValidator) validateReferences(ctx context.Context, l2 *juneauv1alpha1.L2Network, specPath *field.Path) (field.ErrorList, error) {
	rtErrs, err := v.validateGatewayRouteTable(ctx, l2, specPath.Child("gateway", "routeTable"))
	if err != nil {
		return nil, err
	}
	aclErrs, err := v.validateNetworkACL(ctx, l2, specPath.Child("networkACL"))
	if err != nil {
		return nil, err
	}
	return append(rtErrs, aclErrs...), nil
}

// validateVpcReference rejects an L2Network whose Vpc is missing, and
// the default Vpc in particular. The default Vpc is shared by the whole
// cluster and only the default Subnet lives in it.
func (v *L2NetworkCustomValidator) validateVpcReference(ctx context.Context, l2 *juneauv1alpha1.L2Network, path *field.Path) (field.ErrorList, error) {
	if l2.Spec.Vpc == defaultVpcName {
		return field.ErrorList{field.Invalid(path, l2.Spec.Vpc, "an L2Network cannot reference the default Vpc")}, nil
	}

	var vpc juneauv1alpha1.Vpc
	if err := v.Get(ctx, client.ObjectKey{Name: l2.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			return field.ErrorList{field.Invalid(path, l2.Spec.Vpc, "referenced Vpc does not exist")}, nil
		}
		return nil, err
	}

	return nil, nil
}

// validateGatewayRouteTable rejects a gateway whose RouteTable is
// missing or belongs to another Vpc.
func (v *L2NetworkCustomValidator) validateGatewayRouteTable(ctx context.Context, l2 *juneauv1alpha1.L2Network, path *field.Path) (field.ErrorList, error) {
	if l2.Spec.Gateway == nil || l2.Spec.Gateway.RouteTable == "" {
		return nil, nil
	}

	name := l2.Spec.Gateway.RouteTable
	var rt juneauv1alpha1.RouteTable
	if err := v.Get(ctx, client.ObjectKey{Name: name}, &rt); err != nil {
		if errors.IsNotFound(err) {
			return field.ErrorList{field.Invalid(path, name, "referenced RouteTable does not exist")}, nil
		}
		return nil, err
	}

	if rt.Spec.Vpc != l2.Spec.Vpc {
		return field.ErrorList{field.Invalid(path, name,
			fmt.Sprintf("RouteTable belongs to a different Vpc %q", rt.Spec.Vpc))}, nil
	}

	return nil, nil
}

// validateNetworkACL rejects an ACL reference that is missing or points
// into another Vpc.
func (v *L2NetworkCustomValidator) validateNetworkACL(ctx context.Context, l2 *juneauv1alpha1.L2Network, path *field.Path) (field.ErrorList, error) {
	if l2.Spec.NetworkACL == "" {
		return nil, nil
	}

	var acl juneauv1alpha1.NetworkACL
	if err := v.Get(ctx, client.ObjectKey{Name: l2.Spec.NetworkACL}, &acl); err != nil {
		if errors.IsNotFound(err) {
			return field.ErrorList{field.Invalid(path, l2.Spec.NetworkACL, "referenced NetworkACL does not exist")}, nil
		}
		return nil, err
	}

	if acl.Spec.Vpc != l2.Spec.Vpc {
		return field.ErrorList{field.Invalid(path, l2.Spec.NetworkACL,
			fmt.Sprintf("NetworkACL belongs to Vpc %q (expected %q)", acl.Spec.Vpc, l2.Spec.Vpc))}, nil
	}

	return nil, nil
}

// validateL2NetworkCIDR checks the prefix an L2Network declares. On top
// of the shape every Vpc-scoped prefix has to have, it must already be
// written in its normalized form: there is no defaulter to rewrite it,
// and a prefix with host bits left in it would not match what the data
// plane programs.
func validateL2NetworkCIDR(cidr string, path *field.Path) field.ErrorList {
	if cidr == "" {
		return nil
	}
	if errs := validateVpcPrefixCIDR(cidr, path); len(errs) > 0 {
		return errs
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return field.ErrorList{field.Invalid(path, cidr, "must be a valid IPv4 CIDR")}
	}
	if normalized := prefix.Masked().String(); normalized != cidr {
		return field.ErrorList{field.Invalid(path, cidr,
			fmt.Sprintf("must be written in its normalized form %q", normalized))}
	}

	return nil
}

// validateL2NetworkGateway checks the gateway block on its own: it needs
// a prefix to sit in, and the address it answers on has to be one a host
// can actually reach.
func validateL2NetworkGateway(l2 *juneauv1alpha1.L2Network, specPath *field.Path) field.ErrorList {
	gateway := l2.Spec.Gateway
	if gateway == nil {
		return nil
	}

	path := specPath.Child("gateway")
	if l2.Spec.CIDR == "" {
		return field.ErrorList{field.Required(specPath.Child("cidr"),
			"spec.gateway needs spec.cidr: a gateway has to have an address to answer on")}
	}
	if gateway.Address == "" {
		return nil
	}

	prefix, err := netip.ParsePrefix(l2.Spec.CIDR)
	if err != nil {
		// spec.cidr is reported on its own path; nothing to add here.
		return nil
	}
	prefix = prefix.Masked()

	addr, err := netip.ParseAddr(gateway.Address)
	if err != nil || !addr.Is4() {
		return field.ErrorList{field.Invalid(path.Child("address"), gateway.Address, "must be a valid IPv4 address")}
	}
	if !prefix.Contains(addr) {
		return field.ErrorList{field.Invalid(path.Child("address"), gateway.Address,
			fmt.Sprintf("must be within spec.cidr %q", l2.Spec.CIDR))}
	}
	if addr == prefix.Addr() {
		return field.ErrorList{field.Invalid(path.Child("address"), gateway.Address,
			"must not be the network address of spec.cidr")}
	}
	if addr == addressrange.LastAddr(prefix) {
		return field.ErrorList{field.Invalid(path.Child("address"), gateway.Address,
			"must not be the broadcast address of spec.cidr")}
	}

	return nil
}

// validateL2NetworkACLNeedsGateway rejects an ACL on a segment with no
// gateway. The L2 data plane never reads policy, so the rules would only
// ever apply to traffic that crosses the gateway. Accepting the field
// without one would leave the user with a filter that looks configured
// and filters nothing.
func validateL2NetworkACLNeedsGateway(l2 *juneauv1alpha1.L2Network, path *field.Path) field.ErrorList {
	if l2.Spec.NetworkACL == "" || l2.Spec.Gateway != nil {
		return nil
	}
	return field.ErrorList{field.Forbidden(path,
		"a NetworkACL only applies to traffic crossing spec.gateway; declare a gateway or drop the reference")}
}

func l2NetworkInvalid(l2 *juneauv1alpha1.L2Network, errs field.ErrorList) error {
	if len(errs) == 0 {
		return nil
	}
	err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "L2Network"}, l2.Name, errs)
	l2networklog.Info("Validation failed for L2Network", "name", l2.GetName(), "error", err)
	return err
}
