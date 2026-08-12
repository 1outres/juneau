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
var vpclog = logf.Log.WithName("vpc-resource")

// SetupVpcWebhookWithManager registers the webhook for Vpc in the manager.
func SetupVpcWebhookWithManager(mgr ctrl.Manager, serviceCIDR *net.IPNet) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.Vpc{}).
		WithValidator(&VpcCustomValidator{Reader: mgr.GetAPIReader(), ServiceCIDR: serviceCIDR}).
		WithDefaulter(&VpcCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-vpc,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=vpcs,verbs=create;update,versions=v1alpha1,name=mvpc-v1alpha1.kb.io,admissionReviewVersions=v1

// VpcCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind Vpc when those are created or updated.
type VpcCustomDefaulter struct {
}

var _ webhook.CustomDefaulter = &VpcCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind Vpc.
func (d *VpcCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)

	if !ok {
		return fmt.Errorf("expected an Vpc object but got %T", obj)
	}
	vpclog.Info("Defaulting for Vpc", "name", vpc.GetName())

	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-vpc,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=vpcs,verbs=create;update;delete,versions=v1alpha1,name=vvpc-v1alpha1.kb.io,admissionReviewVersions=v1

// VpcCustomValidator struct is responsible for validating the Vpc resource
// when it is created, updated, or deleted.
type VpcCustomValidator struct {
	client.Reader
	ServiceCIDR *net.IPNet
}

var _ webhook.CustomValidator = &VpcCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type Vpc.
func (v *VpcCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil, fmt.Errorf("expected a Vpc object but got %T", obj)
	}
	vpclog.Info("Validation for Vpc upon creation", "name", vpc.GetName())

	errs, err := v.validate(ctx, vpc, nil)
	if err != nil {
		return nil, err
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "Vpc"}, vpc.Name, errs)
		vpclog.Info("Validation failed for Vpc", "name", vpc.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type Vpc.
func (v *VpcCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	vpc, ok := newObj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil, fmt.Errorf("expected a Vpc object for the newObj but got %T", newObj)
	}
	oldVpc, ok := oldObj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil, fmt.Errorf("expected a Vpc object for the oldObj but got %T", oldObj)
	}
	vpclog.Info("Validation for Vpc upon update", "name", vpc.GetName())

	errs, err := v.validate(ctx, vpc, oldVpc)
	if err != nil {
		return nil, err
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "Vpc"}, vpc.Name, errs)
		vpclog.Info("Validation failed for Vpc", "name", vpc.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// validate implements the create/update common validation: checks that
// no Subnet in this VPC overlaps the cluster Service CIDR when service
// routing is enabled.
//
// The provider NAT-source-Subnet reference is intentionally NOT
// validated here. Doing so creates a chicken-and-egg admission deadlock
// when a Vpc and its NAT-source Subnet are submitted together (the Vpc
// references a Subnet that does not yet exist, and the Subnet
// references a Vpc that the rejected Vpc admission prevented from being
// created). The reference is instead validated by the Vpc controller
// and surfaced as a Status condition; see VpcReconciler.
//
// oldVpc may be nil (create path); when non-nil it is used to skip the
// expensive Service-CIDR overlap scan when the VPC's service-enabled
// state didn't actually flip.
func (v *VpcCustomValidator) validate(ctx context.Context, vpc, oldVpc *juneauv1alpha1.Vpc) (field.ErrorList, error) {
	var errs field.ErrorList

	servicePath := field.NewPath("spec").Child("service")

	if vpc.Spec.ServiceEnabled() && shouldCheckReferences(vpc) {
		if oldVpc == nil || !oldVpc.Spec.ServiceEnabled() {
			serviceErrs, err := v.validateServiceEnabled(ctx, vpc, servicePath)
			if err != nil {
				return nil, err
			}
			errs = append(errs, serviceErrs...)
		}
	}

	return errs, nil
}

// validateServiceEnabled checks that no Subnet in this VPC has a CIDR
// that overlaps with the cluster Service CIDR. The check protects
// against enabling Service routing on a VPC where Pod IPs would
// collide with ClusterIPs.
func (v *VpcCustomValidator) validateServiceEnabled(ctx context.Context, vpc *juneauv1alpha1.Vpc, path *field.Path) (field.ErrorList, error) {
	if v.ServiceCIDR == nil {
		return nil, nil
	}

	var subnetList juneauv1alpha1.SubnetList
	if err := v.List(ctx, &subnetList); err != nil {
		return nil, err
	}

	var errs field.ErrorList
	for _, subnet := range subnetList.Items {
		if subnet.Spec.Vpc != vpc.Name {
			continue
		}
		_, subnetCIDR, err := net.ParseCIDR(subnet.Spec.CIDR)
		if err != nil {
			continue
		}
		if cidrsOverlap(subnetCIDR, v.ServiceCIDR) {
			errs = append(errs, field.Invalid(path, vpc.Spec.Service, fmt.Sprintf("Subnet %q (CIDR %q) overlaps with Service CIDR %q", subnet.Name, subnet.Spec.CIDR, v.ServiceCIDR.String())))
		}
	}
	return errs, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type Vpc.
func (v *VpcCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil, fmt.Errorf("expected a Vpc object but got %T", obj)
	}
	vpclog.Info("Validation for Vpc upon deletion", "name", vpc.GetName())

	if vpc.Name == "default" {
		return nil, fmt.Errorf("the default Vpc cannot be deleted")
	}

	// Block deletion while any Subnet still belongs to this Vpc. Subnets
	// are not GC'd with the Vpc, and the main RouteTable's delete guard
	// refuses to release the table while a Subnet references it, so
	// enforcing "delete Subnets first" keeps the Vpc's own cascade from
	// stalling on that RouteTable.
	var subnetList juneauv1alpha1.SubnetList
	if err := v.List(ctx, &subnetList); err != nil {
		return nil, fmt.Errorf("list Subnets: %w", err)
	}
	var refs []string
	for _, subnet := range subnetList.Items {
		if subnet.Spec.Vpc == vpc.Name {
			refs = append(refs, subnet.Name)
		}
	}
	if len(refs) > 0 {
		return nil, errors.NewForbidden(
			schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "vpcs"},
			vpc.Name,
			fmt.Errorf("Subnet(s) %v still belong to this Vpc; delete them first", refs),
		)
	}

	// Block deletion while a VpcPeering still names this Vpc. A peering
	// that lost one side can never become Ready again, and the routes
	// pointing at it would stay broken with no object left to fix.
	var peeringList juneauv1alpha1.VpcPeeringList
	if err := v.List(ctx, &peeringList); err != nil {
		return nil, fmt.Errorf("list VpcPeerings: %w", err)
	}
	var peeringRefs []string
	for i := range peeringList.Items {
		if peeringList.Items[i].Spec.Connects(vpc.Name) {
			peeringRefs = append(peeringRefs, peeringList.Items[i].Name)
		}
	}
	if len(peeringRefs) > 0 {
		return nil, errors.NewForbidden(
			schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "vpcs"},
			vpc.Name,
			fmt.Errorf("VpcPeering(s) %v still peer this Vpc; delete them first", peeringRefs),
		)
	}

	// Same reasoning for transit gateways: an attachment that lost its
	// Vpc can never become Ready again, and the route tables it fed
	// would keep advertising prefixes nobody owns.
	var attachmentList juneauv1alpha1.TransitGatewayAttachmentList
	if err := v.List(ctx, &attachmentList); err != nil {
		return nil, fmt.Errorf("list TransitGatewayAttachments: %w", err)
	}
	var attachmentRefs []string
	for i := range attachmentList.Items {
		if attachmentList.Items[i].Spec.Vpc == vpc.Name {
			attachmentRefs = append(attachmentRefs, attachmentList.Items[i].Name)
		}
	}
	if len(attachmentRefs) > 0 {
		return nil, errors.NewForbidden(
			schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "vpcs"},
			vpc.Name,
			fmt.Errorf("TransitGatewayAttachment(s) %v still attach this Vpc; delete them first", attachmentRefs),
		)
	}

	return nil, nil
}
