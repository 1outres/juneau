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
	"slices"

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

	pool := vpc.Spec.EndpointPool
	for i, entry := range pool.Cidrs() {
		// Entries that do not parse are left alone so the validator can
		// report them with the value the user actually wrote.
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		pool.CIDRs[i] = cidr.String()
	}

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
// routing is enabled, and that the VpcEndpoint pool CIDRs stay clear of
// every address range this VPC can already route to.
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
	poolPath := field.NewPath("spec").Child("endpointPool").Child("cidrs")

	if vpc.Spec.ServiceEnabled() && shouldCheckReferences(vpc) {
		if oldVpc == nil || !oldVpc.Spec.ServiceEnabled() {
			serviceErrs, err := v.validateServiceEnabled(ctx, vpc, servicePath)
			if err != nil {
				return nil, err
			}
			errs = append(errs, serviceErrs...)
		}
	}

	if vpcEndpointPoolChanged(oldVpc, vpc) {
		errs = append(errs, validateVpcEndpointPoolCIDRs(vpc.Spec.EndpointPool, poolPath)...)
		errs = append(errs, validateVpcEndpointPoolServiceCIDROverlap(vpc.Spec.EndpointPool, v.ServiceCIDR, poolPath)...)

		if shouldCheckReferences(vpc) {
			subnetErrs, err := v.validateVpcEndpointPoolSubnetOverlap(ctx, vpc, poolPath)
			if err != nil {
				return nil, err
			}
			errs = append(errs, subnetErrs...)

			peeredErrs, err := v.validateVpcEndpointPoolPeeredSubnetOverlap(ctx, vpc, poolPath)
			if err != nil {
				return nil, err
			}
			errs = append(errs, peeredErrs...)

			transitErrs, err := v.validateVpcEndpointPoolTransitGatewaySubnetOverlap(ctx, vpc, poolPath)
			if err != nil {
				return nil, err
			}
			errs = append(errs, transitErrs...)

			if oldVpc != nil {
				shrinkErrs, err := v.validateVpcEndpointPoolShrink(ctx, vpc, poolPath)
				if err != nil {
					return nil, err
				}
				errs = append(errs, shrinkErrs...)
			}
		}
	}

	return errs, nil
}

// vpcEndpointPoolChanged reports whether the endpoint pool differs from
// the one already stored. The pool rules read Subnets and VpcEndpoints,
// so they are skipped on the many updates that leave the pool alone.
func vpcEndpointPoolChanged(oldVpc, vpc *juneauv1alpha1.Vpc) bool {
	if oldVpc == nil {
		return true
	}
	return !slices.Equal(oldVpc.Spec.EndpointPool.Cidrs(), vpc.Spec.EndpointPool.Cidrs())
}

// validateVpcEndpointPoolCIDRs checks the shape of the pool: every entry
// must be an IPv4 block between /16 and /32, and no two entries may
// overlap. A /32 is a legitimate single-VIP pool, while anything wider
// than /16 would swallow the whole address space of the Vpc.
func validateVpcEndpointPoolCIDRs(pool *juneauv1alpha1.VpcEndpointPoolSpec, path *field.Path) field.ErrorList {
	var errs field.ErrorList

	entries := pool.Cidrs()
	parsed := make([]*net.IPNet, len(entries))
	for i, entry := range entries {
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			errs = append(errs, field.Invalid(path.Index(i), entry, "must be a valid IPv4 CIDR"))
			continue
		}
		if cidr.IP.To4() == nil {
			errs = append(errs, field.Invalid(path.Index(i), entry, "only IPv4 CIDR blocks are supported"))
			continue
		}
		ones, _ := cidr.Mask.Size()
		if ones < 16 || ones > 32 {
			errs = append(errs, field.Invalid(path.Index(i), entry, "CIDR prefix length must be between /16 and /32"))
			continue
		}
		parsed[i] = cidr
	}

	for i, cidr := range parsed {
		if cidr == nil {
			continue
		}
		for j := 0; j < i; j++ {
			if parsed[j] == nil {
				continue
			}
			if cidrsOverlap(cidr, parsed[j]) {
				errs = append(errs, field.Invalid(path.Index(i), entries[i],
					fmt.Sprintf("overlaps with spec.endpointPool.cidrs[%d] %q", j, entries[j])))
			}
		}
	}

	return errs
}

// validateVpcEndpointPoolServiceCIDROverlap rejects a pool that overlaps
// the cluster Service CIDR. Both prefixes become via-routes in the same
// FIB, so the pool would shadow every ClusterIP.
func validateVpcEndpointPoolServiceCIDROverlap(pool *juneauv1alpha1.VpcEndpointPoolSpec, serviceCIDR *net.IPNet, path *field.Path) field.ErrorList {
	if serviceCIDR == nil {
		return nil
	}

	var errs field.ErrorList
	for i, entry := range pool.Cidrs() {
		_, poolCIDR, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		if cidrsOverlap(poolCIDR, serviceCIDR) {
			errs = append(errs, field.Invalid(path.Index(i), entry,
				fmt.Sprintf("overlaps with Service CIDR %q", serviceCIDR.String())))
		}
	}

	return errs
}

// validateVpcEndpointPoolSubnetOverlap rejects a pool that overlaps a
// Subnet of this Vpc. A VIP inside a Subnet would need an arp_table
// entry and would collide with the Pod addresses of that Subnet.
func (v *VpcCustomValidator) validateVpcEndpointPoolSubnetOverlap(ctx context.Context, vpc *juneauv1alpha1.Vpc, path *field.Path) (field.ErrorList, error) {
	if !vpc.Spec.EndpointPool.Configured() {
		return nil, nil
	}

	var subnetList juneauv1alpha1.SubnetList
	if err := v.List(ctx, &subnetList); err != nil {
		return nil, err
	}

	var errs field.ErrorList
	for i, entry := range vpc.Spec.EndpointPool.Cidrs() {
		_, poolCIDR, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		for _, subnet := range subnetList.Items {
			if subnet.Spec.Vpc != vpc.Name {
				continue
			}
			_, subnetCIDR, err := net.ParseCIDR(subnet.Spec.CIDR)
			if err != nil {
				continue
			}
			if cidrsOverlap(poolCIDR, subnetCIDR) {
				errs = append(errs, field.Invalid(path.Index(i), entry,
					fmt.Sprintf("overlaps with Subnet %q CIDR %q in Vpc %q", subnet.Name, subnet.Spec.CIDR, vpc.Name)))
			}
		}
	}

	return errs, nil
}

// validateVpcEndpointPoolPeeredSubnetOverlap rejects a pool that
// overlaps a Subnet of a Vpc this Vpc is peered with. This Vpc's FIB
// would hold both the pool route and the peering route for the same
// prefix, and only one of them can win.
func (v *VpcCustomValidator) validateVpcEndpointPoolPeeredSubnetOverlap(ctx context.Context, vpc *juneauv1alpha1.Vpc, path *field.Path) (field.ErrorList, error) {
	if !vpc.Spec.EndpointPool.Configured() {
		return nil, nil
	}

	peerings, err := listPeeredVpcs(ctx, v.Reader, vpc.Name)
	if err != nil {
		return nil, err
	}
	if len(peerings) == 0 {
		return nil, nil
	}

	var subnetList juneauv1alpha1.SubnetList
	if err := v.List(ctx, &subnetList); err != nil {
		return nil, err
	}

	var errs field.ErrorList
	for i, entry := range vpc.Spec.EndpointPool.Cidrs() {
		_, poolCIDR, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		for _, subnet := range subnetList.Items {
			peeringName, peered := peerings[subnet.Spec.Vpc]
			if !peered {
				continue
			}
			_, subnetCIDR, err := net.ParseCIDR(subnet.Spec.CIDR)
			if err != nil {
				continue
			}
			if cidrsOverlap(poolCIDR, subnetCIDR) {
				errs = append(errs, field.Invalid(path.Index(i), entry,
					fmt.Sprintf("overlaps with Subnet %q CIDR %q in Vpc %q, which is peered by VpcPeering %q",
						subnet.Name, subnet.Spec.CIDR, subnet.Spec.Vpc, peeringName)))
			}
		}
	}

	return errs, nil
}

// validateVpcEndpointPoolTransitGatewaySubnetOverlap rejects a pool that
// overlaps a Subnet of a Vpc that shares a TransitGatewayRouteTable with
// this Vpc, for the same reason as the peering check: the FIB would hold
// the pool route and the transit route for one prefix.
func (v *VpcCustomValidator) validateVpcEndpointPoolTransitGatewaySubnetOverlap(ctx context.Context, vpc *juneauv1alpha1.Vpc, path *field.Path) (field.ErrorList, error) {
	if !vpc.Spec.EndpointPool.Configured() {
		return nil, nil
	}

	reachable, err := listTransitGatewayReachableVpcs(ctx, v.Reader, vpc.Name)
	if err != nil {
		return nil, err
	}
	if len(reachable) == 0 {
		return nil, nil
	}

	var subnetList juneauv1alpha1.SubnetList
	if err := v.List(ctx, &subnetList); err != nil {
		return nil, err
	}

	var errs field.ErrorList
	for i, entry := range vpc.Spec.EndpointPool.Cidrs() {
		_, poolCIDR, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		for _, subnet := range subnetList.Items {
			routeTable, ok := reachable[subnet.Spec.Vpc]
			if !ok {
				continue
			}
			_, subnetCIDR, err := net.ParseCIDR(subnet.Spec.CIDR)
			if err != nil {
				continue
			}
			if cidrsOverlap(poolCIDR, subnetCIDR) {
				errs = append(errs, field.Invalid(path.Index(i), entry,
					fmt.Sprintf("overlaps with Subnet %q CIDR %q in Vpc %q, which is reachable through TransitGatewayRouteTable %q",
						subnet.Name, subnet.Spec.CIDR, subnet.Spec.Vpc, routeTable)))
			}
		}
	}

	return errs, nil
}

// validateVpcEndpointPoolShrink rejects taking address space away from
// the pool while a VpcEndpoint still holds an address in it. The Vpc
// controller deletes the AllocationPool as soon as the CIDR is gone, so
// the endpoint would keep an AllocationClaim on a pool that no longer
// exists and its VIP would stop working without any error.
func (v *VpcCustomValidator) validateVpcEndpointPoolShrink(ctx context.Context, vpc *juneauv1alpha1.Vpc, path *field.Path) (field.ErrorList, error) {
	var endpointList juneauv1alpha1.VpcEndpointList
	if err := v.List(ctx, &endpointList); err != nil {
		return nil, err
	}

	var errs field.ErrorList
	for i := range endpointList.Items {
		endpoint := &endpointList.Items[i]
		if endpoint.Spec.Vpc != vpc.Name || endpoint.Status.Address == "" {
			continue
		}
		address := net.ParseIP(endpoint.Status.Address)
		if address == nil {
			continue
		}
		if vpcEndpointPoolContains(vpc.Spec.EndpointPool, address) {
			continue
		}
		errs = append(errs, field.Invalid(path, vpc.Spec.EndpointPool.Cidrs(),
			fmt.Sprintf("VpcEndpoint %q still uses address %q, which no remaining CIDR covers", endpoint.Name, endpoint.Status.Address)))
	}

	return errs, nil
}

func vpcEndpointPoolContains(pool *juneauv1alpha1.VpcEndpointPoolSpec, address net.IP) bool {
	for _, entry := range pool.Cidrs() {
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		if cidr.Contains(address) {
			return true
		}
	}
	return false
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
