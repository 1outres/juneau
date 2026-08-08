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
	"sort"

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
var transitgatewayattachmentlog = logf.Log.WithName("transitgatewayattachment-resource")

// SetupTransitGatewayAttachmentWebhookWithManager registers the webhook for TransitGatewayAttachment in the manager.
func SetupTransitGatewayAttachmentWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.TransitGatewayAttachment{}).
		WithValidator(&TransitGatewayAttachmentCustomValidator{Reader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-transitgatewayattachment,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=transitgatewayattachments,verbs=create;update;delete,versions=v1alpha1,name=vtransitgatewayattachment-v1alpha1.kb.io,admissionReviewVersions=v1

// TransitGatewayAttachmentCustomValidator validates
// TransitGatewayAttachment resources.
//
// +kubebuilder:object:generate=false
type TransitGatewayAttachmentCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &TransitGatewayAttachmentCustomValidator{}

func (v *TransitGatewayAttachmentCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	attachment, ok := obj.(*juneauv1alpha1.TransitGatewayAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a TransitGatewayAttachment object but got %T", obj)
	}
	transitgatewayattachmentlog.Info("Validation for TransitGatewayAttachment upon creation", "name", attachment.GetName())

	errs, err := v.validateTransitGatewayAttachmentSpec(ctx, attachment)
	if err != nil {
		return nil, err
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "TransitGatewayAttachment"}, attachment.Name, errs)
		transitgatewayattachmentlog.Info("Validation failed for TransitGatewayAttachment", "name", attachment.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

func (v *TransitGatewayAttachmentCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	attachment, ok := newObj.(*juneauv1alpha1.TransitGatewayAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a TransitGatewayAttachment object for the newObj but got %T", newObj)
	}
	oldAttachment, ok := oldObj.(*juneauv1alpha1.TransitGatewayAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a TransitGatewayAttachment object for the oldObj but got %T", oldObj)
	}
	transitgatewayattachmentlog.Info("Validation for TransitGatewayAttachment upon update", "name", attachment.GetName())

	var errs field.ErrorList
	specPath := field.NewPath("spec")
	if attachment.Spec.TransitGateway != oldAttachment.Spec.TransitGateway {
		errs = append(errs, field.Invalid(specPath.Child("transitGateway"), attachment.Spec.TransitGateway, "spec.transitGateway is immutable"))
	}
	if attachment.Spec.Vpc != oldAttachment.Spec.Vpc {
		errs = append(errs, field.Invalid(specPath.Child("vpc"), attachment.Spec.Vpc, "spec.vpc is immutable"))
	}
	if len(errs) == 0 {
		specErrs, err := v.validateTransitGatewayAttachmentSpec(ctx, attachment)
		if err != nil {
			return nil, err
		}
		errs = append(errs, specErrs...)
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "TransitGatewayAttachment"}, attachment.Name, errs)
		transitgatewayattachmentlog.Info("Validation failed for TransitGatewayAttachment", "name", attachment.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateDelete accepts every deletion. Removing an attachment only
// takes prefixes out of the transit route tables; the RouteTables that
// pointed at the gateway report the missing attachment on their own
// Ready condition.
func (v *TransitGatewayAttachmentCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	_ = ctx

	attachment, ok := obj.(*juneauv1alpha1.TransitGatewayAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a TransitGatewayAttachment object but got %T", obj)
	}
	transitgatewayattachmentlog.Info("Validation for TransitGatewayAttachment upon deletion", "name", attachment.GetName())

	return nil, nil
}

func (v *TransitGatewayAttachmentCustomValidator) validateTransitGatewayAttachmentSpec(ctx context.Context, attachment *juneauv1alpha1.TransitGatewayAttachment) (field.ErrorList, error) {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	var transitGateway juneauv1alpha1.TransitGateway
	if err := v.Get(ctx, client.ObjectKey{Name: attachment.Spec.TransitGateway}, &transitGateway); err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}
		errs = append(errs, field.Invalid(specPath.Child("transitGateway"), attachment.Spec.TransitGateway, "referenced TransitGateway does not exist"))
	}

	var vpc juneauv1alpha1.Vpc
	if err := v.Get(ctx, client.ObjectKey{Name: attachment.Spec.Vpc}, &vpc); err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}
		errs = append(errs, field.Invalid(specPath.Child("vpc"), attachment.Spec.Vpc, "referenced Vpc does not exist"))
	}

	routeTablePaths := []struct {
		path *field.Path
		name string
	}{{specPath.Child("association"), attachment.Spec.Association}}
	for i, name := range attachment.Spec.Propagations {
		routeTablePaths = append(routeTablePaths, struct {
			path *field.Path
			name string
		}{specPath.Child("propagations").Index(i), name})
	}
	for _, ref := range routeTablePaths {
		var routeTable juneauv1alpha1.TransitGatewayRouteTable
		if err := v.Get(ctx, client.ObjectKey{Name: ref.name}, &routeTable); err != nil {
			if !errors.IsNotFound(err) {
				return nil, err
			}
			errs = append(errs, field.Invalid(ref.path, ref.name, "referenced TransitGatewayRouteTable does not exist"))
			continue
		}
		if routeTable.Spec.TransitGateway != attachment.Spec.TransitGateway {
			errs = append(errs, field.Invalid(ref.path, ref.name,
				fmt.Sprintf("TransitGatewayRouteTable belongs to TransitGateway %q (expected %q)", routeTable.Spec.TransitGateway, attachment.Spec.TransitGateway)))
		}
	}

	if len(errs) > 0 {
		return errs, nil
	}

	var attachmentList juneauv1alpha1.TransitGatewayAttachmentList
	if err := v.List(ctx, &attachmentList); err != nil {
		return nil, err
	}

	for i := range attachmentList.Items {
		existing := &attachmentList.Items[i]
		if existing.Name == attachment.Name {
			continue
		}
		if existing.Spec.TransitGateway != attachment.Spec.TransitGateway || existing.Spec.Vpc != attachment.Spec.Vpc {
			continue
		}
		errs = append(errs, field.Invalid(specPath.Child("vpc"), attachment.Spec.Vpc,
			fmt.Sprintf("Vpc %q is already attached to TransitGateway %q by TransitGatewayAttachment %q",
				attachment.Spec.Vpc, attachment.Spec.TransitGateway, existing.Name)))
		return errs, nil
	}

	overlapErrs, err := v.validateTransitGatewayCIDROverlap(ctx, attachment, attachmentList.Items, specPath)
	if err != nil {
		return nil, err
	}
	errs = append(errs, overlapErrs...)

	return errs, nil
}

// validateTransitGatewayCIDROverlap rejects an attachment whose Vpc
// hosts a CIDR that another Vpc on one of the same route tables already
// hosts. The transit lookup resolves a destination to a single Subnet
// VNI, so an address reachable through two attachments has no single
// correct answer.
func (v *TransitGatewayAttachmentCustomValidator) validateTransitGatewayCIDROverlap(ctx context.Context, attachment *juneauv1alpha1.TransitGatewayAttachment, attachments []juneauv1alpha1.TransitGatewayAttachment, path *field.Path) (field.ErrorList, error) {
	reachable := transitGatewayReachableVpcs(attachment.Name, attachment.Spec.Vpc, attachment.Spec.RouteTables(), attachments)
	if len(reachable) == 0 {
		return nil, nil
	}

	var subnetList juneauv1alpha1.SubnetList
	if err := v.List(ctx, &subnetList); err != nil {
		return nil, err
	}

	var own, others []juneauv1alpha1.Subnet
	for _, subnet := range subnetList.Items {
		if subnet.Spec.Vpc == attachment.Spec.Vpc {
			own = append(own, subnet)
			continue
		}
		if _, ok := reachable[subnet.Spec.Vpc]; ok {
			others = append(others, subnet)
		}
	}

	var errs field.ErrorList
	for _, a := range own {
		_, aCIDR, err := net.ParseCIDR(a.Spec.CIDR)
		if err != nil {
			continue
		}
		for _, b := range others {
			_, bCIDR, err := net.ParseCIDR(b.Spec.CIDR)
			if err != nil {
				continue
			}
			if !cidrsOverlap(aCIDR, bCIDR) {
				continue
			}
			errs = append(errs, field.Invalid(path.Child("vpc"), attachment.Spec.Vpc,
				fmt.Sprintf("Subnet %q (CIDR %q) in Vpc %q overlaps with Subnet %q (CIDR %q) in Vpc %q, which is reachable through TransitGatewayRouteTable %q",
					a.Name, a.Spec.CIDR, attachment.Spec.Vpc, b.Name, b.Spec.CIDR, b.Spec.Vpc, reachable[b.Spec.Vpc])))
		}
	}

	return errs, nil
}

// transitGatewayReachableVpcs returns the Vpcs whose prefixes end up in
// one of routeTables, mapped to the route table that carries them. The
// attachment named excludeAttachment and everything in excludeVpc is
// left out so a caller can ask "which other Vpcs would I share a table
// with".
func transitGatewayReachableVpcs(excludeAttachment, excludeVpc string, routeTables []string, attachments []juneauv1alpha1.TransitGatewayAttachment) map[string]string {
	tables := make(map[string]struct{}, len(routeTables))
	for _, name := range routeTables {
		tables[name] = struct{}{}
	}

	sorted := make([]*juneauv1alpha1.TransitGatewayAttachment, 0, len(attachments))
	for i := range attachments {
		sorted = append(sorted, &attachments[i])
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	reachable := map[string]string{}
	for _, other := range sorted {
		if other.Name == excludeAttachment || other.Spec.Vpc == excludeVpc {
			continue
		}
		for _, name := range other.Spec.Propagations {
			if _, ok := tables[name]; !ok {
				continue
			}
			if _, seen := reachable[other.Spec.Vpc]; !seen {
				reachable[other.Spec.Vpc] = name
			}
			break
		}
	}
	return reachable
}
