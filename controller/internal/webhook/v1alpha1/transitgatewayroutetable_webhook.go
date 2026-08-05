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
var transitgatewayroutetablelog = logf.Log.WithName("transitgatewayroutetable-resource")

// SetupTransitGatewayRouteTableWebhookWithManager registers the webhook for TransitGatewayRouteTable in the manager.
func SetupTransitGatewayRouteTableWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.TransitGatewayRouteTable{}).
		WithValidator(&TransitGatewayRouteTableCustomValidator{Reader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-transitgatewayroutetable,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=transitgatewayroutetables,verbs=create;update;delete,versions=v1alpha1,name=vtransitgatewayroutetable-v1alpha1.kb.io,admissionReviewVersions=v1

// TransitGatewayRouteTableCustomValidator validates
// TransitGatewayRouteTable resources.
//
// +kubebuilder:object:generate=false
type TransitGatewayRouteTableCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &TransitGatewayRouteTableCustomValidator{}

func (v *TransitGatewayRouteTableCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	routeTable, ok := obj.(*juneauv1alpha1.TransitGatewayRouteTable)
	if !ok {
		return nil, fmt.Errorf("expected a TransitGatewayRouteTable object but got %T", obj)
	}
	transitgatewayroutetablelog.Info("Validation for TransitGatewayRouteTable upon creation", "name", routeTable.GetName())

	errs, err := v.validateTransitGatewayRouteTableSpec(ctx, routeTable, field.NewPath("spec"))
	if err != nil {
		return nil, err
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "TransitGatewayRouteTable"}, routeTable.Name, errs)
		transitgatewayroutetablelog.Info("Validation failed for TransitGatewayRouteTable", "name", routeTable.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

func (v *TransitGatewayRouteTableCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	routeTable, ok := newObj.(*juneauv1alpha1.TransitGatewayRouteTable)
	if !ok {
		return nil, fmt.Errorf("expected a TransitGatewayRouteTable object for the newObj but got %T", newObj)
	}
	oldRouteTable, ok := oldObj.(*juneauv1alpha1.TransitGatewayRouteTable)
	if !ok {
		return nil, fmt.Errorf("expected a TransitGatewayRouteTable object for the oldObj but got %T", oldObj)
	}
	transitgatewayroutetablelog.Info("Validation for TransitGatewayRouteTable upon update", "name", routeTable.GetName())

	var errs field.ErrorList
	specPath := field.NewPath("spec")
	if routeTable.Spec.TransitGateway != oldRouteTable.Spec.TransitGateway {
		errs = append(errs, field.Invalid(specPath.Child("transitGateway"), routeTable.Spec.TransitGateway, "spec.transitGateway is immutable"))
	} else {
		specErrs, err := v.validateTransitGatewayRouteTableSpec(ctx, routeTable, specPath)
		if err != nil {
			return nil, err
		}
		errs = append(errs, specErrs...)
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "TransitGatewayRouteTable"}, routeTable.Name, errs)
		transitgatewayroutetablelog.Info("Validation failed for TransitGatewayRouteTable", "name", routeTable.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

func (v *TransitGatewayRouteTableCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	routeTable, ok := obj.(*juneauv1alpha1.TransitGatewayRouteTable)
	if !ok {
		return nil, fmt.Errorf("expected a TransitGatewayRouteTable object but got %T", obj)
	}
	transitgatewayroutetablelog.Info("Validation for TransitGatewayRouteTable upon deletion", "name", routeTable.GetName())

	// Block deleting the gateway's default route table. Once the owning
	// TransitGateway is itself being deleted we must let the garbage
	// collector cascade this route table away, otherwise a foreground
	// cascade would deadlock on its own child.
	var transitGateway juneauv1alpha1.TransitGateway
	switch err := v.Get(ctx, client.ObjectKey{Name: routeTable.Name}, &transitGateway); {
	case err == nil:
		if transitGateway.DeletionTimestamp.IsZero() {
			return nil, errors.NewForbidden(
				schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "transitgatewayroutetables"},
				routeTable.Name,
				fmt.Errorf("TransitGatewayRouteTable %q is the default TransitGatewayRouteTable of TransitGateway %q; delete the TransitGateway first", routeTable.Name, transitGateway.Name),
			)
		}
	case !errors.IsNotFound(err):
		return nil, fmt.Errorf("look up TransitGateway %q: %w", routeTable.Name, err)
	}

	// Block deletion while an attachment still associates or propagates
	// into this table. Losing it would silently strand the traffic that
	// arrives from those attachments.
	var attachmentList juneauv1alpha1.TransitGatewayAttachmentList
	if err := v.List(ctx, &attachmentList); err != nil {
		return nil, fmt.Errorf("list TransitGatewayAttachments: %w", err)
	}
	var refs []string
	for i := range attachmentList.Items {
		for _, name := range attachmentList.Items[i].Spec.RouteTables() {
			if name == routeTable.Name {
				refs = append(refs, attachmentList.Items[i].Name)
				break
			}
		}
	}
	if len(refs) > 0 {
		return nil, errors.NewForbidden(
			schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "transitgatewayroutetables"},
			routeTable.Name,
			fmt.Errorf("TransitGatewayAttachment(s) %v still references this TransitGatewayRouteTable via spec.association or spec.propagations", refs),
		)
	}

	return nil, nil
}

func (v *TransitGatewayRouteTableCustomValidator) validateTransitGatewayRouteTableSpec(ctx context.Context, routeTable *juneauv1alpha1.TransitGatewayRouteTable, specPath *field.Path) (field.ErrorList, error) {
	var errs field.ErrorList

	var transitGateway juneauv1alpha1.TransitGateway
	if err := v.Get(ctx, client.ObjectKey{Name: routeTable.Spec.TransitGateway}, &transitGateway); err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}
		errs = append(errs, field.Invalid(specPath.Child("transitGateway"), routeTable.Spec.TransitGateway, "referenced TransitGateway does not exist"))
	}

	seenDst := map[string]struct{}{}
	for i, route := range routeTable.Spec.Routes {
		routePath := specPath.Child("routes").Index(i)

		if route.Blackhole {
			if route.Attachment != "" {
				errs = append(errs, field.Invalid(routePath.Child("attachment"), route.Attachment, "spec.routes[].attachment must be empty when blackhole is true"))
			}
		} else if route.Attachment == "" {
			errs = append(errs, field.Required(routePath.Child("attachment"), "spec.routes[].attachment is required unless blackhole is true"))
		}

		if _, ok := seenDst[route.Dst]; ok {
			errs = append(errs, field.Duplicate(routePath.Child("dst"), route.Dst))
			continue
		}
		seenDst[route.Dst] = struct{}{}
	}

	return errs, nil
}
