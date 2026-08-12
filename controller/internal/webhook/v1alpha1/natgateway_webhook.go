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

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
var natgatewaylog = logf.Log.WithName("natgateway-resource")

// SetupNATGatewayWebhookWithManager registers the webhook for NATGateway in the manager.
func SetupNATGatewayWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.NATGateway{}).
		WithValidator(&NATGatewayCustomValidator{Reader: mgr.GetAPIReader()}).
		WithDefaulter(&NATGatewayCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-natgateway,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=natgateways,verbs=create;update,versions=v1alpha1,name=mnatgateway-v1alpha1.kb.io,admissionReviewVersions=v1

// NATGatewayCustomDefaulter sets defaults for NATGateway.
type NATGatewayCustomDefaulter struct{}

var _ webhook.CustomDefaulter = &NATGatewayCustomDefaulter{}

func (d *NATGatewayCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	_ = ctx
	if _, ok := obj.(*juneauloutresmev1alpha1.NATGateway); !ok {
		return fmt.Errorf("expected a NATGateway object but got %T", obj)
	}
	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-natgateway,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=natgateways,verbs=create;update;delete,versions=v1alpha1,name=vnatgateway-v1alpha1.kb.io,admissionReviewVersions=v1

// NATGatewayCustomValidator validates NATGateway resources.
type NATGatewayCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &NATGatewayCustomValidator{}

func (v *NATGatewayCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	natgateway, ok := obj.(*juneauloutresmev1alpha1.NATGateway)
	if !ok {
		return nil, fmt.Errorf("expected a NATGateway object but got %T", obj)
	}
	natgatewaylog.Info("Validation for NATGateway upon creation", "name", natgateway.GetName())

	return v.validate(ctx, natgateway, nil)
}

func (v *NATGatewayCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	natgateway, ok := newObj.(*juneauloutresmev1alpha1.NATGateway)
	if !ok {
		return nil, fmt.Errorf("expected a NATGateway object for the newObj but got %T", newObj)
	}
	oldNATGateway, ok := oldObj.(*juneauloutresmev1alpha1.NATGateway)
	if !ok {
		return nil, fmt.Errorf("expected a NATGateway object for the oldObj but got %T", oldObj)
	}
	natgatewaylog.Info("Validation for NATGateway upon update", "name", natgateway.GetName())

	return v.validate(ctx, natgateway, oldNATGateway)
}

func (v *NATGatewayCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	natgateway, ok := obj.(*juneauloutresmev1alpha1.NATGateway)
	if !ok {
		return nil, fmt.Errorf("expected a NATGateway object but got %T", obj)
	}
	natgatewaylog.Info("Validation for NATGateway upon deletion", "name", natgateway.GetName())

	// Block deletion while any RouteTable.spec.routes references this NATGateway.
	var routeTableList juneauloutresmev1alpha1.RouteTableList
	if err := v.List(ctx, &routeTableList); err != nil {
		return nil, fmt.Errorf("list RouteTables: %w", err)
	}
	var refs []string
	for _, rt := range routeTableList.Items {
		for _, route := range rt.Spec.Routes {
			if route.Via.Type == juneauloutresmev1alpha1.ViaNATGateway && route.Via.NATGateway == natgateway.Name {
				refs = append(refs, rt.Name)
				break
			}
		}
	}
	if len(refs) > 0 {
		return nil, errors.NewForbidden(
			schema.GroupResource{Group: juneauloutresmev1alpha1.GroupVersion.Group, Resource: "natgateways"},
			natgateway.Name,
			fmt.Errorf("RouteTable(s) %v still reference this NATGateway via spec.routes[].via.natGateway", refs),
		)
	}

	return nil, nil
}

func (v *NATGatewayCustomValidator) validate(ctx context.Context, obj, oldObj *juneauloutresmev1alpha1.NATGateway) (admission.Warnings, error) {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if oldObj != nil {
		if obj.Spec.Vpc != oldObj.Spec.Vpc {
			errs = append(errs, field.Invalid(specPath.Child("vpc"), obj.Spec.Vpc, "spec.vpc is immutable"))
		}
		if obj.Spec.ExternalNetwork != oldObj.Spec.ExternalNetwork {
			errs = append(errs, field.Invalid(specPath.Child("externalNetwork"), obj.Spec.ExternalNetwork, "spec.externalNetwork is immutable"))
		}
	}

	if shouldCheckReferences(obj) {
		if obj.Spec.Vpc != "" {
			var vpc juneauloutresmev1alpha1.Vpc
			if err := v.Get(ctx, client.ObjectKey{Name: obj.Spec.Vpc}, &vpc); err != nil {
				if errors.IsNotFound(err) {
					errs = append(errs, field.Invalid(specPath.Child("vpc"), obj.Spec.Vpc, "referenced Vpc does not exist"))
				} else {
					return nil, err
				}
			}
		}

		if obj.Spec.ExternalNetwork != "" {
			var externalNetwork juneauloutresmev1alpha1.ExternalNetwork
			if err := v.Get(ctx, client.ObjectKey{Name: obj.Spec.ExternalNetwork}, &externalNetwork); err != nil {
				if errors.IsNotFound(err) {
					errs = append(errs, field.Invalid(specPath.Child("externalNetwork"), obj.Spec.ExternalNetwork, "referenced ExternalNetwork does not exist"))
				} else {
					return nil, err
				}
			} else if externalNetwork.Spec.Type != juneauloutresmev1alpha1.ExternalNetworkTypeBGP {
				errs = append(errs, field.Invalid(specPath.Child("externalNetwork"), obj.Spec.ExternalNetwork, "referenced ExternalNetwork must have type=bgp"))
			}
		}
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "NATGateway"}, obj.Name, errs)
		natgatewaylog.Info("Validation failed for NATGateway", "name", obj.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}
