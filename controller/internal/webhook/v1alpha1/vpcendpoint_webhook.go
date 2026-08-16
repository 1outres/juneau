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
var vpcendpointlog = logf.Log.WithName("vpcendpoint-resource")

// SetupVpcEndpointWebhookWithManager registers the webhook for VpcEndpoint in the manager.
func SetupVpcEndpointWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.VpcEndpoint{}).
		WithValidator(&VpcEndpointCustomValidator{Reader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-vpcendpoint,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=vpcendpoints,verbs=create;update,versions=v1alpha1,name=vvpcendpoint-v1alpha1.kb.io,admissionReviewVersions=v1

// VpcEndpointCustomValidator validates VpcEndpoint resources.
//
// +kubebuilder:object:generate=false
type VpcEndpointCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &VpcEndpointCustomValidator{}

func (v *VpcEndpointCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	endpoint, ok := obj.(*juneauv1alpha1.VpcEndpoint)
	if !ok {
		return nil, fmt.Errorf("expected a VpcEndpoint object but got %T", obj)
	}
	vpcendpointlog.Info("Validation for VpcEndpoint upon creation", "name", endpoint.GetName())

	var errs field.ErrorList
	if shouldCheckReferences(endpoint) {
		vpcErrs, err := v.validateVpcEndpointVpc(ctx, endpoint, field.NewPath("spec").Child("vpc"))
		if err != nil {
			return nil, err
		}
		errs = append(errs, vpcErrs...)
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "VpcEndpoint"}, endpoint.Name, errs)
		vpcendpointlog.Info("Validation failed for VpcEndpoint", "name", endpoint.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

func (v *VpcEndpointCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	_ = ctx

	endpoint, ok := newObj.(*juneauv1alpha1.VpcEndpoint)
	if !ok {
		return nil, fmt.Errorf("expected a VpcEndpoint object for the newObj but got %T", newObj)
	}
	oldEndpoint, ok := oldObj.(*juneauv1alpha1.VpcEndpoint)
	if !ok {
		return nil, fmt.Errorf("expected a VpcEndpoint object for the oldObj but got %T", oldObj)
	}
	vpcendpointlog.Info("Validation for VpcEndpoint upon update", "name", endpoint.GetName())

	var errs field.ErrorList
	specPath := field.NewPath("spec")

	// spec.service stays mutable: pointing a stable VIP at another
	// Service is the main reason to have the VIP at all. spec.vpc is not,
	// because the VIP was taken from the endpoint pool of the old Vpc.
	if endpoint.Spec.Vpc != oldEndpoint.Spec.Vpc {
		errs = append(errs, field.Invalid(specPath.Child("vpc"), endpoint.Spec.Vpc, "spec.vpc is immutable"))
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "VpcEndpoint"}, endpoint.Name, errs)
		vpcendpointlog.Info("Validation failed for VpcEndpoint", "name", endpoint.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateDelete accepts every deletion. The AllocationClaim that holds
// the VIP is owned by the endpoint, so it is garbage-collected with it.
func (v *VpcEndpointCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	_ = ctx

	endpoint, ok := obj.(*juneauv1alpha1.VpcEndpoint)
	if !ok {
		return nil, fmt.Errorf("expected a VpcEndpoint object but got %T", obj)
	}
	vpcendpointlog.Info("Validation for VpcEndpoint upon deletion", "name", endpoint.GetName())

	return nil, nil
}

// validateVpcEndpointVpc checks that spec.vpc names an existing Vpc that
// declares an endpoint pool. Without a pool the endpoint has no address
// to take and can never become Ready on its own, so the mistake is
// better reported at admission than parked in a Status condition.
func (v *VpcEndpointCustomValidator) validateVpcEndpointVpc(ctx context.Context, endpoint *juneauv1alpha1.VpcEndpoint, path *field.Path) (field.ErrorList, error) {
	var vpc juneauv1alpha1.Vpc
	if err := v.Get(ctx, client.ObjectKey{Name: endpoint.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			return field.ErrorList{field.Invalid(path, endpoint.Spec.Vpc, "referenced Vpc does not exist")}, nil
		}
		return nil, err
	}

	if !vpc.Spec.EndpointPool.Configured() {
		return field.ErrorList{field.Invalid(path, endpoint.Spec.Vpc,
			fmt.Sprintf("Vpc %q has no spec.endpointPool; configure it before creating a VpcEndpoint", vpc.Name))}, nil
	}

	return nil, nil
}
