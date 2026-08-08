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
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var allocationclaimlog = logf.Log.WithName("allocationclaim-resource")

// SetupAllocationClaimWebhookWithManager registers the webhook for AllocationClaim in the manager.
func SetupAllocationClaimWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.AllocationClaim{}).
		WithValidator(&AllocationClaimCustomValidator{}).
		WithDefaulter(&AllocationClaimCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-allocationclaim,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=allocationclaims,verbs=create;update,versions=v1alpha1,name=mallocationclaim-v1alpha1.kb.io,admissionReviewVersions=v1

// AllocationClaimCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind AllocationClaim when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type AllocationClaimCustomDefaulter struct{}

var _ webhook.CustomDefaulter = &AllocationClaimCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind AllocationClaim.
func (d *AllocationClaimCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	allocationclaim, ok := obj.(*juneauloutresmev1alpha1.AllocationClaim)
	if !ok {
		return fmt.Errorf("expected an AllocationClaim object but got %T", obj)
	}
	allocationclaimlog.Info("Defaulting for AllocationClaim", "name", allocationclaim.GetName())
	return nil
}

// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-allocationclaim,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=allocationclaims,verbs=create;update,versions=v1alpha1,name=vallocationclaim-v1alpha1.kb.io,admissionReviewVersions=v1

// AllocationClaimCustomValidator struct is responsible for validating the AllocationClaim resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type AllocationClaimCustomValidator struct{}

var _ webhook.CustomValidator = &AllocationClaimCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type AllocationClaim.
func (v *AllocationClaimCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	allocationclaim, ok := obj.(*juneauloutresmev1alpha1.AllocationClaim)
	if !ok {
		return nil, fmt.Errorf("expected a AllocationClaim object but got %T", obj)
	}
	allocationclaimlog.Info("Validation for AllocationClaim upon creation", "name", allocationclaim.GetName())

	if errs := validateAllocationClaimSpec(allocationclaim); len(errs) > 0 {
		err := apierrors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "AllocationClaim"}, allocationclaim.Name, errs)
		allocationclaimlog.Info("Validation failed for AllocationClaim", "name", allocationclaim.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type AllocationClaim.
func (v *AllocationClaimCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	allocationclaim, ok := newObj.(*juneauloutresmev1alpha1.AllocationClaim)
	if !ok {
		return nil, fmt.Errorf("expected a AllocationClaim object for the newObj but got %T", newObj)
	}
	allocationclaimlog.Info("Validation for AllocationClaim upon update", "name", allocationclaim.GetName())

	oldClaim, ok := oldObj.(*juneauloutresmev1alpha1.AllocationClaim)
	if !ok {
		return nil, fmt.Errorf("expected a AllocationClaim object for the oldObj but got %T", oldObj)
	}

	var errs field.ErrorList
	specPath := field.NewPath("spec")
	if !reflect.DeepEqual(allocationclaim.Spec.PoolRefs, oldClaim.Spec.PoolRefs) {
		errs = append(errs, field.Invalid(specPath.Child("poolRefs"), allocationclaim.Spec.PoolRefs, "spec.poolRefs is immutable"))
	}
	if allocationclaim.Spec.ResourceRef != oldClaim.Spec.ResourceRef {
		errs = append(errs, field.Invalid(specPath.Child("resourceRef"), allocationclaim.Spec.ResourceRef, "spec.resourceRef is immutable"))
	}
	if allocationclaim.Spec.Attribute != oldClaim.Spec.Attribute {
		errs = append(errs, field.Invalid(specPath.Child("attribute"), allocationclaim.Spec.Attribute, "spec.attribute is immutable"))
	}
	if (allocationclaim.Spec.RequestedNumber == nil) != (oldClaim.Spec.RequestedNumber == nil) {
		errs = append(errs, field.Invalid(specPath.Child("requestedNumber"), allocationclaim.Spec.RequestedNumber, "spec.requestedNumber is immutable"))
	} else if allocationclaim.Spec.RequestedNumber != nil && oldClaim.Spec.RequestedNumber != nil && *allocationclaim.Spec.RequestedNumber != *oldClaim.Spec.RequestedNumber {
		errs = append(errs, field.Invalid(specPath.Child("requestedNumber"), *allocationclaim.Spec.RequestedNumber, "spec.requestedNumber is immutable"))
	}
	if (allocationclaim.Spec.RequestedIP == nil) != (oldClaim.Spec.RequestedIP == nil) {
		errs = append(errs, field.Invalid(specPath.Child("requestedIP"), allocationclaim.Spec.RequestedIP, "spec.requestedIP is immutable"))
	} else if allocationclaim.Spec.RequestedIP != nil && oldClaim.Spec.RequestedIP != nil && *allocationclaim.Spec.RequestedIP != *oldClaim.Spec.RequestedIP {
		errs = append(errs, field.Invalid(specPath.Child("requestedIP"), *allocationclaim.Spec.RequestedIP, "spec.requestedIP is immutable"))
	}
	if !reflect.DeepEqual(allocationclaim.Spec.AllocationFilter, oldClaim.Spec.AllocationFilter) {
		errs = append(errs, field.Invalid(specPath.Child("allocationFilter"), allocationclaim.Spec.AllocationFilter, "spec.allocationFilter is immutable"))
	}
	if allocationclaim.Spec.ReuseKey != oldClaim.Spec.ReuseKey {
		errs = append(errs, field.Invalid(specPath.Child("reuseKey"), allocationclaim.Spec.ReuseKey, "spec.reuseKey is immutable"))
	}
	if !retainReferenceEqual(allocationclaim.Spec.RetainWhile, oldClaim.Spec.RetainWhile) {
		errs = append(errs, field.Invalid(specPath.Child("retainWhile"), allocationclaim.Spec.RetainWhile, "spec.retainWhile is immutable"))
	}
	errs = append(errs, validateAllocationClaimSpec(allocationclaim)...)
	if len(errs) > 0 {
		err := apierrors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "AllocationClaim"}, allocationclaim.Name, errs)
		allocationclaimlog.Info("Validation failed for AllocationClaim", "name", allocationclaim.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// validateAllocationClaimSpec checks the fields that markers cannot express.
func validateAllocationClaimSpec(claim *juneauloutresmev1alpha1.AllocationClaim) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	// The reuse key names the backing AllocationLease object.
	if claim.Spec.ReuseKey != "" {
		for _, msg := range validation.IsDNS1123Subdomain(claim.Spec.ReuseKey) {
			errs = append(errs, field.Invalid(specPath.Child("reuseKey"), claim.Spec.ReuseKey, msg))
		}
	}

	errs = append(errs, validateRetainReference(claim.Spec.RetainWhile, specPath.Child("retainWhile"))...)
	return errs
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type AllocationClaim.
func (v *AllocationClaimCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	allocationclaim, ok := obj.(*juneauloutresmev1alpha1.AllocationClaim)
	if !ok {
		return nil, fmt.Errorf("expected a AllocationClaim object but got %T", obj)
	}
	allocationclaimlog.Info("Validation for AllocationClaim upon deletion", "name", allocationclaim.GetName())

	return nil, nil
}
