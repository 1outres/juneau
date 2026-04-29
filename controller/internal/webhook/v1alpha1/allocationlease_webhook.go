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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
var allocationleaselog = logf.Log.WithName("allocationlease-resource")

// SetupAllocationLeaseWebhookWithManager registers the webhook for AllocationLease in the manager.
func SetupAllocationLeaseWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.AllocationLease{}).
		WithValidator(&AllocationLeaseCustomValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-allocationlease,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=allocationleases,verbs=create;update,versions=v1alpha1,name=vallocationlease-v1alpha1.kb.io,admissionReviewVersions=v1

// AllocationLeaseCustomValidator validates AllocationLease resources.
//
// AllocationLease is an internal resource managed by the AllocationClaim
// controller. The webhook enforces structural invariants (required fields,
// immutable identity) so that mistakes in the controller's auto-management
// surface immediately rather than corrupting state.
type AllocationLeaseCustomValidator struct{}

var _ webhook.CustomValidator = &AllocationLeaseCustomValidator{}

func (v *AllocationLeaseCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	lease, ok := obj.(*juneauloutresmev1alpha1.AllocationLease)
	if !ok {
		return nil, fmt.Errorf("expected an AllocationLease object but got %T", obj)
	}
	allocationleaselog.Info("Validation for AllocationLease upon creation", "name", lease.GetName())

	if errs := validateAllocationLeaseSpec(lease); len(errs) > 0 {
		return nil, apierrors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "AllocationLease"}, lease.Name, errs)
	}
	return nil, nil
}

func (v *AllocationLeaseCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	lease, ok := newObj.(*juneauloutresmev1alpha1.AllocationLease)
	if !ok {
		return nil, fmt.Errorf("expected an AllocationLease object for the newObj but got %T", newObj)
	}
	old, ok := oldObj.(*juneauloutresmev1alpha1.AllocationLease)
	if !ok {
		return nil, fmt.Errorf("expected an AllocationLease object for the oldObj but got %T", oldObj)
	}
	allocationleaselog.Info("Validation for AllocationLease upon update", "name", lease.GetName())

	var errs field.ErrorList
	specPath := field.NewPath("spec")
	if lease.Spec.PoolRef.Name != old.Spec.PoolRef.Name {
		errs = append(errs, field.Invalid(specPath.Child("poolRef", "name"), lease.Spec.PoolRef.Name, "spec.poolRef.name is immutable"))
	}
	if lease.Spec.Value != old.Spec.Value {
		errs = append(errs, field.Invalid(specPath.Child("value"), lease.Spec.Value, "spec.value is immutable"))
	}
	if lease.Spec.ReuseKey != old.Spec.ReuseKey {
		errs = append(errs, field.Invalid(specPath.Child("reuseKey"), lease.Spec.ReuseKey, "spec.reuseKey is immutable"))
	}
	errs = append(errs, validateAllocationLeaseSpec(lease)...)

	if len(errs) > 0 {
		return nil, apierrors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "AllocationLease"}, lease.Name, errs)
	}
	return nil, nil
}

func (v *AllocationLeaseCustomValidator) ValidateDelete(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	lease, ok := obj.(*juneauloutresmev1alpha1.AllocationLease)
	if !ok {
		return nil, fmt.Errorf("expected an AllocationLease object but got %T", obj)
	}
	allocationleaselog.Info("Validation for AllocationLease upon deletion", "name", lease.GetName())
	return nil, nil
}

func validateAllocationLeaseSpec(lease *juneauloutresmev1alpha1.AllocationLease) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if lease.Spec.PoolRef.Name == "" {
		errs = append(errs, field.Required(specPath.Child("poolRef", "name"), "spec.poolRef.name is required"))
	}
	if lease.Spec.Value.Number == 0 && lease.Spec.Value.IP == "" {
		errs = append(errs, field.Required(specPath.Child("value"), "spec.value must set either number or ip"))
	}
	if lease.Spec.Value.Number != 0 && lease.Spec.Value.IP != "" {
		errs = append(errs, field.Invalid(specPath.Child("value"), lease.Spec.Value, "spec.value.number and spec.value.ip are mutually exclusive"))
	}
	if lease.Spec.ReuseKey.APIVersion == "" {
		errs = append(errs, field.Required(specPath.Child("reuseKey", "apiVersion"), "spec.reuseKey.apiVersion is required"))
	}
	if lease.Spec.ReuseKey.Kind == "" {
		errs = append(errs, field.Required(specPath.Child("reuseKey", "kind"), "spec.reuseKey.kind is required"))
	}
	if lease.Spec.ReuseKey.Name == "" {
		errs = append(errs, field.Required(specPath.Child("reuseKey", "name"), "spec.reuseKey.name is required"))
	}
	return errs
}
