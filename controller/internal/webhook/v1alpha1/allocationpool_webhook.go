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
	"errors"
	"fmt"
	"net/netip"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
// log is for logging in this package.
var allocationpoollog = logf.Log.WithName("allocationpool-resource")

// SetupAllocationPoolWebhookWithManager registers the webhook for AllocationPool in the manager.
func SetupAllocationPoolWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.AllocationPool{}).
		WithValidator(&AllocationPoolCustomValidator{Reader: mgr.GetAPIReader()}).
		WithDefaulter(&AllocationPoolCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-allocationpool,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=allocationpools,verbs=create;update,versions=v1alpha1,name=mallocationpool-v1alpha1.kb.io,admissionReviewVersions=v1

// AllocationPoolCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind AllocationPool when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type AllocationPoolCustomDefaulter struct{}

var _ webhook.CustomDefaulter = &AllocationPoolCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind AllocationPool.
func (d *AllocationPoolCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	allocationpool, ok := obj.(*juneauloutresmev1alpha1.AllocationPool)
	if !ok {
		return fmt.Errorf("expected an AllocationPool object but got %T", obj)
	}
	allocationpoollog.Info("Defaulting for AllocationPool", "name", allocationpool.GetName())

	if allocationpool.Spec.Type == "" {
		allocationpool.Spec.Type = juneauloutresmev1alpha1.AllocationTypeNumber
	}
	if allocationpool.Spec.Strategy == "" {
		allocationpool.Spec.Strategy = juneauloutresmev1alpha1.AllocationStrategyFirstFit
	}

	return nil
}

// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-allocationpool,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=allocationpools,verbs=create;update;delete,versions=v1alpha1,name=vallocationpool-v1alpha1.kb.io,admissionReviewVersions=v1

// AllocationPoolCustomValidator struct is responsible for validating the AllocationPool resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type AllocationPoolCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &AllocationPoolCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type AllocationPool.
func (v *AllocationPoolCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	allocationpool, ok := obj.(*juneauloutresmev1alpha1.AllocationPool)
	if !ok {
		return nil, fmt.Errorf("expected a AllocationPool object but got %T", obj)
	}
	allocationpoollog.Info("Validation for AllocationPool upon creation", "name", allocationpool.GetName())

	return nil, validateAllocationPool(allocationpool)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type AllocationPool.
func (v *AllocationPoolCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	allocationpool, ok := newObj.(*juneauloutresmev1alpha1.AllocationPool)
	if !ok {
		return nil, fmt.Errorf("expected a AllocationPool object for the newObj but got %T", newObj)
	}
	allocationpoollog.Info("Validation for AllocationPool upon update", "name", allocationpool.GetName())

	oldPool, ok := oldObj.(*juneauloutresmev1alpha1.AllocationPool)
	if !ok {
		return nil, fmt.Errorf("expected a AllocationPool object for the oldObj but got %T", oldObj)
	}

	var errs field.ErrorList
	specPath := field.NewPath("spec")
	if allocationpool.Spec.Type != oldPool.Spec.Type {
		errs = append(errs, field.Invalid(specPath.Child("type"), allocationpool.Spec.Type, "spec.type is immutable"))
	}
	if allocationpool.Spec.Strategy != oldPool.Spec.Strategy {
		errs = append(errs, field.Invalid(specPath.Child("strategy"), allocationpool.Spec.Strategy, "spec.strategy is immutable"))
	}
	if allocationpool.Spec.Number == nil || oldPool.Spec.Number == nil {
		if allocationpool.Spec.Number != oldPool.Spec.Number {
			errs = append(errs, field.Invalid(specPath.Child("number"), allocationpool.Spec.Number, "spec.number is immutable"))
		}
	} else {
		if allocationpool.Spec.Number.Min != oldPool.Spec.Number.Min {
			errs = append(errs, field.Invalid(specPath.Child("number", "min"), allocationpool.Spec.Number.Min, "spec.number.min is immutable"))
		}
		if allocationpool.Spec.Number.Max != oldPool.Spec.Number.Max {
			errs = append(errs, field.Invalid(specPath.Child("number", "max"), allocationpool.Spec.Number.Max, "spec.number.max is immutable"))
		}
	}
	if err := validateAllocationPoolFields(allocationpool, &errs); err != nil {
		return nil, err
	}
	if len(errs) > 0 {
		err := apierrors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "AllocationPool"}, allocationpool.Name, errs)
		allocationpoollog.Info("Validation failed for AllocationPool", "name", allocationpool.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type AllocationPool.
func (v *AllocationPoolCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	allocationpool, ok := obj.(*juneauloutresmev1alpha1.AllocationPool)
	if !ok {
		return nil, fmt.Errorf("expected a AllocationPool object but got %T", obj)
	}
	allocationpoollog.Info("Validation for AllocationPool upon deletion", "name", allocationpool.GetName())

	var claims juneauloutresmev1alpha1.AllocationClaimList
	if err := v.List(ctx, &claims); err != nil {
		return nil, err
	}
	for _, claim := range claims.Items {
		if claim.DeletionTimestamp != nil {
			continue
		}
		referenced := false
		for _, ref := range claim.Spec.PoolRefs {
			if ref.Name == allocationpool.Name {
				referenced = true
				break
			}
		}
		if !referenced {
			continue
		}
		return nil, apierrors.NewForbidden(
			schema.GroupResource{Group: juneauloutresmev1alpha1.GroupVersion.Group, Resource: "allocationpools"},
			allocationpool.Name,
			fmt.Errorf("AllocationPool is referenced by AllocationClaim %q", claim.Name),
		)
	}

	return nil, nil
}

func validateAllocationPool(pool *juneauloutresmev1alpha1.AllocationPool) error {
	var errs field.ErrorList
	if err := validateAllocationPoolFields(pool, &errs); err != nil {
		return err
	}
	if len(errs) == 0 {
		return nil
	}
	return apierrors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "AllocationPool"}, pool.Name, errs)
}

func validateAllocationPoolFields(pool *juneauloutresmev1alpha1.AllocationPool, errs *field.ErrorList) error {
	specPath := field.NewPath("spec")
	switch pool.Spec.Type {
	case juneauloutresmev1alpha1.AllocationTypeNumber:
		if pool.Spec.Number == nil {
			*errs = append(*errs, field.Required(specPath.Child("number"), "spec.number is required for type=number"))
			return nil
		}
		if pool.Spec.Number.Min > pool.Spec.Number.Max {
			*errs = append(*errs, field.Invalid(specPath.Child("number", "min"), pool.Spec.Number.Min, "spec.number.min must be less than or equal to spec.number.max"))
		}
		if pool.Spec.IP != nil {
			*errs = append(*errs, field.Invalid(specPath.Child("ip"), pool.Spec.IP, "spec.ip is not supported for type=number"))
		}
		return nil
	case juneauloutresmev1alpha1.AllocationTypeIP:
		if pool.Spec.IP == nil {
			*errs = append(*errs, field.Required(specPath.Child("ip"), "spec.ip is required for type=ip"))
			return nil
		}
		if len(pool.Spec.IP.CIDRs) == 0 && len(pool.Spec.IP.Ranges) == 0 {
			*errs = append(*errs, field.Required(specPath.Child("ip"), "spec.ip.cidrs or spec.ip.ranges must contain at least one entry"))
		}
		for i, raw := range pool.Spec.IP.CIDRs {
			if _, err := netip.ParsePrefix(raw); err != nil {
				*errs = append(*errs, field.Invalid(specPath.Child("ip", "cidrs").Index(i), raw, fmt.Sprintf("invalid CIDR: %v", err)))
			}
		}
		for i, entry := range pool.Spec.IP.Ranges {
			validateAllocationPoolIPRange(specPath.Child("ip", "ranges").Index(i), entry, errs)
		}
		for i, raw := range pool.Spec.IP.Excluded {
			if _, err := netip.ParseAddr(raw); err != nil {
				*errs = append(*errs, field.Invalid(specPath.Child("ip", "excluded").Index(i), raw, fmt.Sprintf("invalid IP: %v", err)))
			}
		}
		if pool.Spec.Number != nil {
			*errs = append(*errs, field.Invalid(specPath.Child("number"), pool.Spec.Number, "spec.number is not supported for type=ip"))
		}
		return nil
	}
	if pool.Spec.Number != nil {
		*errs = append(*errs, field.Invalid(specPath.Child("number"), pool.Spec.Number, fmt.Sprintf("spec.number is not supported for type=%q", pool.Spec.Type)))
	}
	if pool.Spec.IP != nil {
		*errs = append(*errs, field.Invalid(specPath.Child("ip"), pool.Spec.IP, fmt.Sprintf("spec.ip is not supported for type=%q", pool.Spec.Type)))
	}
	return nil
}

func validateAllocationPoolIPRange(path *field.Path, entry juneauloutresmev1alpha1.AllocationPoolIPRange, errs *field.ErrorList) {
	start, startErr := parseAllocationPoolIPBound(entry.Start)
	if startErr != nil {
		*errs = append(*errs, field.Invalid(path.Child("start"), entry.Start, startErr.Error()))
	}
	end, endErr := parseAllocationPoolIPBound(entry.End)
	if endErr != nil {
		*errs = append(*errs, field.Invalid(path.Child("end"), entry.End, endErr.Error()))
	}
	if startErr != nil || endErr != nil {
		return
	}
	if start.Compare(end) > 0 {
		*errs = append(*errs, field.Invalid(path, entry, "range start must be less than or equal to range end"))
	}
}

func parseAllocationPoolIPBound(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP: %v", err)
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return netip.Addr{}, errors.New("only IPv4 is supported")
	}
	return addr, nil
}
