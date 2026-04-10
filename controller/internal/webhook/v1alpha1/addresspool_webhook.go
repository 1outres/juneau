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
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
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
// log is for logging in this package.
var addresspoollog = logf.Log.WithName("addresspool-resource")

// SetupAddressPoolWebhookWithManager registers the webhook for AddressPool in the manager.
func SetupAddressPoolWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.AddressPool{}).
		WithValidator(&AddressPoolCustomValidator{}).
		WithDefaulter(&AddressPoolCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-addresspool,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=addresspools,verbs=create;update,versions=v1alpha1,name=maddresspool-v1alpha1.kb.io,admissionReviewVersions=v1

// AddressPoolCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind AddressPool when those are created or updated.
type AddressPoolCustomDefaulter struct {
}

var _ webhook.CustomDefaulter = &AddressPoolCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind AddressPool.
func (d *AddressPoolCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	addresspool, ok := obj.(*juneauloutresmev1alpha1.AddressPool)

	if !ok {
		return fmt.Errorf("expected an AddressPool object but got %T", obj)
	}
	addresspoollog.Info("Defaulting for AddressPool", "name", addresspool.GetName())

	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-addresspool,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=addresspools,verbs=create;update,versions=v1alpha1,name=vaddresspool-v1alpha1.kb.io,admissionReviewVersions=v1

// AddressPoolCustomValidator struct is responsible for validating the AddressPool resource
// when it is created, updated, or deleted.
type AddressPoolCustomValidator struct {
}

var _ webhook.CustomValidator = &AddressPoolCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type AddressPool.
func (v *AddressPoolCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	addresspool, ok := obj.(*juneauloutresmev1alpha1.AddressPool)
	if !ok {
		return nil, fmt.Errorf("expected a AddressPool object but got %T", obj)
	}
	addresspoollog.Info("Validation for AddressPool upon creation", "name", addresspool.GetName())

	return v.validate(addresspool, nil)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type AddressPool.
func (v *AddressPoolCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	addresspool, ok := newObj.(*juneauloutresmev1alpha1.AddressPool)
	if !ok {
		return nil, fmt.Errorf("expected a AddressPool object for the newObj but got %T", newObj)
	}
	addresspoollog.Info("Validation for AddressPool upon update", "name", addresspool.GetName())

	oldAddressPool, ok := oldObj.(*juneauloutresmev1alpha1.AddressPool)
	if !ok {
		return nil, fmt.Errorf("expected a AddressPool object for the oldObj but got %T", oldObj)
	}

	return v.validate(addresspool, oldAddressPool)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type AddressPool.
func (v *AddressPoolCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	addresspool, ok := obj.(*juneauloutresmev1alpha1.AddressPool)
	if !ok {
		return nil, fmt.Errorf("expected a AddressPool object but got %T", obj)
	}
	addresspoollog.Info("Validation for AddressPool upon deletion", "name", addresspool.GetName())

	return nil, nil
}

func (v *AddressPoolCustomValidator) validate(newObj *juneauloutresmev1alpha1.AddressPool, oldObj *juneauloutresmev1alpha1.AddressPool) (admission.Warnings, error) {
	var errs field.ErrorList

	if newObj.Spec.AdvertiseMode == "" {
		errs = append(errs, field.Required(field.NewPath("spec", "advertiseMode"), "advertiseMode is required"))
	}

	if len(newObj.Spec.Addresses) == 0 {
		errs = append(errs, field.Required(field.NewPath("spec", "addresses"), "at least one address is required"))
	}

	switch newObj.Spec.AdvertiseMode {
	case juneauloutresmev1alpha1.AddressPoolAdvertiseModeBGP:
		for i, a := range newObj.Spec.Addresses {
			_, ipnet, err := net.ParseCIDR(a)
			if err != nil {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addresses").Index(i), a, "must be a valid CIDR"))
				continue
			}
			if ipnet.IP.To4() == nil {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addresses").Index(i), a, "only IPv4 CIDR is supported"))
				continue
			}
			ones, _ := ipnet.Mask.Size()
			if ones < 8 || ones > 32 {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addresses").Index(i), a, "prefix must be between /8 and /32"))
			}
		}
	case juneauloutresmev1alpha1.AddressPoolAdvertiseModeARP:
		for i, a := range newObj.Spec.Addresses {
			parts := strings.Split(a, "-")
			if len(parts) != 2 {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addresses").Index(i), a, "must be in start-end format"))
				continue
			}
			start := net.ParseIP(strings.TrimSpace(parts[0])).To4()
			end := net.ParseIP(strings.TrimSpace(parts[1])).To4()
			if start == nil || end == nil {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addresses").Index(i), a, "must be IPv4 range"))
				continue
			}
			if bytesCompare(start, end) > 0 {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addresses").Index(i), a, "range start must be <= end"))
			}
		}
	default:
		if newObj.Spec.AdvertiseMode != "" {
			errs = append(errs, field.NotSupported(field.NewPath("spec", "advertiseMode"), newObj.Spec.AdvertiseMode, []string{string(juneauloutresmev1alpha1.AddressPoolAdvertiseModeBGP), string(juneauloutresmev1alpha1.AddressPoolAdvertiseModeARP)}))
		}
	}

	if oldObj != nil {
		if newObj.Spec.AdvertiseMode != oldObj.Spec.AdvertiseMode {
			errs = append(errs, field.Invalid(field.NewPath("spec", "advertiseMode"), newObj.Spec.AdvertiseMode, "advertiseMode is immutable"))
		}
		oldSet := make(map[string]struct{}, len(oldObj.Spec.Addresses))
		for _, a := range oldObj.Spec.Addresses {
			oldSet[a] = struct{}{}
		}
		for a := range oldSet {
			if !contains(newObj.Spec.Addresses, a) {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addresses"), newObj.Spec.Addresses, fmt.Sprintf("address %s cannot be removed", a)))
			}
		}
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "AddressPool"}, newObj.Name, errs)
		addresspoollog.Info("Validation failed for AddressPool", "name", newObj.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

func bytesCompare(a, b net.IP) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] == b[i] {
			continue
		}
		if a[i] < b[i] {
			return -1
		}
		return 1
	}
	if len(a) == len(b) {
		return 0
	}
	if len(a) < len(b) {
		return -1
	}
	return 1
}

func contains(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}
