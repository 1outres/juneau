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
var addresslog = logf.Log.WithName("address-resource")

// SetupAddressWebhookWithManager registers the webhook for Address in the manager.
func SetupAddressWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.Address{}).
		WithValidator(&AddressCustomValidator{Client: mgr.GetClient()}).
		WithDefaulter(&AddressCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-address,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=addresses,verbs=create;update,versions=v1alpha1,name=maddress-v1alpha1.kb.io,admissionReviewVersions=v1

// AddressCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind Address when those are created or updated.
type AddressCustomDefaulter struct {
}

var _ webhook.CustomDefaulter = &AddressCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind Address.
func (d *AddressCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	address, ok := obj.(*juneauloutresmev1alpha1.Address)

	if !ok {
		return fmt.Errorf("expected an Address object but got %T", obj)
	}
	addresslog.Info("Defaulting for Address", "name", address.GetName())

	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-address,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=addresses,verbs=create;update,versions=v1alpha1,name=vaddress-v1alpha1.kb.io,admissionReviewVersions=v1

// AddressCustomValidator struct is responsible for validating the Address resource
// when it is created, updated, or deleted.
type AddressCustomValidator struct {
	client.Client
}

var _ webhook.CustomValidator = &AddressCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type Address.
func (v *AddressCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	address, ok := obj.(*juneauloutresmev1alpha1.Address)
	if !ok {
		return nil, fmt.Errorf("expected a Address object but got %T", obj)
	}
	addresslog.Info("Validation for Address upon creation", "name", address.GetName())

	var errs field.ErrorList

	var subnet juneauloutresmev1alpha1.Subnet
	if err := v.Get(ctx, client.ObjectKey{Name: address.Spec.Subnet}, &subnet); err != nil {
		if errors.IsNotFound(err) {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("subnet"), address.Spec.Subnet, "referenced Subnet does not exist"))
		} else {
			return nil, fmt.Errorf("unable to get Subnet %s: %w", address.Spec.Subnet, err)
		}
	}

	_, err := net.ParseMAC(address.Spec.MAC)
	if err != nil {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("mac"), address.Spec.MAC, "invalid MAC address format"))
	}

	if address.Spec.Address != "" {
		ip := net.ParseIP(address.Spec.Address)
		if ip == nil {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("address"), address.Spec.Address, "invalid IP address format"))
		} else if subnet.Name != "" {
			_, cidr, err := net.ParseCIDR(subnet.Spec.CIDR)
			if err != nil {
			return nil, fmt.Errorf("invalid CIDR format in Subnet spec: %v", err)
			}
			if !cidr.Contains(ip) {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("address"), address.Spec.Address, "IP address is not within the specified Subnet CIDR"))
			}
		}
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(address.GroupVersionKind().GroupKind(), address.Name, errs)
		addresslog.Error(err, "Validation failed for Address", "name", address.GetName())
		return nil, err
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type Address.
func (v *AddressCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	address, ok := newObj.(*juneauloutresmev1alpha1.Address)
	if !ok {
		return nil, fmt.Errorf("expected a Address object for the newObj but got %T", newObj)
	}
	oldAddress, ok := oldObj.(*juneauloutresmev1alpha1.Address)
	if !ok {
		return nil, fmt.Errorf("expected a Address object for the oldObj but got %T", oldObj)
	}
	addresslog.Info("Validation for Address upon update", "name", address.GetName())

	var errs field.ErrorList

	if address.Spec.Subnet != oldAddress.Spec.Subnet {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("subnet"), address.Spec.Subnet, "field is immutable"))
	}

	if address.Spec.MAC != oldAddress.Spec.MAC {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("mac"), address.Spec.MAC, "field is immutable"))
	}

	if address.Spec.Address != oldAddress.Spec.Address {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("address"), address.Spec.Address, "field is immutable"))
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(address.GroupVersionKind().GroupKind(), address.Name, errs)
		addresslog.Error(err, "Validation failed for Address", "name", address.GetName())
		return nil, err
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type Address.
func (v *AddressCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	address, ok := obj.(*juneauloutresmev1alpha1.Address)
	if !ok {
		return nil, fmt.Errorf("expected a Address object but got %T", obj)
	}
	addresslog.Info("Validation for Address upon deletion", "name", address.GetName())

	return nil, nil
}
