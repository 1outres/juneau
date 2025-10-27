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

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var addresslog = logf.Log.WithName("address-resource")

// SetupAddressWebhookWithManager registers the webhook for Address in the manager.
func SetupAddressWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.Address{}).
		WithValidator(&AddressCustomValidator{}).
		WithDefaulter(&AddressCustomDefaulter{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-address,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=addresses,verbs=create;update,versions=v1alpha1,name=maddress-v1alpha1.kb.io,admissionReviewVersions=v1

// AddressCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind Address when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type AddressCustomDefaulter struct {
	// TODO(user): Add more fields as needed for defaulting
}

var _ webhook.CustomDefaulter = &AddressCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind Address.
func (d *AddressCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	address, ok := obj.(*juneauloutresmev1alpha1.Address)

	if !ok {
		return fmt.Errorf("expected an Address object but got %T", obj)
	}
	addresslog.Info("Defaulting for Address", "name", address.GetName())

	// TODO(user): fill in your defaulting logic.

	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-address,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=addresses,verbs=create;update,versions=v1alpha1,name=vaddress-v1alpha1.kb.io,admissionReviewVersions=v1

// AddressCustomValidator struct is responsible for validating the Address resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type AddressCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

var _ webhook.CustomValidator = &AddressCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type Address.
func (v *AddressCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	address, ok := obj.(*juneauloutresmev1alpha1.Address)
	if !ok {
		return nil, fmt.Errorf("expected a Address object but got %T", obj)
	}
	addresslog.Info("Validation for Address upon creation", "name", address.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type Address.
func (v *AddressCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	address, ok := newObj.(*juneauloutresmev1alpha1.Address)
	if !ok {
		return nil, fmt.Errorf("expected a Address object for the newObj but got %T", newObj)
	}
	addresslog.Info("Validation for Address upon update", "name", address.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type Address.
func (v *AddressCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	address, ok := obj.(*juneauloutresmev1alpha1.Address)
	if !ok {
		return nil, fmt.Errorf("expected a Address object but got %T", obj)
	}
	addresslog.Info("Validation for Address upon deletion", "name", address.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}
