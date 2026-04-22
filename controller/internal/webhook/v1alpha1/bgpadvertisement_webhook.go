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
// log is for logging in this package.
var bgpadvertisementlog = logf.Log.WithName("bgpadvertisement-resource")

// SetupBGPAdvertisementWebhookWithManager registers the webhook for BGPAdvertisement in the manager.
func SetupBGPAdvertisementWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.BGPAdvertisement{}).
		WithValidator(&BGPAdvertisementCustomValidator{Client: mgr.GetClient()}).
		WithDefaulter(&BGPAdvertisementCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-bgpadvertisement,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=bgpadvertisements,verbs=create;update,versions=v1alpha1,name=mbgpadvertisement-v1alpha1.kb.io,admissionReviewVersions=v1

// BGPAdvertisementCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind BGPAdvertisement when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type BGPAdvertisementCustomDefaulter struct{}

var _ webhook.CustomDefaulter = &BGPAdvertisementCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind BGPAdvertisement.
func (d *BGPAdvertisementCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	bgpadvertisement, ok := obj.(*juneauloutresmev1alpha1.BGPAdvertisement)
	if !ok {
		return fmt.Errorf("expected an BGPAdvertisement object but got %T", obj)
	}
	bgpadvertisementlog.Info("Defaulting for BGPAdvertisement", "name", bgpadvertisement.GetName())
	return nil
}

// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-bgpadvertisement,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=bgpadvertisements,verbs=create;update,versions=v1alpha1,name=vbgpadvertisement-v1alpha1.kb.io,admissionReviewVersions=v1

// BGPAdvertisementCustomValidator struct is responsible for validating the BGPAdvertisement resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type BGPAdvertisementCustomValidator struct {
	client.Client
}

var _ webhook.CustomValidator = &BGPAdvertisementCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type BGPAdvertisement.
func (v *BGPAdvertisementCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	bgpadvertisement, ok := obj.(*juneauloutresmev1alpha1.BGPAdvertisement)
	if !ok {
		return nil, fmt.Errorf("expected a BGPAdvertisement object but got %T", obj)
	}
	bgpadvertisementlog.Info("Validation for BGPAdvertisement upon creation", "name", bgpadvertisement.GetName())

	return v.validate(ctx, bgpadvertisement)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type BGPAdvertisement.
func (v *BGPAdvertisementCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	bgpadvertisement, ok := newObj.(*juneauloutresmev1alpha1.BGPAdvertisement)
	if !ok {
		return nil, fmt.Errorf("expected a BGPAdvertisement object for the newObj but got %T", newObj)
	}
	bgpadvertisementlog.Info("Validation for BGPAdvertisement upon update", "name", bgpadvertisement.GetName())

	return v.validate(ctx, bgpadvertisement)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type BGPAdvertisement.
func (v *BGPAdvertisementCustomValidator) ValidateDelete(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	bgpadvertisement, ok := obj.(*juneauloutresmev1alpha1.BGPAdvertisement)
	if !ok {
		return nil, fmt.Errorf("expected a BGPAdvertisement object but got %T", obj)
	}
	bgpadvertisementlog.Info("Validation for BGPAdvertisement upon deletion", "name", bgpadvertisement.GetName())
	return nil, nil
}

func (v *BGPAdvertisementCustomValidator) validate(ctx context.Context, obj *juneauloutresmev1alpha1.BGPAdvertisement) (admission.Warnings, error) {
	var errs field.ErrorList

	for i, pool := range obj.Spec.AddressPools {
		var ap juneauloutresmev1alpha1.AddressPool
		if err := v.Get(ctx, client.ObjectKey{Name: pool}, &ap); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addressPools").Index(i), pool, "referenced AddressPool does not exist"))
				continue
			}
			return nil, err
		}
		if ap.Spec.AdvertiseMode != juneauloutresmev1alpha1.AddressPoolAdvertiseModeBGP {
			errs = append(errs, field.Invalid(field.NewPath("spec", "addressPools").Index(i), pool, "AddressPool must have advertiseMode=bgp"))
		}
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "BGPAdvertisement"}, obj.Name, errs)
		bgpadvertisementlog.Info("Validation failed for BGPAdvertisement", "name", obj.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}
