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
	"slices"

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
	"github.com/1outres/juneau/controller/internal/addressrange"
)

// nolint:unused
// log is for logging in this package.
var addresspoollog = logf.Log.WithName("addresspool-resource")

// SetupAddressPoolWebhookWithManager registers the webhook for AddressPool in the manager.
func SetupAddressPoolWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.AddressPool{}).
		WithValidator(&AddressPoolCustomValidator{Reader: mgr.GetAPIReader()}).
		WithDefaulter(&AddressPoolCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-addresspool,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=addresspools,verbs=create;update,versions=v1alpha1,name=maddresspool-v1alpha1.kb.io,admissionReviewVersions=v1

// AddressPoolCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind AddressPool when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type AddressPoolCustomDefaulter struct{}

var _ webhook.CustomDefaulter = &AddressPoolCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind AddressPool.
func (d *AddressPoolCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	addresspool, ok := obj.(*juneauloutresmev1alpha1.AddressPool)
	if !ok {
		return fmt.Errorf("expected an AddressPool object but got %T", obj)
	}
	addresspoollog.Info("Defaulting for AddressPool", "name", addresspool.GetName())
	return nil
}

// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-addresspool,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=addresspools,verbs=create;update;delete,versions=v1alpha1,name=vaddresspool-v1alpha1.kb.io,admissionReviewVersions=v1

// AddressPoolCustomValidator struct is responsible for validating the AddressPool resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type AddressPoolCustomValidator struct {
	client.Reader
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
	oldAddressPool, ok := oldObj.(*juneauloutresmev1alpha1.AddressPool)
	if !ok {
		return nil, fmt.Errorf("expected a AddressPool object for the oldObj but got %T", oldObj)
	}
	addresspoollog.Info("Validation for AddressPool upon update", "name", addresspool.GetName())

	return v.validate(addresspool, oldAddressPool)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type AddressPool.
func (v *AddressPoolCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	addresspool, ok := obj.(*juneauloutresmev1alpha1.AddressPool)
	if !ok {
		return nil, fmt.Errorf("expected a AddressPool object but got %T", obj)
	}
	addresspoollog.Info("Validation for AddressPool upon deletion", "name", addresspool.GetName())

	var externalNetworks juneauloutresmev1alpha1.ExternalNetworkList
	if err := v.List(ctx, &externalNetworks); err != nil {
		return nil, err
	}
	for _, externalNetwork := range externalNetworks.Items {
		if externalNetwork.DeletionTimestamp != nil {
			continue
		}
		if slices.Contains(externalNetwork.Spec.AddressPools, addresspool.Name) {
			return nil, errors.NewForbidden(
				schema.GroupResource{Group: juneauloutresmev1alpha1.GroupVersion.Group, Resource: "addresspools"},
				addresspool.Name,
				fmt.Errorf("AddressPool is referenced by ExternalNetwork %q", externalNetwork.Name),
			)
		}
	}

	var bgpAdvertisements juneauloutresmev1alpha1.BGPAdvertisementList
	if err := v.List(ctx, &bgpAdvertisements); err != nil {
		return nil, err
	}
	for _, bgpAdvertisement := range bgpAdvertisements.Items {
		if bgpAdvertisement.DeletionTimestamp != nil {
			continue
		}
		if slices.Contains(bgpAdvertisement.Spec.AddressPools, addresspool.Name) {
			return nil, errors.NewForbidden(
				schema.GroupResource{Group: juneauloutresmev1alpha1.GroupVersion.Group, Resource: "addresspools"},
				addresspool.Name,
				fmt.Errorf("AddressPool is referenced by BGPAdvertisement %q", bgpAdvertisement.Name),
			)
		}
	}

	return nil, nil
}

func (v *AddressPoolCustomValidator) validate(newObj *juneauloutresmev1alpha1.AddressPool, oldObj *juneauloutresmev1alpha1.AddressPool) (admission.Warnings, error) {
	var errs field.ErrorList

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
			if _, _, err := addressrange.ParseIPv4Range(a); err != nil {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addresses").Index(i), a, err.Error()))
			}
		}
	}

	if oldObj != nil {
		if newObj.Spec.AdvertiseMode != oldObj.Spec.AdvertiseMode {
			errs = append(errs, field.Invalid(field.NewPath("spec", "advertiseMode"), newObj.Spec.AdvertiseMode, "advertiseMode is immutable"))
		}
		newSet := make(map[string]struct{}, len(newObj.Spec.Addresses))
		for _, a := range newObj.Spec.Addresses {
			newSet[a] = struct{}{}
		}
		for _, a := range oldObj.Spec.Addresses {
			if _, ok := newSet[a]; !ok {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addresses"), newObj.Spec.Addresses, fmt.Sprintf("address %q cannot be removed; addresses are append-only", a)))
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
