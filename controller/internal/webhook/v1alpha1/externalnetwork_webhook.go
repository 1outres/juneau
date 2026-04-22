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
var externalnetworklog = logf.Log.WithName("externalnetwork-resource")

// SetupExternalNetworkWebhookWithManager registers the webhook for ExternalNetwork in the manager.
func SetupExternalNetworkWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.ExternalNetwork{}).
		WithValidator(&ExternalNetworkCustomValidator{Client: mgr.GetClient()}).
		WithDefaulter(&ExternalNetworkCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-externalnetwork,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=externalnetworks,verbs=create;update,versions=v1alpha1,name=mexternalnetwork-v1alpha1.kb.io,admissionReviewVersions=v1

// ExternalNetworkCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind ExternalNetwork when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type ExternalNetworkCustomDefaulter struct{}

var _ webhook.CustomDefaulter = &ExternalNetworkCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind ExternalNetwork.
func (d *ExternalNetworkCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	externalnetwork, ok := obj.(*juneauloutresmev1alpha1.ExternalNetwork)
	if !ok {
		return fmt.Errorf("expected an ExternalNetwork object but got %T", obj)
	}
	externalnetworklog.Info("Defaulting for ExternalNetwork", "name", externalnetwork.GetName())
	return nil
}

// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-externalnetwork,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=externalnetworks,verbs=create;update;delete,versions=v1alpha1,name=vexternalnetwork-v1alpha1.kb.io,admissionReviewVersions=v1

// ExternalNetworkCustomValidator struct is responsible for validating the ExternalNetwork resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type ExternalNetworkCustomValidator struct {
	client.Client
}

var _ webhook.CustomValidator = &ExternalNetworkCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type ExternalNetwork.
func (v *ExternalNetworkCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	externalnetwork, ok := obj.(*juneauloutresmev1alpha1.ExternalNetwork)
	if !ok {
		return nil, fmt.Errorf("expected a ExternalNetwork object but got %T", obj)
	}
	externalnetworklog.Info("Validation for ExternalNetwork upon creation", "name", externalnetwork.GetName())

	return v.validate(ctx, externalnetwork, nil)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type ExternalNetwork.
func (v *ExternalNetworkCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	externalnetwork, ok := newObj.(*juneauloutresmev1alpha1.ExternalNetwork)
	if !ok {
		return nil, fmt.Errorf("expected a ExternalNetwork object for the newObj but got %T", newObj)
	}
	oldNetwork, ok := oldObj.(*juneauloutresmev1alpha1.ExternalNetwork)
	if !ok {
		return nil, fmt.Errorf("expected a ExternalNetwork object for the oldObj but got %T", oldObj)
	}
	externalnetworklog.Info("Validation for ExternalNetwork upon update", "name", externalnetwork.GetName())

	return v.validate(ctx, externalnetwork, oldNetwork)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type ExternalNetwork.
func (v *ExternalNetworkCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	externalnetwork, ok := obj.(*juneauloutresmev1alpha1.ExternalNetwork)
	if !ok {
		return nil, fmt.Errorf("expected a ExternalNetwork object but got %T", obj)
	}
	externalnetworklog.Info("Validation for ExternalNetwork upon deletion", "name", externalnetwork.GetName())

	var elasticIPs juneauloutresmev1alpha1.ElasticIPList
	if err := v.List(ctx, &elasticIPs); err != nil {
		return nil, err
	}

	for _, elasticIP := range elasticIPs.Items {
		if elasticIP.Spec.ExternalNetwork != externalnetwork.Name {
			continue
		}
		if elasticIP.DeletionTimestamp != nil {
			continue
		}
		return nil, errors.NewForbidden(
			schema.GroupResource{Group: juneauloutresmev1alpha1.GroupVersion.Group, Resource: "externalnetworks"},
			externalnetwork.Name,
			fmt.Errorf("ExternalNetwork is referenced by ElasticIP %q", elasticIP.Name),
		)
	}

	return nil, nil
}

func (v *ExternalNetworkCustomValidator) validate(ctx context.Context, obj *juneauloutresmev1alpha1.ExternalNetwork, oldObj *juneauloutresmev1alpha1.ExternalNetwork) (admission.Warnings, error) {
	var errs field.ErrorList

	if oldObj != nil && obj.Spec.Type != oldObj.Spec.Type {
		errs = append(errs, field.Invalid(field.NewPath("spec", "type"), obj.Spec.Type, "type is immutable"))
	}

	if oldObj != nil {
		newPools := make(map[string]struct{}, len(obj.Spec.AddressPools))
		for _, pool := range obj.Spec.AddressPools {
			newPools[pool] = struct{}{}
		}
		for _, pool := range oldObj.Spec.AddressPools {
			if _, ok := newPools[pool]; !ok {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addressPools"), obj.Spec.AddressPools, fmt.Sprintf("addressPool %q cannot be removed; addressPools are append-only", pool)))
			}
		}
	}

	for i, pool := range obj.Spec.AddressPools {
		var ap juneauloutresmev1alpha1.AddressPool
		if err := v.Get(ctx, client.ObjectKey{Name: pool}, &ap); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addressPools").Index(i), pool, "referenced AddressPool does not exist"))
				continue
			}
			return nil, err
		}
		switch obj.Spec.Type {
		case juneauloutresmev1alpha1.ExternalNetworkTypeBGP:
			if ap.Spec.AdvertiseMode != juneauloutresmev1alpha1.AddressPoolAdvertiseModeBGP {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addressPools").Index(i), pool, "type=bgp requires AddressPool advertiseMode=bgp"))
			}
		case juneauloutresmev1alpha1.ExternalNetworkTypeARP:
			if ap.Spec.AdvertiseMode != juneauloutresmev1alpha1.AddressPoolAdvertiseModeARP {
				errs = append(errs, field.Invalid(field.NewPath("spec", "addressPools").Index(i), pool, "type=arp requires AddressPool advertiseMode=arp"))
			}
		}
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "ExternalNetwork"}, obj.Name, errs)
		externalnetworklog.Info("Validation failed for ExternalNetwork", "name", obj.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}
