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
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var networkendpointlog = logf.Log.WithName("networkendpoint-resource")

// SetupNetworkEndpointWebhookWithManager registers the webhook for NetworkEndpoint in the manager.
func SetupNetworkEndpointWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.NetworkEndpoint{}).
		WithValidator(&NetworkEndpointCustomValidator{}).
		WithDefaulter(&NetworkEndpointCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-networkendpoint,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=networkendpoints,verbs=create;update,versions=v1alpha1,name=mnetworkendpoint-v1alpha1.kb.io,admissionReviewVersions=v1

// NetworkEndpointCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind NetworkEndpoint when those are created or updated.
type NetworkEndpointCustomDefaulter struct {
}

var _ webhook.CustomDefaulter = &NetworkEndpointCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind NetworkEndpoint.
func (d *NetworkEndpointCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	networkendpoint, ok := obj.(*juneauv1alpha1.NetworkEndpoint)

	if !ok {
		return fmt.Errorf("expected an NetworkEndpoint object but got %T", obj)
	}
	networkendpointlog.Info("Defaulting for NetworkEndpoint", "name", networkendpoint.GetName())

	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-networkendpoint,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=networkendpoints,verbs=create;update,versions=v1alpha1,name=vnetworkendpoint-v1alpha1.kb.io,admissionReviewVersions=v1

// NetworkEndpointCustomValidator struct is responsible for validating the NetworkEndpoint resource
// when it is created, updated, or deleted.
type NetworkEndpointCustomValidator struct {
}

var _ webhook.CustomValidator = &NetworkEndpointCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type NetworkEndpoint.
func (v *NetworkEndpointCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	networkendpoint, ok := obj.(*juneauv1alpha1.NetworkEndpoint)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkEndpoint object but got %T", obj)
	}
	networkendpointlog.Info("Validation for NetworkEndpoint upon creation", "name", networkendpoint.GetName())

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type NetworkEndpoint.
func (v *NetworkEndpointCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	networkendpoint, ok := newObj.(*juneauv1alpha1.NetworkEndpoint)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkEndpoint object for the newObj but got %T", newObj)
	}
	oldNetworkEndpoint, ok := oldObj.(*juneauv1alpha1.NetworkEndpoint)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkEndpoint object for the oldObj but got %T", oldObj)
	}
	networkendpointlog.Info("Validation for NetworkEndpoint upon update", "name", networkendpoint.GetName())

	var errs field.ErrorList
	specPath := field.NewPath("spec")
	podRefPath := specPath.Child("podRef")

	if networkendpoint.Spec.NodeName != oldNetworkEndpoint.Spec.NodeName {
		errs = append(errs, field.Invalid(specPath.Child("nodeName"), networkendpoint.Spec.NodeName, "spec.nodeName is immutable"))
	}
	if networkendpoint.Spec.Subnet != oldNetworkEndpoint.Spec.Subnet {
		errs = append(errs, field.Invalid(specPath.Child("subnet"), networkendpoint.Spec.Subnet, "spec.subnet is immutable"))
	}
	if networkendpoint.Spec.Address != oldNetworkEndpoint.Spec.Address {
		errs = append(errs, field.Invalid(specPath.Child("address"), networkendpoint.Spec.Address, "spec.address is immutable"))
	}
	if networkendpoint.Spec.MACAddress != oldNetworkEndpoint.Spec.MACAddress {
		errs = append(errs, field.Invalid(specPath.Child("macAddress"), networkendpoint.Spec.MACAddress, "spec.macAddress is immutable"))
	}
	if networkendpoint.Spec.HostMACAddress != oldNetworkEndpoint.Spec.HostMACAddress {
		errs = append(errs, field.Invalid(specPath.Child("hostMACAddress"), networkendpoint.Spec.HostMACAddress, "spec.hostMACAddress is immutable"))
	}
	if networkendpoint.Spec.Ifindex != oldNetworkEndpoint.Spec.Ifindex {
		errs = append(errs, field.Invalid(specPath.Child("ifindex"), networkendpoint.Spec.Ifindex, "spec.ifindex is immutable"))
	}
	if networkendpoint.Spec.PodRef.UID != oldNetworkEndpoint.Spec.PodRef.UID {
		errs = append(errs, field.Invalid(podRefPath.Child("uid"), networkendpoint.Spec.PodRef.UID, "spec.podRef.uid is immutable"))
	}
	if networkendpoint.Spec.PodRef.Name != oldNetworkEndpoint.Spec.PodRef.Name {
		errs = append(errs, field.Invalid(podRefPath.Child("name"), networkendpoint.Spec.PodRef.Name, "spec.podRef.name is immutable"))
	}
	if networkendpoint.Spec.PodRef.Interface != oldNetworkEndpoint.Spec.PodRef.Interface {
		errs = append(errs, field.Invalid(podRefPath.Child("interface"), networkendpoint.Spec.PodRef.Interface, "spec.podRef.interface is immutable"))
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "NetworkEndpoint"}, networkendpoint.Name, errs)
		networkendpointlog.Info("Validation failed for NetworkEndpoint", "name", networkendpoint.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type NetworkEndpoint.
func (v *NetworkEndpointCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	networkendpoint, ok := obj.(*juneauv1alpha1.NetworkEndpoint)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkEndpoint object but got %T", obj)
	}
	networkendpointlog.Info("Validation for NetworkEndpoint upon deletion", "name", networkendpoint.GetName())

	return nil, nil
}
