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

	specPath := field.NewPath("spec")
	errs := validatePodRefForKind(specPath, networkendpoint.Spec.Kind, networkendpoint.Spec.PodRef)
	errs = append(errs, validateInterfaceRefsForKind(specPath, networkendpoint)...)
	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "NetworkEndpoint"}, networkendpoint.Name, errs)
		networkendpointlog.Info("Validation failed for NetworkEndpoint", "name", networkendpoint.GetName(), "error", err)
		return nil, err
	}
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

	// Identity fields (kind, nodeName, subnet, address, macAddress) and
	// PodRef are immutable: they describe who this endpoint is.
	// Attachment (ifindex / hostMACAddress) is intentionally mutable —
	// it is the daemon's view of the local kernel iface and may legally
	// change across daemon restarts (e.g. ifindex re-assignment after
	// host reboot).
	if networkendpoint.Spec.Kind != oldNetworkEndpoint.Spec.Kind {
		errs = append(errs, field.Invalid(specPath.Child("kind"), networkendpoint.Spec.Kind, "spec.kind is immutable"))
	}
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
	errs = append(errs, validatePodRefImmutable(podRefPath, oldNetworkEndpoint.Spec.PodRef, networkendpoint.Spec.PodRef)...)
	errs = append(errs, validatePodRefForKind(specPath, networkendpoint.Spec.Kind, networkendpoint.Spec.PodRef)...)
	if networkendpoint.Spec.NetworkInterfaceRef != oldNetworkEndpoint.Spec.NetworkInterfaceRef {
		errs = append(errs, field.Invalid(specPath.Child("networkInterfaceRef"), networkendpoint.Spec.NetworkInterfaceRef, "spec.networkInterfaceRef is immutable"))
	}
	if !reflect.DeepEqual(networkendpoint.Spec.NetworkInterfaceAttachmentRef, oldNetworkEndpoint.Spec.NetworkInterfaceAttachmentRef) {
		errs = append(errs, field.Invalid(specPath.Child("networkInterfaceAttachmentRef"), networkendpoint.Spec.NetworkInterfaceAttachmentRef, "spec.networkInterfaceAttachmentRef is immutable"))
	}
	errs = append(errs, validateInterfaceRefsForKind(specPath, networkendpoint)...)

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "NetworkEndpoint"}, networkendpoint.Name, errs)
		networkendpointlog.Info("Validation failed for NetworkEndpoint", "name", networkendpoint.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

func validateInterfaceRefsForKind(path *field.Path, endpoint *juneauv1alpha1.NetworkEndpoint) field.ErrorList {
	if endpoint.Spec.Kind != juneauv1alpha1.EndpointKindPod {
		return nil
	}
	var errs field.ErrorList
	if endpoint.Spec.NetworkInterfaceRef == "" {
		errs = append(errs, field.Required(path.Child("networkInterfaceRef"), "required for Pod endpoints"))
	}
	if endpoint.Spec.NetworkInterfaceAttachmentRef == nil {
		errs = append(errs, field.Required(path.Child("networkInterfaceAttachmentRef"), "required for Pod endpoints"))
	}
	return errs
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

// validatePodRefImmutable enforces immutability of PodRef. Adding or
// removing a PodRef on update is also disallowed: PodRef presence is
// kind-scoped (Pod requires it, others forbid it), and Kind itself is
// immutable.
func validatePodRefImmutable(path *field.Path, oldRef, newRef *juneauv1alpha1.NetworkEndpointPodReference) field.ErrorList {
	if oldRef == nil && newRef == nil {
		return nil
	}
	if oldRef == nil || newRef == nil {
		return field.ErrorList{field.Invalid(path, newRef, "spec.podRef presence is immutable")}
	}
	var errs field.ErrorList
	if newRef.UID != oldRef.UID {
		errs = append(errs, field.Invalid(path.Child("uid"), newRef.UID, "spec.podRef.uid is immutable"))
	}
	if newRef.Name != oldRef.Name {
		errs = append(errs, field.Invalid(path.Child("name"), newRef.Name, "spec.podRef.name is immutable"))
	}
	if newRef.Interface != oldRef.Interface {
		errs = append(errs, field.Invalid(path.Child("interface"), newRef.Interface, "spec.podRef.interface is immutable"))
	}
	return errs
}

// validatePodRefForKind enforces the kind/podRef invariant: Pod kind
// requires PodRef, all other kinds forbid it.
func validatePodRefForKind(specPath *field.Path, kind juneauv1alpha1.EndpointKind, ref *juneauv1alpha1.NetworkEndpointPodReference) field.ErrorList {
	switch kind {
	case juneauv1alpha1.EndpointKindPod:
		if ref == nil {
			return field.ErrorList{field.Required(specPath.Child("podRef"), "spec.podRef is required when spec.kind=Pod")}
		}
	default:
		if ref != nil {
			return field.ErrorList{field.Forbidden(specPath.Child("podRef"), fmt.Sprintf("spec.podRef must be omitted when spec.kind=%s", kind))}
		}
	}
	return nil
}
