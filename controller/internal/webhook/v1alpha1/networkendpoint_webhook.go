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
	networkendpointlog.Info("Validation for NetworkEndpoint upon update", "name", networkendpoint.GetName())

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
